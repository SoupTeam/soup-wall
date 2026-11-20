// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! First installation of a profile bundle.

use super::*;

impl ProfileManager {
    /// Installs an initial profile bundle. Fails if a profile is already active.
    pub fn install(
        &self,
        profile_dir: &Path,
        expected_bundle_sha: Option<&str>,
    ) -> Result<InstalledRecord> {
        let _lock = self.lock()?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if crate::service::registered(&self.home) {
            crate::service::Service::new(&self.home)?.require_instance_launcher()?;
        }
        let mut state = self.load_state()?;
        ensure!(
            state.in_progress.is_none(),
            "another profile operation is in progress or was interrupted: run `agentfw mcp-profile recover`"
        );
        ensure!(
            state.active_bundle_sha256.is_none(),
            "a profile is already active (bundle: {}): use `agentfw mcp-profile upgrade` to update",
            state.active_bundle_sha256.as_deref().unwrap_or_default()
        );

        let bundle = self.stage_revision(profile_dir)?;
        if let Some(expected) = expected_bundle_sha {
            ensure!(
                bundle.bundle_sha256 == expected,
                "bundle digest mismatch: expected {}, got {}",
                expected,
                bundle.bundle_sha256
            );
        }

        let next_gen = state
            .generation
            .checked_add(1)
            .context("generation overflow")?;
        let op_id = self.operation_id();
        let lifecycle = crate::lifecycle::Manager::new(&self.home);

        let (pre_config, pre_config_digest, target_yaml, target_config_digest) =
            self.prepare_config(&bundle.bundle_sha256, &bundle.registry_sha256, None)?;
        let target_cfg = Config::from_yaml(&target_yaml)?;

        // FAIL CLOSED: do NOT swallow status errors into was_running = false
        let daemon_st = lifecycle.status().context(
            "failed to determine daemon lifecycle status; cannot safely install profile",
        )?;
        check_daemon_ownership(&daemon_st, Some(&target_cfg), pre_config_digest.as_deref())?;
        let was_running = daemon_st.running;
        let pre_instance = daemon_st.process.as_ref().map(|p| p.instance.clone());

        let candidate = self.candidate_path(&op_id);
        let displaced = self.displaced_path(&op_id);

        // Hold coordinated service and lifecycle ownership across journal write and config write
        let _service_op_lock = self.service_operation_lock()?;
        let lifecycle_lock = lifecycle
            .lock()
            .context("failed to acquire lifecycle lock for profile installation")?;

        let locked_daemon_st = lifecycle.status_locked().context(
            "failed to determine daemon lifecycle status under lock; cannot safely modify configuration",
        )?;
        check_daemon_ownership(
            &locked_daemon_st,
            Some(&target_cfg),
            pre_config_digest.as_deref(),
        )?;
        ensure!(
            locked_daemon_st.running == was_running
                && locked_daemon_st.process.as_ref().map(|p| p.instance.as_str())
                    == pre_instance.as_deref(),
            "conflict: daemon process was started, stopped, or replaced independently before configuration write"
        );

        // 1. Durably record in_progress journal
        state.in_progress = Some(OperationJournal {
            operation_id: op_id.clone(),
            kind: OperationKind::Install,
            phase: OperationPhase::Staged,
            reserved_generation: next_gen,
            source_bundle_sha256: None,
            target_bundle_sha256: bundle.bundle_sha256.clone(),
            pre_operation_config: pre_config.clone(),
            pre_operation_config_digest: pre_config_digest.clone(),
            target_config_digest: target_config_digest.clone(),
            was_daemon_running: was_running,
            pre_daemon_instance: pre_instance.clone(),
            pre_daemon_config_digest: daemon_st.process.as_ref().map(|p| p.config_digest.clone()),
            started_at_utc: now_utc(),
            config_written: false,
            displaced_config_path: Some(displaced.clone()),
            candidate_daemon_instance: None,
            compensated_daemon_instance: None,
            historical_compensated_instances: Vec::new(),
        });
        self.save_state(&state)?;

        // 2. Write config.yaml with CAS
        self.write_config(
            &target_yaml,
            pre_config_digest.as_deref(),
            &candidate,
            &displaced,
        )?;
        let journal_ref = state.in_progress.as_mut().unwrap();
        journal_ref.config_written = true;
        journal_ref.phase = OperationPhase::ConfigWritten;
        self.save_state(&state)?;

        // Release lifecycle and service locks so status / restart can inspect lifecycle without lock conflict
        drop(lifecycle_lock);
        drop(_service_op_lock);

        // Verify daemon ownership post-write under coordinated lifecycle ownership
        let post_st = lifecycle.status()?;
        if let Err(e) = check_daemon_ownership_post_write(
            &post_st,
            Some(&target_cfg),
            was_running,
            pre_instance.as_deref(),
        ) {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            return Err(e);
        }

        // 3. Daemon restart & verification if running
        let mut verified = true;
        let mut candidate_inst: Option<String> = None;
        let needs_verification = was_running || post_st.running || post_st.process.is_some();
        if needs_verification {
            let inst = crate::token::generate();
            candidate_inst = Some(inst.clone());
            let j = state.in_progress.as_mut().unwrap();
            j.phase = OperationPhase::DaemonRestarting;
            j.candidate_daemon_instance = Some(inst.clone());
            self.save_state(&state)?;

            match self.restart_and_verify_daemon(
                &lifecycle,
                &target_config_digest,
                pre_instance.as_deref(),
                was_running,
                Some(&inst),
            ) {
                Ok(_) => {}
                Err(e) => {
                    // Check for ownership conflict first: NEVER compensate over ownership conflict!
                    if Self::is_ownership_conflict(&e) {
                        state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                        self.save_state(&state)?;
                        bail!("ownership conflict during candidate daemon restart ({e:#}); leaving superseding daemon and configuration untouched");
                    }
                    // Check for supersession before automatic compensation
                    let cur_digest = self.config_digest()?;
                    if cur_digest.as_deref() != Some(&target_config_digest) {
                        state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                        self.save_state(&state)?;
                        bail!("candidate daemon failed to boot ({e:#}); config.yaml was modified externally, refusing to overwrite");
                    }
                    // Automatic compensation: rollback config and restart baseline daemon
                    state.in_progress.as_mut().unwrap().phase = OperationPhase::RollingBack;
                    self.save_state(&state)?;
                    let _service_comp_lock = self.service_operation_lock()?;
                    let comp_lock = lifecycle.lock().context(
                        "failed to coordinate lifecycle lock for automatic compensation",
                    )?;
                    let comp_st = lifecycle.status_locked().context(
                        "failed to determine daemon lifecycle status under compensation lock",
                    )?;
                    let authorized_running = match check_compensation_ownership(
                        &comp_st,
                        candidate_inst.as_deref(),
                        was_running,
                        pre_instance.as_deref(),
                    ) {
                        Ok(auth) => auth,
                        Err(err) => {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            return Err(err);
                        }
                    };
                    self.restore_config(
                        pre_config.as_deref(),
                        Some(&target_config_digest),
                        &candidate,
                        &displaced,
                    )?;
                    drop(comp_lock);
                    drop(_service_comp_lock);
                    if was_running {
                        let comp_inst = crate::token::generate();
                        state
                            .in_progress
                            .as_mut()
                            .unwrap()
                            .compensated_daemon_instance = Some(comp_inst.clone());
                        self.save_state(&state)?;

                        let baseline_restart = self.restart_or_start_daemon(
                            &lifecycle,
                            authorized_running.as_deref(),
                            Some(&comp_inst),
                        );
                        if let Err(re) = baseline_restart {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            bail!("candidate daemon failed to boot ({e:#}) and baseline recovery failed to restart ({re:#})");
                        }
                        let st = lifecycle.status()?;
                        let process_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
                        let empty_digest = sha256_bytes(b"");
                        let baseline_digest = pre_config_digest.as_deref().unwrap_or(&empty_digest);
                        ensure!(
                            st.running && process_digest == Some(baseline_digest) && st.process.as_ref().map(|p| p.instance.as_str()) == Some(&comp_inst),
                            "candidate daemon failed to boot ({e:#}); restored baseline configuration but daemon is not running with baseline configuration"
                        );
                        let journal_ref = state.in_progress.as_mut().unwrap();
                        journal_ref.pre_daemon_instance = Some(comp_inst);
                    } else {
                        let st = lifecycle.status()?;
                        if is_daemon_running(&st) {
                            if let Err(se) = lifecycle.stop() {
                                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                                self.save_state(&state)?;
                                bail!("candidate daemon failed to boot ({e:#}) and failed to stop candidate daemon: {se:#}");
                            }
                        }
                        let post_stop = lifecycle.status()?;
                        if post_stop.running || post_stop.process.is_some() {
                            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                            self.save_state(&state)?;
                            bail!("candidate daemon failed to boot ({e:#}) and process ownership remains unresolved");
                        }
                    }
                    let from_bundle = state.active_bundle_sha256.clone();
                    let current_gen = state.generation;
                    self.finalize_compensation(
                        &lifecycle,
                        &mut state,
                        &op_id,
                        OperationKind::Install,
                        &bundle.bundle_sha256,
                        from_bundle,
                        current_gen,
                        pre_config.as_deref(),
                        pre_config_digest.as_deref(),
                        was_running,
                        &e,
                    )?;
                    bail!("daemon failed to start with new profile ({e:#}); automatically rolled back configuration");
                }
            }
        } else {
            verified = false;
        }

        // 4. Commit state
        // Revalidate configuration ownership and daemon binding under lifecycle and service locks before committing activation
        let _service_lock = self.service_operation_lock()?;
        let commit_lock = lifecycle
            .lock()
            .context("failed to coordinate lifecycle lock for activation commit")?;
        let cur_cfg = self.config_digest()?;
        if cur_cfg.as_deref() != Some(&target_config_digest) {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!(
                "activation aborted: config.yaml was externally modified before activation commit (expected candidate digest {}, found {})",
                target_config_digest,
                cur_cfg.as_deref().unwrap_or("<none>")
            );
        }
        let final_st = lifecycle
            .status_locked()
            .context("failed to determine daemon lifecycle status under commit lock")?;
        if was_running && !final_st.running {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!("activation aborted: daemon unexpectedly stopped before activation commit");
        }
        if let Some(expected_inst) = &candidate_inst {
            let proc_inst = final_st.process.as_ref().map(|p| p.instance.as_str());
            if proc_inst != Some(expected_inst.as_str()) {
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(&state)?;
                bail!(
                    "activation aborted: candidate daemon instance superseded before commit (expected {expected_inst}, found {:?})",
                    proc_inst
                );
            }
        } else if final_st.running || final_st.process.is_some() {
            state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
            self.save_state(&state)?;
            bail!("activation aborted: an independent daemon was started before activation commit");
        }
        if let Some(proc) = &final_st.process {
            if proc.config_digest != target_config_digest
                && (was_running || post_st.process.is_some())
            {
                state.in_progress.as_mut().unwrap().phase = OperationPhase::Failed;
                self.save_state(&state)?;
                bail!(
                    "activation aborted: daemon process config digest mismatch before commit (expected {}, got {})",
                    target_config_digest,
                    proc.config_digest
                );
            }
        }

        state.previous_bundle_sha256 = state.active_bundle_sha256.take();
        state.active_bundle_sha256 = Some(bundle.bundle_sha256.clone());
        state.generation = next_gen;
        state.history.push(OperationRecord {
            operation_id: op_id.clone(),
            kind: OperationKind::Install,
            generation: next_gen,
            bundle_sha256: bundle.bundle_sha256.clone(),
            from_bundle_sha256: None,
            timestamp_utc: now_utc(),
            status: "success".into(),
            detail: "installed initial profile".into(),
        });
        state.in_progress = None;
        self.save_state(&state)?;
        drop(commit_lock);

        Ok(InstalledRecord {
            operation_id: op_id,
            kind: OperationKind::Install,
            generation: next_gen,
            bundle_sha256: bundle.bundle_sha256,
            previous_bundle_sha256: None,
            config_digest: target_config_digest,
            daemon_restarted: was_running,
            verified,
        })
    }
}
