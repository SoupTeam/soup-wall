// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Crash recovery: finish or undo an operation the journal shows as interrupted.

use super::*;

impl ProfileManager {
    /// Recovers from an interrupted or crashed operation.
    pub fn recover(&self) -> Result<()> {
        let _lock = self.lock()?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if crate::service::registered(&self.home) {
            crate::service::Service::new(&self.home)?.require_instance_launcher()?;
        }
        let mut state = self.load_state()?;
        let Some(mut journal) = state.in_progress.take() else {
            return Ok(());
        };

        let candidate_path = self.candidate_path(&journal.operation_id);
        let displaced_path = journal
            .displaced_config_path
            .clone()
            .unwrap_or_else(|| self.displaced_path(&journal.operation_id));

        if journal.phase == OperationPhase::Verified {
            if candidate_path.exists() {
                let _ = fs::remove_file(&candidate_path);
                let _ = sync_dir(&self.home);
            }
            if displaced_path.exists() {
                let _ = fs::remove_file(&displaced_path);
                let _ = sync_dir(&self.home);
            }
            // Already verified before crash, can finalize state
            state.previous_bundle_sha256 = journal.source_bundle_sha256.clone();
            state.active_bundle_sha256 = Some(journal.target_bundle_sha256.clone());
            state.generation = journal.reserved_generation;
            state.history.push(OperationRecord {
                operation_id: journal.operation_id,
                kind: journal.kind,
                generation: journal.reserved_generation,
                bundle_sha256: journal.target_bundle_sha256,
                from_bundle_sha256: journal.source_bundle_sha256,
                timestamp_utc: now_utc(),
                status: "success (recovered)".into(),
                detail: "recovered verified operation".into(),
            });
            self.save_state(&state)?;
            return Ok(());
        }

        let lifecycle = crate::lifecycle::Manager::new(&self.home);
        let initial_st = lifecycle.status()?;

        // Before touching any files (candidate_path, displaced_path, config.yaml),
        // verify daemon ownership so independent operator daemons are preserved intact.
        if let Err(e) = check_recovery_daemon_ownership(&initial_st, &journal) {
            journal.phase = OperationPhase::Failed;
            state.in_progress = Some(journal);
            self.save_state(&state)?;
            return Err(e);
        }

        // On Windows, if ReplaceFileW completed but MoveFileExW crashed before moving to displaced_path:
        let swap_bak = PathBuf::from(format!("{}.swap-bak", displaced_path.display()));
        if swap_bak.exists() && !displaced_path.exists() {
            let _ = fs::rename(&swap_bak, &displaced_path);
            let _ = sync_dir(&self.home);
        }

        let mut service_rec_lock = self.service_operation_lock()?;
        let mut rec_lock = Some(
            lifecycle
                .lock()
                .context("failed to coordinate lifecycle lock for recovery")?,
        );

        let locked_st = lifecycle.status_locked().context(
            "failed to determine daemon lifecycle status under recovery lock; cannot safely recover profile",
        )?;
        if let Err(e) = check_recovery_daemon_ownership(&locked_st, &journal) {
            journal.phase = OperationPhase::Failed;
            state.in_progress = Some(journal);
            self.save_state(&state)?;
            return Err(e);
        }

        if candidate_path.exists() {
            let _ = fs::remove_file(&candidate_path);
            sync_dir(&self.home)?;
        }

        // Reconcile displaced configuration if a crash occurred during file swap/restoration
        if displaced_path.exists() {
            let displaced_bytes = fs::read(&displaced_path)?;
            let displaced_digest = sha256_bytes(&displaced_bytes);

            if self.config_path.exists() {
                let cur_bytes = fs::read(&self.config_path)?;
                let cur_digest = sha256_bytes(&cur_bytes);

                if cur_digest == journal.target_config_digest {
                    let baseline_digest = journal.pre_operation_config_digest.as_deref();
                    if displaced_digest == journal.target_config_digest {
                        // Finding 4 (Codex P2): Initial install hard_link succeeded but scratch displaced_path was not unlinked yet.
                        // Both paths contain target config. Simply unlink displaced_path scratch!
                        let _ = fs::remove_file(&displaced_path);
                        sync_dir(&self.home)?;
                    } else if baseline_digest.is_some()
                        && Some(displaced_digest.as_str()) == baseline_digest
                    {
                        // Swap interrupted after swap succeeded: displaced file is expected baseline.
                        // Swap back to restore baseline configuration!
                        if let Err(e) = atomic_swap(&displaced_path, &self.config_path) {
                            journal.phase = OperationPhase::Failed;
                            state.in_progress = Some(journal);
                            self.save_state(&state)?;
                            bail!(
                                "failed to swap baseline configuration back to config.yaml during recovery: {e:#}; displaced file preserved at {}",
                                displaced_path.display()
                            );
                        }
                        // Finding 1 (Codex P1): Validate what was displaced by this recovery swap before deleting!
                        let swapped_bytes = fs::read(&displaced_path)?;
                        let swapped_digest = sha256_bytes(&swapped_bytes);
                        if swapped_digest == journal.target_config_digest {
                            let _ = fs::remove_file(&displaced_path);
                            sync_dir(&self.home)?;
                        } else {
                            // Intervening write! config.yaml was modified before swap back!
                            // Swap back to restore the newer operator configuration to config.yaml!
                            if let Err(e) = atomic_swap(&displaced_path, &self.config_path) {
                                journal.phase = OperationPhase::Failed;
                                state.in_progress = Some(journal);
                                self.save_state(&state)?;
                                bail!(
                                    "conflict during recovery: config.yaml was externally modified before recovery swap; failed to restore: {e:#}; displaced file preserved at {}",
                                    displaced_path.display()
                                );
                            }
                            let comp_bytes = fs::read(&displaced_path)?;
                            let comp_digest = sha256_bytes(&comp_bytes);
                            if comp_digest == displaced_digest {
                                let _ = fs::remove_file(&displaced_path);
                                sync_dir(&self.home)?;
                            }
                            journal.phase = OperationPhase::Failed;
                            state.in_progress = Some(journal);
                            self.save_state(&state)?;
                            bail!(
                                "conflict during recovery: config.yaml was externally superseded before recovery swap (restored newest configuration {})",
                                swapped_digest
                            );
                        }
                    } else {
                        // Finding 1 (Codex P1): Displaced file was SUPERSEDED by an operator!
                        // Swap displaced_path back to config.yaml to preserve the operator's superseded deployment!
                        if let Err(e) = atomic_swap(&displaced_path, &self.config_path) {
                            journal.phase = OperationPhase::Failed;
                            state.in_progress = Some(journal);
                            self.save_state(&state)?;
                            bail!(
                                "conflict during recovery: displaced configuration was externally superseded, but atomic restoration to config.yaml failed: {e:#}; displaced file preserved at {}",
                                displaced_path.display()
                            );
                        }
                        // Finding 1 (Codex P1): Validate what was displaced by this swap before deleting!
                        let swapped_bytes = fs::read(&displaced_path)?;
                        let swapped_digest = sha256_bytes(&swapped_bytes);
                        if swapped_digest == journal.target_config_digest {
                            let _ = fs::remove_file(&displaced_path);
                            sync_dir(&self.home)?;
                        } else {
                            if let Err(e) = atomic_swap(&displaced_path, &self.config_path) {
                                journal.phase = OperationPhase::Failed;
                                state.in_progress = Some(journal);
                                self.save_state(&state)?;
                                bail!(
                                    "conflict during recovery: config.yaml was externally modified; failed to restore: {e:#}; displaced file preserved at {}",
                                    displaced_path.display()
                                );
                            }
                            let final_bytes = fs::read(&displaced_path).ok();
                            if final_bytes.as_deref().map(sha256_bytes).as_deref()
                                == Some(&journal.target_config_digest)
                            {
                                let _ = fs::remove_file(&displaced_path);
                                sync_dir(&self.home)?;
                            }
                        }
                        journal.phase = OperationPhase::Failed;
                        state.in_progress = Some(journal);
                        self.save_state(&state)?;
                        bail!(
                            "conflict during recovery: displaced configuration was externally superseded; restored superseded configuration to config.yaml"
                        );
                    }
                } else if displaced_digest == journal.target_config_digest {
                    // Crash before swap: displaced file was candidate scratch.
                    let _ = fs::remove_file(&displaced_path);
                    sync_dir(&self.home)?;
                } else {
                    // Unexpected external conflict on both files: preserve displaced path and fail
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!(
                        "conflict during recovery: unexpected displaced configuration state (config: {}, displaced: {})",
                        cur_digest,
                        displaced_digest
                    );
                }
            } else {
                // config.yaml does not exist
                if displaced_digest == journal.target_config_digest {
                    // Candidate file from unswapped install or displaced target during restoration to absent baseline
                    let _ = fs::remove_file(&displaced_path);
                    sync_dir(&self.home)?;
                } else if journal.pre_operation_config_digest.as_deref() == Some(&displaced_digest)
                {
                    // Baseline configuration was displaced and config.yaml is absent.
                    // Restore baseline configuration to config.yaml!
                    match fs::hard_link(&displaced_path, &self.config_path) {
                        Ok(_) => {
                            let _ = fs::remove_file(&displaced_path);
                            sync_dir(&self.home)?;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                            sync_dir(&self.home)?;
                        }
                        Err(e) => {
                            sync_dir(&self.home)?;
                            bail!("failed to restore baseline configuration: {e:#}");
                        }
                    }
                } else {
                    // Finding 1 (Codex P1): Displaced file is neither target candidate nor expected baseline!
                    // It could be operator data displaced during compensation of a crashed initial install or intervening write.
                    // Preserve displaced configuration by restoring it to config.yaml if possible, or retaining it!
                    let restored = match fs::hard_link(&displaced_path, &self.config_path) {
                        Ok(_) => {
                            let _ = fs::remove_file(&displaced_path);
                            sync_dir(&self.home)?;
                            true
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                            sync_dir(&self.home)?;
                            false
                        }
                        Err(_) => {
                            sync_dir(&self.home)?;
                            false
                        }
                    };
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    if restored {
                        bail!(
                            "conflict during recovery: displaced configuration does not match target profile; restored to config.yaml"
                        );
                    } else {
                        bail!(
                            "conflict during recovery: displaced configuration does not match target profile; preserved at {}",
                            displaced_path.display()
                        );
                    }
                }
            }
        }

        let current_config = if self.config_path.exists() {
            Some(fs::read_to_string(&self.config_path)?)
        } else {
            None
        };
        let current_digest = current_config
            .as_deref()
            .map(|c| sha256_bytes(c.as_bytes()));

        // If target config was applied to disk (regardless of recorded phase):
        if current_digest.as_deref() == Some(&journal.target_config_digest) {
            self.restore_config(
                journal.pre_operation_config.as_deref(),
                Some(&journal.target_config_digest),
                &candidate_path,
                &displaced_path,
            )?;
            drop(rec_lock.take());
            drop(service_rec_lock.take());

            if journal.was_daemon_running {
                let rec_st = lifecycle.status()?;
                let authorized_running = if is_daemon_running(&rec_st) {
                    let curr_inst = rec_st.process.as_ref().map(|p| p.instance.as_str());
                    if curr_inst == journal.candidate_daemon_instance.as_deref() {
                        journal.candidate_daemon_instance.clone()
                    } else if curr_inst == journal.pre_daemon_instance.as_deref() {
                        journal.pre_daemon_instance.clone()
                    } else if curr_inst == journal.compensated_daemon_instance.as_deref() {
                        journal.compensated_daemon_instance.clone()
                    } else if let Some(matched) = curr_inst.and_then(|ci| {
                        journal
                            .historical_compensated_instances
                            .iter()
                            .find(|h| h.as_str() == ci)
                            .cloned()
                    }) {
                        Some(matched)
                    } else {
                        journal.phase = OperationPhase::Failed;
                        state.in_progress = Some(journal);
                        self.save_state(&state)?;
                        bail!(
                            "conflict during recovery: an independent daemon was started; refusing to stop it"
                        );
                    }
                } else {
                    None
                };

                let recovery_inst = crate::token::generate();
                journal.phase = OperationPhase::RollingBack;
                if let Some(old_comp) = journal.compensated_daemon_instance.take() {
                    if !journal.historical_compensated_instances.contains(&old_comp) {
                        journal.historical_compensated_instances.push(old_comp);
                    }
                }
                journal.compensated_daemon_instance = Some(recovery_inst.clone());
                state.in_progress = Some(journal.clone());
                self.save_state(&state)?;

                let restart_res = self.restart_or_start_daemon(
                    &lifecycle,
                    authorized_running.as_deref(),
                    Some(&recovery_inst),
                );
                if let Err(re) = restart_res {
                    // Do not discard error and do not clear journal
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!("recovery restored configuration but baseline daemon restart failed: {re:#}");
                }
                let st = lifecycle.status()?;
                let process_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
                let proc_inst = st.process.as_ref().map(|p| p.instance.as_str());
                let empty_digest = sha256_bytes(b"");
                let baseline_digest = journal
                    .pre_operation_config_digest
                    .as_deref()
                    .unwrap_or(&empty_digest);
                ensure!(
                    st.running && process_digest == Some(baseline_digest) && proc_inst == Some(&recovery_inst),
                    "recovery restored configuration but daemon is not running with baseline digest"
                );
                journal.historical_compensated_instances.clear();
                state.in_progress = Some(journal.clone());
                self.save_state(&state)?;
            } else {
                // Baseline was stopped and no independent daemon was running.
                let post_stop = lifecycle.status()?;
                if post_stop.running || post_stop.process.is_some() {
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!(
                        "conflict during recovery: an independent daemon was detected while baseline was stopped; refusing to stop it"
                    );
                }
                let baseline_cfg = journal
                    .pre_operation_config
                    .as_deref()
                    .and_then(|text| Config::from_yaml(text).ok());
                if let Err(e) = check_daemon_ownership(&post_stop, baseline_cfg.as_ref(), None) {
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!("recovery restored configuration but daemon ownership check failed: {e:#}; refusing to clear journal");
                }
            }
        } else if current_digest == journal.pre_operation_config_digest {
            drop(rec_lock.take());
            drop(service_rec_lock.take());
            // Configuration matches baseline (including when both are None)!
            let empty_digest = sha256_bytes(b"");
            let baseline_cfg_digest = journal
                .pre_operation_config_digest
                .as_deref()
                .unwrap_or(&empty_digest);

            if journal.was_daemon_running {
                let st = lifecycle.status()?;
                let process_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
                if !st.running || process_digest != Some(baseline_cfg_digest) {
                    let rec_st = lifecycle.status()?;
                    let authorized_running = if is_daemon_running(&rec_st) {
                        let curr_inst = rec_st.process.as_ref().map(|p| p.instance.as_str());
                        if curr_inst == journal.candidate_daemon_instance.as_deref() {
                            journal.candidate_daemon_instance.clone()
                        } else if curr_inst == journal.pre_daemon_instance.as_deref() {
                            journal.pre_daemon_instance.clone()
                        } else if curr_inst == journal.compensated_daemon_instance.as_deref() {
                            journal.compensated_daemon_instance.clone()
                        } else if let Some(matched) = curr_inst.and_then(|ci| {
                            journal
                                .historical_compensated_instances
                                .iter()
                                .find(|h| h.as_str() == ci)
                                .cloned()
                        }) {
                            Some(matched)
                        } else {
                            journal.phase = OperationPhase::Failed;
                            state.in_progress = Some(journal);
                            self.save_state(&state)?;
                            bail!(
                                "conflict during recovery: an independent daemon was started; refusing to stop it"
                            );
                        }
                    } else {
                        None
                    };

                    let recovery_inst = crate::token::generate();
                    journal.phase = OperationPhase::RollingBack;
                    if let Some(old_comp) = journal.compensated_daemon_instance.take() {
                        if !journal.historical_compensated_instances.contains(&old_comp) {
                            journal.historical_compensated_instances.push(old_comp);
                        }
                    }
                    journal.compensated_daemon_instance = Some(recovery_inst.clone());
                    state.in_progress = Some(journal.clone());
                    self.save_state(&state)?;

                    let restart_res = self.restart_or_start_daemon(
                        &lifecycle,
                        authorized_running.as_deref(),
                        Some(&recovery_inst),
                    );
                    if let Err(re) = restart_res {
                        journal.phase = OperationPhase::Failed;
                        state.in_progress = Some(journal);
                        self.save_state(&state)?;
                        bail!("recovery confirmed baseline configuration but baseline daemon restart failed: {re:#}");
                    }
                    let st = lifecycle.status()?;
                    let process_digest = st.process.as_ref().map(|p| p.config_digest.as_str());
                    let proc_inst = st.process.as_ref().map(|p| p.instance.as_str());
                    ensure!(
                        st.running && process_digest == Some(baseline_cfg_digest) && proc_inst == Some(&recovery_inst),
                        "recovery confirmed baseline configuration but daemon is not running with baseline configuration"
                    );
                    journal.historical_compensated_instances.clear();
                    state.in_progress = Some(journal.clone());
                    self.save_state(&state)?;
                } else {
                    let curr_inst = st.process.as_ref().map(|p| p.instance.as_str());
                    let is_original_baseline = journal.pre_daemon_instance.as_deref().is_some()
                        && curr_inst == journal.pre_daemon_instance.as_deref();
                    let is_compensated_baseline =
                        (journal.compensated_daemon_instance.as_deref().is_some()
                            && curr_inst == journal.compensated_daemon_instance.as_deref())
                            || curr_inst.is_some_and(|inst| {
                                journal
                                    .historical_compensated_instances
                                    .iter()
                                    .any(|h| h == inst)
                            });
                    if is_original_baseline {
                        // Original baseline daemon is still running with baseline config; clear unexecuted compensation reservation
                        journal.compensated_daemon_instance = None;
                        journal.historical_compensated_instances.clear();
                        state.in_progress = Some(journal.clone());
                        self.save_state(&state)?;
                    } else if is_compensated_baseline {
                        // Previous recovery restart succeeded with compensated instance
                        if let Some(ci) = curr_inst {
                            journal.compensated_daemon_instance = Some(ci.to_string());
                            journal.historical_compensated_instances.clear();
                            state.in_progress = Some(journal.clone());
                            self.save_state(&state)?;
                        }
                    } else {
                        journal.phase = OperationPhase::Failed;
                        state.in_progress = Some(journal);
                        self.save_state(&state)?;
                        bail!(
                            "conflict during recovery: an independent daemon was started with baseline configuration; refusing to stop it"
                        );
                    }
                }
            } else {
                let st = lifecycle.status()?;
                if st.running || st.process.is_some() {
                    // Daemon was started independently by an operator with baseline configuration.
                    // Preserve the running daemon and report conflict!
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!(
                        "conflict during recovery: an independent daemon was started with baseline configuration; refusing to stop it"
                    );
                }
                let baseline_cfg = journal
                    .pre_operation_config
                    .as_deref()
                    .and_then(|text| Config::from_yaml(text).ok());
                if let Err(e) = check_daemon_ownership(&st, baseline_cfg.as_ref(), None) {
                    journal.phase = OperationPhase::Failed;
                    state.in_progress = Some(journal);
                    self.save_state(&state)?;
                    bail!("recovery confirmed baseline configuration but daemon ownership check failed: {e:#}; refusing to clear journal");
                }
            }
        } else {
            // External conflict! Neither target nor baseline matched.
            journal.phase = OperationPhase::Failed;
            state.in_progress = Some(journal);
            self.save_state(&state)?;
            bail!(
                "conflict during recovery: current config.yaml does not match target or baseline digest; refusing to clear journal"
            );
        }

        // Revalidate baseline ownership before finalizing recovery under coordinated lifecycle locking
        let _service_lock = self.service_operation_lock()?;
        let commit_lock = lifecycle
            .lock()
            .context("failed to coordinate lifecycle lock for recovery finalization")?;
        let cur_cfg = self.config_digest()?;
        let expected_baseline_digest = journal.pre_operation_config_digest.clone();
        if cur_cfg != expected_baseline_digest {
            journal.phase = OperationPhase::Failed;
            state.in_progress = Some(journal);
            self.save_state(&state)?;
            bail!(
                "conflict during recovery: config.yaml was externally modified before clearing journal (expected baseline digest {:?}, found {:?})",
                expected_baseline_digest,
                cur_cfg
            );
        }

        let final_st = lifecycle.status_locked().context(
            "failed to determine daemon lifecycle status under recovery finalization lock",
        )?;

        let baseline_cfg = journal
            .pre_operation_config
            .as_deref()
            .and_then(|text| Config::from_yaml(text).ok());
        let expected_instance =
            if journal.pre_daemon_instance.as_deref().is_some_and(|pre| {
                final_st.process.as_ref().map(|p| p.instance.as_str()) == Some(pre)
            }) {
                journal.pre_daemon_instance.clone()
            } else if let Some(proc_inst) = final_st.process.as_ref().map(|p| p.instance.as_str()) {
                if journal.compensated_daemon_instance.as_deref() == Some(proc_inst)
                    || journal
                        .historical_compensated_instances
                        .iter()
                        .any(|h| h == proc_inst)
                {
                    Some(proc_inst.to_string())
                } else {
                    journal
                        .compensated_daemon_instance
                        .clone()
                        .or_else(|| journal.pre_daemon_instance.clone())
                }
            } else {
                journal
                    .compensated_daemon_instance
                    .clone()
                    .or_else(|| journal.pre_daemon_instance.clone())
            };

        if let Err(e) = check_daemon_ownership_post_write(
            &final_st,
            baseline_cfg.as_ref(),
            journal.was_daemon_running,
            expected_instance.as_deref(),
        ) {
            journal.phase = OperationPhase::Failed;
            state.in_progress = Some(journal);
            self.save_state(&state)?;
            bail!("conflict during recovery: daemon ownership check failed before clearing journal: {e:#}");
        }

        if journal.was_daemon_running {
            if !final_st.running {
                journal.phase = OperationPhase::Failed;
                state.in_progress = Some(journal);
                self.save_state(&state)?;
                bail!("conflict during recovery: baseline daemon is not running before clearing journal");
            }
            let empty_digest = sha256_bytes(b"");
            let baseline_digest = expected_baseline_digest
                .as_deref()
                .unwrap_or(&empty_digest)
                .to_string();
            let proc_digest = final_st.process.as_ref().map(|p| p.config_digest.as_str());
            if proc_digest != Some(&baseline_digest) {
                journal.phase = OperationPhase::Failed;
                state.in_progress = Some(journal);
                self.save_state(&state)?;
                bail!(
                    "conflict during recovery: baseline daemon running with mismatched config digest before clearing journal (expected {baseline_digest}, got {:?})",
                    proc_digest
                );
            }
        }

        state.history.push(OperationRecord {
            operation_id: journal.operation_id,
            kind: journal.kind,
            generation: state.generation,
            bundle_sha256: journal.target_bundle_sha256,
            from_bundle_sha256: journal.source_bundle_sha256,
            timestamp_utc: now_utc(),
            status: "failed (recovered)".into(),
            detail: "recovery verified baseline configuration and daemon state".into(),
        });
        state.in_progress = None;
        self.save_state(&state)?;
        drop(commit_lock);
        Ok(())
    }
}
