// SPDX-License-Identifier: Apache-2.0
//! Confined filesystem MCP original-create *staging*, not a write authority.
//! The authenticated relay executes the ORIGINAL pinned server in a separate
//! sandbox against this fresh private stage, stops/reaps the server, inspects
//! its actual output and obtains native result-release/policy authority before
//! using the atomic publisher. This module never publishes to the workspace.

#[cfg(target_os = "linux")]
mod linux {
    use super::super::server_profile::filesystem_create::CreateSelection;
    use anyhow::{ensure, Context};
    use sha2::{Digest, Sha256};
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    /// The untrusted child can only ever see this ephemeral filesystem tree
    /// through /workspace. It cannot see or publish directly to the user's
    /// real workspace. Drop is a best-effort cleanup after the owner stops.
    pub(crate) struct OwnedStage {
        root: PathBuf,
        directory: File,
        dev: u64,
        ino: u64,
    }

    impl OwnedStage {
        pub(crate) fn new() -> anyhow::Result<Self> {
            // Respect a trusted runner's TMPDIR: some accepted container
            // regressions intentionally mount /tmp read-only. Never fall
            // back to another guessed writable location or disable isolation.
            let base = std::env::temp_dir();
            let meta = fs::symlink_metadata(&base)?;
            ensure!(
                base.is_absolute() && meta.file_type().is_dir(),
                "invalid private staging parent"
            );
            for _ in 0..8 {
                let root = base.join(format!(
                    ".agentfw-original-create-{}",
                    crate::token::generate()
                ));
                let result = fs::DirBuilder::new().mode(0o700).create(&root);
                match result {
                    Ok(()) => {
                        let directory = File::open(&root)?;
                        let meta = directory.metadata()?;
                        ensure!(
                            meta.is_dir()
                                && meta.uid() == unsafe { libc::geteuid() }
                                && meta.permissions().mode() & 0o7777 == 0o700,
                            "temporary staging directory unsafe"
                        );
                        return Ok(Self {
                            root,
                            directory,
                            dev: meta.dev(),
                            ino: meta.ino(),
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error).context("failed to allocate private stage"),
                }
            }
            anyhow::bail!("failed to reserve unique private stage")
        }

        pub(crate) fn path(&self) -> &Path {
            &self.root
        }

        fn unchanged(&self) -> anyhow::Result<()> {
            let handle = self.directory.metadata()?;
            let path = fs::symlink_metadata(&self.root)?;
            ensure!(
                handle.is_dir()
                    && path.is_dir()
                    && handle.dev() == self.dev
                    && handle.ino() == self.ino
                    && path.dev() == self.dev
                    && path.ino() == self.ino
                    && handle.uid() == unsafe { libc::geteuid() }
                    && handle.permissions().mode() & 0o7777 == 0o700,
                "staging root was substituted"
            );
            Ok(())
        }

        /// Call only once the original upstream server and every descendant
        /// are conclusively terminated. An extra artifact, link or unexpected
        /// content refuses publication, even if the upstream result says OK.
        pub(crate) fn verify(&self, selected: &CreateSelection) -> anyhow::Result<VerifiedOutput> {
            self.unchanged()?;
            // Enumerate only the pinned stage directory, not a pathname
            // another same-UID actor could rename between identity checks.
            let proc_dir = File::open("/proc/self/fd")?;
            let mut proc_stat: libc::statfs = unsafe { std::mem::zeroed() };
            ensure!(
                unsafe { libc::fstatfs(proc_dir.as_raw_fd(), &mut proc_stat) } == 0
                    && proc_stat.f_type as u64 == 0x9fa0,
                "trusted proc descriptor directory unavailable"
            );
            let pinned = format!("/proc/self/fd/{}", self.directory.as_raw_fd());
            let mut seen = fs::read_dir(&pinned)?;
            let item = seen
                .next()
                .context("original server did not create a file")??;
            ensure!(
                seen.next().is_none(),
                "original server created extra artifacts"
            );
            ensure!(
                item.file_name() == selected.leaf.as_str(),
                "original server created unexpected artifact"
            );
            let leaf = std::ffi::CString::new(selected.leaf.as_bytes())?;
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            ensure!(fd >= 0, "original output could not be safely opened");
            let file = unsafe { File::from_raw_fd(fd) };
            let meta = file.metadata()?;
            ensure!(
                meta.is_file()
                    && meta.nlink() == 1
                    && meta.dev() == self.dev
                    && meta.uid() == unsafe { libc::geteuid() }
                    && meta.mode() & 0o7111 == 0
                    && meta.len() == selected.content_bytes as u64
                    && meta.len() <= 4096,
                "untrusted output is not the expected owner-held bounded regular file"
            );
            // The ORIGINAL upstream fs.writeFile normally creates 0644.
            // No other user can reach this inode while its parent is 0700;
            // normalize the already pinned, verified one-link regular inode
            // to 0600 before any bytes can leave the private namespace.
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            ensure!(
                file.metadata()?.mode() & 0o7777 == 0o600,
                "original staging output could not be made owner-private"
            );
            let mut bytes = Vec::new();
            file.take(4097).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() == selected.content_bytes
                    && format!("{:x}", Sha256::digest(&bytes)) == selected.content_sha256,
                "original server output bytes mismatch"
            );
            let content = String::from_utf8(bytes)?;
            self.unchanged()?;
            Ok(VerifiedOutput {
                leaf: selected.leaf.clone(),
                content,
                content_sha256: selected.content_sha256.clone(),
            })
        }
    }

    impl Drop for OwnedStage {
        fn drop(&mut self) {
            // A substituted directory must never be recursively removed.
            if self.unchanged().is_ok() {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    /// Verified stage bytes are still *not* a publication grant. Caller must
    /// separately possess a currently valid exact-session admission, completed
    /// native result receipt, and a one-use policy/approval authority.
    pub(crate) struct VerifiedOutput {
        leaf: String,
        content: String,
        content_sha256: String,
    }

    impl VerifiedOutput {
        /// Read-only preparation of the already verified ORIGINAL upstream
        /// output for the accepted descriptor-pinned, atomic, no-clobber
        /// publisher. This function never writes to the real workspace.
        /// The caller must possess a fresh, one-use native result/policy
        /// release before invoking PreparedCreate::stage and ::publish.
        pub(crate) fn prepare_atomic_publication(
            self,
            workspace: &crate::sandbox::PinnedWorkspace,
        ) -> anyhow::Result<crate::mcp::create_file::PreparedCreate> {
            ensure!(
                self.content.len() <= 4096
                    && format!("{:x}", Sha256::digest(self.content.as_bytes()))
                        == self.content_sha256,
                "upstream output identity changed after verification"
            );
            let target = workspace.canonical().join(&self.leaf);
            crate::mcp::create_file::PreparedCreate::prepare(workspace, &target, &self.content)
                .map_err(Into::into)
        }
    }

    #[cfg(test)]
    pub(crate) fn verified_test_output(args: &serde_json::Value) -> anyhow::Result<VerifiedOutput> {
        let selected = crate::mcp::server_profile::filesystem_create::validate_request(args)?;
        let stage = OwnedStage::new()?;
        fs::write(
            stage.path().join(&selected.leaf),
            args["content"].as_str().unwrap(),
        )?;
        stage.verify(&selected)
    }

    /// A valid original error can be released after native inspection, but
    /// must never carry verified bytes into the publication branch. Partial
    /// stage artifacts left by a failed upstream operation are discarded.
    fn validate_original_output(
        stage: &OwnedStage,
        selected: &CreateSelection,
        reply: &serde_json::Value,
    ) -> anyhow::Result<Option<VerifiedOutput>> {
        let profiles = super::super::server_profile::filesystem_create::classify_manifest(
            &super::super::server_profile::original_manifest(),
        )?;
        match profiles["write_file"].validate_result(reply)? {
            "value" => stage.verify(selected).map(Some),
            "error" => Ok(None),
            _ => anyhow::bail!("unsupported original create result kind"),
        }
    }

    // No access to the real workspace is passed to this exchange. Even a
    // compromised original upstream process can only mutate its one ephemeral
    // /workspace stage and sandbox-private tmpfs. The caller must separately
    // obtain a still-valid native receipt and publish the verified bytes.
    pub(crate) async fn run_original_upstream(
        profile: &crate::mcp::server_profile::ProfileConfig,
        original_args: &serde_json::Value,
    ) -> anyhow::Result<(Vec<u8>, Option<VerifiedOutput>)> {
        use crate::mcp::{server_profile, server_sandbox};
        use serde_json::{json, Value};
        use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};

        const FRAME_LIMIT: usize = server_profile::MAX_FRAME_BYTES;
        const EXCHANGE_SECONDS: u64 = 20;

        async fn receive<R: AsyncBufRead + Unpin>(
            reader: &mut R,
            expected_id: i64,
        ) -> anyhow::Result<(Value, Vec<u8>)> {
            let mut frame = Vec::new();
            loop {
                let buffer = reader.fill_buf().await?;
                ensure!(
                    !buffer.is_empty(),
                    "original server ended before its response"
                );
                let end = buffer.iter().position(|b| *b == b'\n');
                let take = end.map_or(buffer.len(), |idx| idx + 1);
                ensure!(
                    frame.len() + take <= FRAME_LIMIT,
                    "original server response frame exceeded bound"
                );
                frame.extend_from_slice(&buffer[..take]);
                reader.consume(take);
                if end.is_some() {
                    break;
                }
            }
            let crate::mcp::admission::Strict(message) =
                serde_json::from_slice(&frame).context("invalid original-server JSON")?;
            ensure!(
                message["jsonrpc"] == "2.0"
                    && message["id"] == expected_id
                    && message.as_object().is_some_and(|obj| obj.len() == 3)
                    && (message.get("result").is_some() ^ message.get("error").is_some()),
                "original server sent an unexpected or ambiguous response"
            );
            Ok((message, frame))
        }

        async fn send<W: AsyncWriteExt + Unpin>(sink: &mut W, value: &Value) -> anyhow::Result<()> {
            let mut bytes = serde_json::to_vec(value)?;
            ensure!(
                bytes.len() < FRAME_LIMIT,
                "original server request over limit"
            );
            bytes.push(b'\n');
            sink.write_all(&bytes).await?;
            sink.flush().await?;
            Ok(())
        }

        ensure!(
            profile.format == server_profile::filesystem_create::FORMAT,
            "original create requires its explicit versioned profile"
        );
        let selected = server_profile::filesystem_create::validate_request(original_args)?;
        let stage = OwnedStage::new()?;
        let prepared = server_sandbox::prepare_create_stage(profile, stage.path())?;
        let (mut process, mut budget, mut owner, sandbox_pid) = prepared.spawn().await?;
        // A bounded diagnostic identifies only this owned ephemeral worker.
        // Acceptance pins its kernel identity before injecting a worker fault.
        // A closed diagnostic pipe must not skip owned process cleanup.
        let _ = writeln!(
            std::io::stderr().lock(),
            "{}",
            json!({"event":"mcp_original_create_worker",
            "sandbox_pid":sandbox_pid})
        );
        let attached = if let Some(budget) = budget.as_mut() {
            budget.verify_attached(sandbox_pid)
        } else {
            Ok(())
        };
        let owner_check = owner.check();
        let mut stderr_task = None;
        let exchange = async {
            attached?;
            owner_check?;
            let stdin = process
                .stdin
                .take()
                .context("original server stdin missing")?;
            let stdout = process
                .stdout
                .take()
                .context("original server stdout missing")?;
            let stderr = process
                .stderr
                .take()
                .context("original server stderr missing")?;
            let mut writer = stdin;
            let mut reader = BufReader::new(stdout);
            stderr_task = Some(tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut bytes = Vec::new();
                stderr.take(1024 * 1024 + 1).read_to_end(&mut bytes).await?;
                ensure!(
                    bytes.len() <= 1024 * 1024,
                    "original server stderr over limit"
                );
                Ok::<_, anyhow::Error>(())
            }));

            let session = async {
                send(
                    &mut writer,
                    &json!({"jsonrpc":"2.0","id":1,"method":"initialize",
                    "params":{"protocolVersion":server_profile::PROTOCOL_VERSION,
                        "capabilities":{},"clientInfo":{"name":"soup-wall","version":"0.3.0"}}}),
                )
                .await?;
                let (hello, _) = receive(&mut reader, 1).await?;
                ensure!(
                    hello.get("error").is_none(),
                    "original upstream initialization rejected"
                );
                server_profile::validate_initialization_for(
                    profile.format.as_str(),
                    &hello["result"],
                )?;
                send(
                    &mut writer,
                    &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                )
                .await?;
                send(
                    &mut writer,
                    &json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
                )
                .await?;
                let (discovery, _) = receive(&mut reader, 2).await?;
                ensure!(
                    discovery.get("error").is_none(),
                    "original upstream discovery failed"
                );
                let available =
                    server_profile::classify_manifest_for(&profile.format, &discovery["result"])?;
                let write = available
                    .get("write_file")
                    .context("original write_file unavailable")?;
                write.validate_arguments(original_args)?;
                send(
                    &mut writer,
                    &json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                    "params":{"name":"write_file","arguments":original_args}}),
                )
                .await?;
                let (reply, raw) = receive(&mut reader, 3).await?;
                write.validate_result(&reply)?;
                // Explicitly close the original server input; the namespace
                // owner is always reaped before inspecting the stage.
                writer.shutdown().await?;
                Ok::<_, anyhow::Error>((raw, reply))
            };
            // The original process may keep stderr open after write_file.
            // Never await stderr EOF before stopping the child.
            session.await
        };
        let outcome =
            tokio::time::timeout(std::time::Duration::from_secs(EXCHANGE_SECONDS), exchange)
                .await
                .context("original server operation timed out")
                .and_then(|x| x);

        // Do not inspect any sandbox-generated bytes until its child and
        // guardian are fully quiescent. Never publish within this function.
        let owner_quiesce = owner.quiesce().await;
        let budget_check = budget.as_ref().map(|b| b.check()).unwrap_or(Ok(()));
        let budget_cleanup = if let Some(b) = budget.as_mut() {
            b.finish().await
        } else {
            Ok(())
        };
        let owner_cleanup = owner.finish().await;
        let child_cleanup = server_sandbox::terminate(&mut process).await;
        let stderr_cleanup = if let Some(mut task) = stderr_task {
            match tokio::time::timeout(std::time::Duration::from_secs(2), &mut task).await {
                Ok(Ok(result)) => result,
                Ok(Err(error)) => Err(anyhow::anyhow!("original stderr reader crashed: {error}")),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Err(anyhow::anyhow!("original stderr reader did not finish"))
                }
            }
        } else {
            Err(anyhow::anyhow!("original stderr reader was not installed"))
        };
        // Always attempt all owned cleanup before examining any original
        // output, including on a timed-out or malformed RPC.
        let (result, reply) = outcome?;
        owner_quiesce?;
        budget_check?;
        budget_cleanup?;
        owner_cleanup?;
        child_cleanup?;
        stderr_cleanup?;
        let verified = validate_original_output(&stage, &selected, &reply)?;
        Ok((result, verified))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;
        use std::os::unix::fs::symlink;

        fn selected(leaf: &str, content: &str) -> CreateSelection {
            crate::mcp::server_profile::filesystem_create::validate_request(
                &json!({"path":format!("/workspace/{leaf}"),"content":content}),
            )
            .unwrap()
        }

        fn original_file(stage: &OwnedStage, leaf: &str, content: &[u8]) {
            let file = stage.path().join(leaf);
            fs::write(&file, content).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        }

        /// A missing pinned runtime/namespace permission is a failure, never
        /// an accepted skip. CI passes the same real SOU-62 installation
        /// profile and trusted Agent image used for accepted original read.
        #[tokio::test]
        #[ignore = "requires SOU62_SANDBOX_TEST_PROFILE and SOU86_TEST_AGENTFW"]
        async fn actual_original_write_file_is_confined_to_unpublished_stage() {
            use crate::mcp::server_profile::{filesystem_create, ProfileConfig};
            let path = std::env::var_os("SOU62_SANDBOX_TEST_PROFILE")
                .expect("real installed original-server profile is required");
            let mut profile = ProfileConfig::read(&fs::read(path).unwrap()).unwrap();
            assert_eq!(profile.format, crate::mcp::server_profile::FORMAT);
            profile.format = filesystem_create::FORMAT.to_owned();
            assert!(
                std::env::var_os("SOU86_TEST_AGENTFW").is_some(),
                "trusted namespace owner image required"
            );
            let root = tempfile::tempdir().unwrap();
            let workspace = root.path().join("real-workspace");
            fs::create_dir(&workspace).unwrap();
            let outside = root.path().join("outside-marker.txt");
            fs::write(&outside, b"outside unchanged").unwrap();
            profile.workspace = workspace.canonicalize().unwrap();
            profile.workspace_identity = Some(
                crate::mcp::server_profile::WorkspaceIdentity::from_metadata(
                    &fs::metadata(&profile.workspace).unwrap(),
                ),
            );
            let args = json!({"path":"/workspace/original.txt","content":"upstream 🌍"});
            let (raw, verified) = super::run_original_upstream(&profile, &args).await.unwrap();
            let verified = verified.expect("successful original create has verified output");
            assert_eq!(verified.leaf, "original.txt");
            assert_eq!(verified.content, "upstream 🌍");
            assert_eq!(
                verified.content_sha256,
                filesystem_create::validate_request(&args)
                    .unwrap()
                    .content_sha256
            );
            let response: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(response["id"], 3);
            assert!(response.get("result").is_some());
            assert!(!workspace.join("original.txt").exists());
            assert_eq!(fs::read(&outside).unwrap(), b"outside unchanged");
            assert_eq!(fs::read_dir(&workspace).unwrap().count(), 0);

            // These refusals happen *before* any upstream process is spawned.
            for denied in [
                json!({"path":"/workspace/../outside-marker.txt","content":"bad"}),
                json!({"path":"/workspace/nested/new","content":"bad"}),
                json!({"path":"/workspace/original.txt","content":"x".repeat(4097)}),
                json!({"path":"/tmp/outside-marker.txt","content":"bad"}),
                json!({"path":"/workspace/original.txt","content":"bad","overwrite":true}),
            ] {
                assert!(super::run_original_upstream(&profile, &denied)
                    .await
                    .is_err());
            }
            assert_eq!(fs::read(&outside).unwrap(), b"outside unchanged");
            assert_eq!(fs::read_dir(&workspace).unwrap().count(), 0);
        }

        #[test]
        fn original_errors_never_grant_publication_even_with_partial_stage_artifacts() {
            let stage = OwnedStage::new().unwrap();
            let root = stage.path().to_path_buf();
            let selected = selected("approved.txt", "exact authorized bytes");
            // A failed upstream write may have left partial output. Neither a
            // JSON-RPC error nor an isError tool result may publish it.
            original_file(&stage, "approved.txt", b"partial");
            let errors = [
                json!({"jsonrpc":"2.0","id":3,"error":{"code":-32603,"message":"original failure"}}),
                json!({"jsonrpc":"2.0","id":3,"result":{"isError":true,
                    "content":[{"type":"text","text":"Error: ENOSPC: no space left"}]}}),
            ];
            for reply in errors {
                assert!(validate_original_output(&stage, &selected, &reply)
                    .unwrap()
                    .is_none());
            }
            let false_success = json!({"jsonrpc":"2.0","id":3,"result":{
                "content":[{"type":"text","text":"success"}],
                "structuredContent":{"content":"success"}}});
            assert!(validate_original_output(&stage, &selected, &false_success).is_err());
            let hidden = json!({"jsonrpc":"2.0","id":3,"error":{
                "code":-32603,"message":"failure","data":{"uninspected":"payload"}}});
            assert!(validate_original_output(&stage, &selected, &hidden).is_err());
            drop(stage);
            assert!(
                !root.exists(),
                "failed upstream artifacts must be discarded"
            );
        }

        #[test]
        fn verified_output_prepares_atomic_no_clobber_without_early_effects() {
            let stage = OwnedStage::new().unwrap();
            let accepted = selected("pub.txt", "approved bytes");
            original_file(&stage, &accepted.leaf, b"approved bytes");
            let output = stage.verify(&accepted).unwrap();
            let workspace = tempfile::tempdir().unwrap();
            let pinned = crate::sandbox::PinnedWorkspace::open(workspace.path()).unwrap();
            let prepared = output.prepare_atomic_publication(&pinned).unwrap();
            let published = workspace.path().join("pub.txt");
            assert!(!published.exists(), "preparation must not publish");
            let staged = prepared.stage().unwrap();
            assert!(!published.exists(), "anonymous staging must not publish");
            let result = staged.publish().unwrap();
            assert!(result.committed && result.directory_synced);
            assert_eq!(fs::read(&published).unwrap(), b"approved bytes");
            let replay = stage
                .verify(&accepted)
                .unwrap()
                .prepare_atomic_publication(&pinned);
            assert!(
                replay.is_err(),
                "the existing file must never be overwritten"
            );
            assert_eq!(fs::read(&published).unwrap(), b"approved bytes");
        }

        #[test]
        fn original_create_rejects_workspace_replacement_after_original_admission_pin() {
            let owned = tempfile::tempdir().unwrap();
            let root = owned.path().join("workspace");
            fs::create_dir(&root).unwrap();
            let pinned = crate::sandbox::PinnedWorkspace::open(&root).unwrap();
            let upstream = OwnedStage::new().unwrap();
            let selection = selected("allowed.txt", "hello");
            original_file(&upstream, "allowed.txt", b"hello");
            let output = upstream.verify(&selection).unwrap();

            let renamed = owned.path().join("moved-original");
            fs::rename(&root, &renamed).unwrap();
            fs::create_dir(&root).unwrap();
            assert!(
                output.prepare_atomic_publication(&pinned).is_err(),
                "a same-name replacement must never acquire native create authority"
            );
            assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
            assert_eq!(fs::read_dir(&renamed).unwrap().count(), 0);
        }

        #[test]
        fn verifies_exact_original_bytes_and_removes_private_stage_on_drop() {
            let stage = OwnedStage::new().unwrap();
            let root = stage.path().to_path_buf();
            assert_eq!(fs::metadata(&root).unwrap().mode() & 0o7777, 0o700);
            let selection = selected("hello.txt", "sample 🌍");
            original_file(&stage, &selection.leaf, "sample 🌍".as_bytes());
            let outcome = stage.verify(&selection).unwrap();
            assert_eq!(outcome.leaf, "hello.txt");
            assert_eq!(outcome.content, "sample 🌍");
            assert_eq!(outcome.content_sha256, selection.content_sha256);
            drop(stage);
            assert!(!root.exists());
        }

        #[test]
        fn any_extra_output_or_content_mismatch_refuses_without_publication() {
            let stage = OwnedStage::new().unwrap();
            let expected = selected("allowed.txt", "approved");
            original_file(&stage, "allowed.txt", b"approved");
            assert!(stage.verify(&expected).is_ok());
            original_file(&stage, "extra.txt", b"secret");
            assert!(stage.verify(&expected).is_err());
            fs::remove_file(stage.path().join("extra.txt")).unwrap();
            original_file(&stage, "allowed.txt", b"tampered");
            assert!(stage.verify(&expected).is_err());
        }

        #[test]
        fn original_stage_rejects_fifo_directory_and_aliased_inode_without_blocking() {
            let stage = OwnedStage::new().unwrap();
            let requested = selected("approved.txt", "ok");
            let target = stage.path().join("approved.txt");
            let c_path = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
            let began = std::time::Instant::now();
            assert!(stage.verify(&requested).is_err());
            assert!(
                began.elapsed() < std::time::Duration::from_secs(1),
                "FIFO inspection blocked waiting for a peer"
            );
            fs::remove_file(&target).unwrap();
            fs::create_dir(&target).unwrap();
            assert!(stage.verify(&requested).is_err());
            fs::remove_dir(&target).unwrap();
            original_file(&stage, "approved.txt", b"ok");
            let outside = tempfile::tempdir().unwrap();
            fs::hard_link(&target, outside.path().join("alias")).unwrap();
            assert!(stage.verify(&requested).is_err());
            assert_eq!(fs::read(outside.path().join("alias")).unwrap(), b"ok");
            fs::remove_file(outside.path().join("alias")).unwrap();
            let output = stage.verify(&requested).unwrap();
            let workspace = tempfile::tempdir().unwrap();
            let pinned = crate::sandbox::PinnedWorkspace::open(workspace.path()).unwrap();
            let staged = output
                .prepare_atomic_publication(&pinned)
                .unwrap()
                .stage()
                .unwrap();
            fs::write(workspace.path().join("approved.txt"), b"operator inventory").unwrap();
            assert!(
                staged.publish().is_err(),
                "concurrent original create overwrote operator inventory"
            );
            assert_eq!(
                fs::read(workspace.path().join("approved.txt")).unwrap(),
                b"operator inventory"
            );
        }

        #[test]
        fn stage_rejects_links_and_oversize_and_public_file_modes() {
            let stage = OwnedStage::new().unwrap();
            let requested = selected("approved.txt", "ok");
            symlink("/etc/passwd", stage.path().join("approved.txt")).unwrap();
            assert!(stage.verify(&requested).is_err());
            fs::remove_file(stage.path().join("approved.txt")).unwrap();
            let file = File::create(stage.path().join("approved.txt")).unwrap();
            file.set_len(4097).unwrap();
            assert!(stage.verify(&requested).is_err());
            drop(file);
            original_file(&stage, "approved.txt", b"ok");
            fs::set_permissions(
                stage.path().join("approved.txt"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            // Original upstream defaults to 0644; the stage root is 0700.
            // Normalize the verified single-linked file before publication.
            assert!(stage.verify(&requested).is_ok());
            assert_eq!(
                fs::metadata(stage.path().join("approved.txt"))
                    .unwrap()
                    .mode()
                    & 0o7777,
                0o600
            );
            fs::set_permissions(
                stage.path().join("approved.txt"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            assert!(stage.verify(&requested).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{run_original_upstream, VerifiedOutput};

#[cfg(all(test, target_os = "linux"))]
pub(crate) use linux::verified_test_output;
