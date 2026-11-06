// SPDX-License-Identifier: Apache-2.0
//! Launcher-owned receiving process. An identity alone cannot stop a process.
use super::*;
use std::process::{Child, ExitStatus};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Identity {
    pid: u32,
    generation: String,
}

pub(super) struct Consumer {
    child: Child,
    identity: Identity,
    stop_spent: bool,
    #[cfg(target_os = "linux")]
    registration: Option<fs::File>,
}

impl Consumer {
    pub(super) fn new(child: Child) -> Self {
        Self {
            identity: Identity {
                pid: child.id(),
                generation: crate::token::generate(),
            },
            child,
            stop_spent: false,
            #[cfg(target_os = "linux")]
            registration: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn register(&mut self, run: &crate::pilot_approval::RunGuard) -> Result<()> {
        ensure!(
            !self.stop_spent && self.registration.is_none(),
            "consumer_registration_spent"
        );
        ensure!(!self.exited()?, "consumer_exited");
        self.registration =
            Some(run.register_consumer(self.child.id(), &self.identity.generation)?);
        Ok(())
    }

    pub(super) fn identity(&self) -> Identity {
        self.identity.clone()
    }

    pub(super) fn exited(&mut self) -> std::io::Result<bool> {
        owned_host_exited(&mut self.child)
    }

    /// Withdraw the exact run's authority and await its existing namespace
    /// cleanup before terminating the held recipient. Cleanup failure still
    /// requires physical termination, but cannot yield a successful receipt.
    pub(super) async fn stop_after_cleanup<F>(
        &mut self,
        expected: &Identity,
        grace: Duration,
        cleanup: &mut Option<F>,
    ) -> Result<ExitStatus>
    where
        F: FnOnce() -> Result<()> + Send + 'static,
    {
        ensure!(
            &self.identity == expected,
            "analysis_consumer_generation_mismatch"
        );
        ensure!(!self.stop_spent, "analysis_consumer_stop_spent");
        let confirmation = match cleanup.take() {
            Some(waiter) => tokio::task::spawn_blocking(waiter)
                .await
                .context("selected-owner cleanup worker failed")
                .and_then(|result| result),
            None => Ok(()),
        };
        let stopped = self.stop(expected, grace).await;
        // Do not skip physical cleanup when the daemon/namespace is lost.
        let status = stopped?;
        confirmation?;
        Ok(status)
    }

    /// Always target the held Child. Copied PID/generation claims cannot replace it.
    /// A failed attempt remains spent; it cannot produce a later success receipt.
    pub(super) async fn stop(
        &mut self,
        expected: &Identity,
        grace: Duration,
    ) -> Result<ExitStatus> {
        ensure!(
            &self.identity == expected,
            "analysis_consumer_generation_mismatch"
        );
        ensure!(!self.stop_spent, "analysis_consumer_stop_spent");
        self.stop_spent = true;
        let group = terminate_process_group(self.child.id(), grace).await;
        #[cfg(not(unix))]
        let group = group.and_then(|()| {
            if self.child.try_wait()?.is_none() {
                self.child.kill()?;
            }
            Ok(())
        });
        // Reaping happens even after a signal error, preserving the existing
        // cleanup obligation. The error still prevents a confirmed stop.
        let reaped = reap_owned_host(&mut self.child).await;
        group?;
        reaped
    }
}

/// Test-only adapter around the existing held-child owner and stop path.
#[cfg(all(test, target_os = "linux"))]
pub(crate) struct FixtureProcess(Consumer);

#[cfg(all(test, target_os = "linux"))]
impl FixtureProcess {
    pub(crate) fn spawn(command: &mut Command) -> Result<Self> {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        Ok(Self(Consumer::new(command.spawn()?)))
    }

    pub(crate) fn pid(&self) -> u32 {
        self.0.child.id()
    }

    pub(crate) fn exited(&mut self) -> std::io::Result<bool> {
        self.0.exited()
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        let identity = self.0.identity();
        self.0.stop(&identity, Duration::ZERO).await?;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for FixtureProcess {
    fn drop(&mut self) {
        // Cancellation/panic still kills the held bwrap supervisor. Its private
        // PID namespace loses init and all descendants, including setsid children.
        if matches!(self.0.child.try_wait(), Ok(None)) {
            let _ = self.0.child.kill();
            let _ = self.0.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "spawned only by the bounded process witness"]
    fn effect_child() {
        let path = std::env::var_os("SOU218_EFFECT_WITNESS").expect("witness path");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            use std::io::Write;
            file.write_all(b"effect\n").unwrap();
            file.flush().unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    async fn running(path: &Path) -> Consumer {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "pilot_launcher::consumer::tests::effect_child",
                "--ignored",
            ])
            .env("SOU218_EFFECT_WITNESS", path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut consumer = Consumer::new(command.spawn().unwrap());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while fs::metadata(path).map_or(true, |metadata| metadata.len() == 0) {
            assert!(!consumer.exited().unwrap());
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        consumer
    }

    #[tokio::test]
    async fn cleanup_precedes_stop_and_failure_or_panic_cannot_confirm() {
        for failure in 0..3 {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("effect");
            let mut child = running(&path).await;
            let identity = child.identity();
            let witness = path.clone();
            let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observed_in_worker = observed.clone();
            let mut cleanup = Some(move || {
                // The held recipient must still be alive throughout withdrawal
                // and namespace drain. Observe actual writes, not a PID flag.
                let before = fs::metadata(&witness)?.len();
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                while fs::metadata(&witness)?.len() == before {
                    ensure!(
                        std::time::Instant::now() < deadline,
                        "recipient stopped before cleanup"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                observed_in_worker.store(true, std::sync::atomic::Ordering::SeqCst);
                match failure {
                    1 => bail!("namespace cleanup unconfirmed"),
                    2 => panic!("cleanup witness worker failure"),
                    _ => Ok(()),
                }
            });
            let mut wrong = identity.clone();
            wrong.generation.push('x');
            assert!(child
                .stop_after_cleanup(&wrong, Duration::ZERO, &mut cleanup)
                .await
                .is_err());
            assert!(cleanup.is_some(), "substitution must not spend cleanup");
            let result = child
                .stop_after_cleanup(&identity, Duration::ZERO, &mut cleanup)
                .await;
            assert_eq!(result.is_ok(), failure == 0);
            assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
            assert!(cleanup.is_none());
            assert!(
                child.child.try_wait().unwrap().is_some(),
                "failure still terminates the child"
            );
            let length = fs::metadata(&path).unwrap().len();
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(fs::metadata(&path).unwrap().len(), length);
            assert!(child
                .stop_after_cleanup(&identity, Duration::ZERO, &mut cleanup)
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn held_process_stop_rejects_substitution_and_replay_and_stops_effect() {
        let directory = tempfile::tempdir().unwrap();
        let first_path = directory.path().join("first");
        let second_path = directory.path().join("second");
        let mut first = running(&first_path).await;
        let mut second = running(&second_path).await;
        let first_identity = first.identity();
        let second_identity = second.identity();
        let mut substituted_generation = first_identity.clone();
        substituted_generation.generation = second_identity.generation.clone();
        assert_eq!(
            first
                .stop(&substituted_generation, Duration::ZERO)
                .await
                .unwrap_err()
                .to_string(),
            "analysis_consumer_generation_mismatch"
        );
        let mismatch = first
            .stop(&second_identity, Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(
            mismatch.to_string(),
            "analysis_consumer_generation_mismatch"
        );
        assert!(!first.exited().unwrap());
        assert!(!second.exited().unwrap());
        first
            .stop(&first_identity, Duration::from_millis(10))
            .await
            .unwrap();
        let length = fs::metadata(&first_path).unwrap().len();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(fs::metadata(&first_path).unwrap().len(), length);
        assert!(!second.exited().unwrap());
        let replay = first
            .stop(&first_identity, Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(replay.to_string(), "analysis_consumer_stop_spent");
        second
            .stop(&second_identity, Duration::from_millis(10))
            .await
            .unwrap();
    }
}
