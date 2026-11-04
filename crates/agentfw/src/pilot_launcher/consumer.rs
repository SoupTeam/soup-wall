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
        }
    }

    pub(super) fn identity(&self) -> Identity {
        self.identity.clone()
    }

    pub(super) fn exited(&mut self) -> std::io::Result<bool> {
        owned_host_exited(&mut self.child)
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
