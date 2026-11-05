// SPDX-License-Identifier: Apache-2.0
//! Held launcher/recipient binding. Registration grants no reading purpose.
use super::*;

pub(crate) const CONTRACT: &str = "sw-held-consumer/1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registration {
    contract: String,
    run: Run,
    consumer_pid: u32,
    consumer_start: u64,
    generation: String,
    manifest_fd: i32,
}

impl Registration {
    pub(crate) fn identity(&self) -> String {
        super::digest(&serde_json::to_vec(self).expect("typed registration"))
    }
    pub(crate) fn generation(&self) -> &str {
        &self.generation
    }
    pub(crate) fn host(&self) -> &str {
        &self.run.host_session
    }
    pub(crate) fn expires(&self) -> u64 {
        self.run.expires_at_ms
    }
    pub(crate) fn authorities(&self) -> &BTreeMap<String, String> {
        &self.run.authorities
    }

    pub(crate) fn authority_expiry(&self) -> u64 {
        self.run.authority_expires_at_ms
    }

    /// Expiry or a failed liveness lookup is not physical disposal. Require
    /// both the PID and its entire process group to be absent. Ambiguous
    /// errors and PID/group reuse retain the live slot conservatively.
    pub(crate) fn physically_disposed(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            let Ok(pid) = i32::try_from(self.consumer_pid) else {
                return false;
            };
            if pid <= 1 || fs::metadata("/proc/self/stat").is_err() {
                return false;
            }
            if !matches!(fs::metadata(format!("/proc/{pid}")), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
            {
                return false;
            }
            let result = unsafe { libc::kill(-pid, 0) };
            result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// A live observation, not a durable drain/ownership attestation.
    pub(crate) fn verify(&self, instance: &str, registry: &str, now: u64) -> Result<()> {
        ensure!(
            self.contract == CONTRACT && self.run.contract == "sw-pilot-run/1",
            "consumer_contract"
        );
        ensure!(
            self.run.instance_id == instance && self.run.registry_sha256 == registry,
            "consumer_instance"
        );
        ensure!(
            self.run.expires_at_ms > now && self.run.expires_at_ms - now <= 3_600_000,
            "consumer_expired"
        );
        ensure!(
            !self.generation.is_empty() && self.generation.len() <= 128,
            "consumer_generation"
        );
        ensure!(
            self.run.authorities.len() == 2
                && self.run.authorities.contains_key("filesystem")
                && self.run.authorities.contains_key("git"),
            "consumer_authorities"
        );
        #[cfg(target_os = "linux")]
        {
            verify_manifest(&self.run, &serde_json::to_vec(&self.run)?)?;
            verify_sealed_owner(
                self.run.launcher_pid,
                self.run.launcher_start,
                self.manifest_fd,
                &serde_json::to_vec(self)?,
            )?;
            verify_child(
                self.consumer_pid,
                self.consumer_start,
                self.run.launcher_pid,
            )?;
            ensure!(
                process_start(self.run.launcher_pid)? == self.run.launcher_start,
                "consumer_owner_changed"
            );
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("analysis_consumer_registration_requires_linux")
    }
}

#[cfg(target_os = "linux")]
fn verify_child(pid: u32, start: u64, parent: u32) -> Result<()> {
    ensure!(process_start(pid)? == start, "consumer_generation_changed");
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, rest) = stat.rsplit_once(')').context("consumer_process_identity")?;
    let fields: Vec<_> = rest.split_whitespace().collect();
    ensure!(
        fields.get(1).and_then(|v| v.parse::<u32>().ok()) == Some(parent),
        "consumer_parent_changed"
    );
    ensure!(
        fields.get(2).and_then(|v| v.parse::<u32>().ok()) == Some(pid),
        "consumer_group_changed"
    );
    ensure!(process_start(pid)? == start, "consumer_generation_changed");
    Ok(())
}

#[cfg(target_os = "linux")]
impl RunGuard {
    /// Only the launcher holding the actual Child calls this. Its Consumer
    /// retains the sealed file until the receiving lifecycle is disposed.
    pub(crate) fn register_consumer(&self, pid: u32, generation: &str) -> Result<fs::File> {
        let mut held = manifest()?;
        let registration = Registration {
            contract: CONTRACT.into(),
            run: self.run.clone(),
            consumer_pid: pid,
            consumer_start: process_start(pid)?,
            generation: generation.into(),
            manifest_fd: descriptor(&held),
        };
        seal_bytes(&mut held, &serde_json::to_vec(&registration)?)?;
        registration.verify(
            &self.run.instance_id,
            &self.run.registry_sha256,
            approval::now_ms(),
        )?;
        let cfg = stop_config(&self.run)?;
        let address: std::net::SocketAddr = cfg.socket_address().parse()?;
        ensure!(
            address.ip().is_loopback(),
            "consumer_registration_requires_loopback"
        );
        let key = token(&self.run.home, "native-token")?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(2))
                    .build()?;
                let response = client
                    .post(cfg.endpoint_url(crate::native::consumer::ENDPOINT))
                    .bearer_auth(key)
                    .json(&registration)
                    .send()
                    .await?;
                ensure!(
                    response.status() == reqwest::StatusCode::NO_CONTENT,
                    "consumer_registration_unconfirmed"
                );
                Ok::<(), anyhow::Error>(())
            })?;
        Ok(held)
    }
}

// Real-process fixture used only by the re-executed Linux handler regression.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn held_fixture(
    instance: &str,
    registry: &str,
    host: &str,
    child: &std::process::Child,
) -> (Registration, Vec<fs::File>) {
    held_fixture_with_ttl(instance, registry, host, child, 120_000)
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn held_fixture_with_ttl(
    instance: &str,
    registry: &str,
    host: &str,
    child: &std::process::Child,
    ttl_ms: u64,
) -> (Registration, Vec<fs::File>) {
    let mut run_file = manifest().unwrap();
    let now = approval::now_ms();
    let run = Run {
        contract: "sw-pilot-run/1".into(),
        run_id: crate::token::generate(),
        home: PathBuf::from("/unused-component-fixture"),
        instance_id: instance.into(),
        registry_sha256: registry.into(),
        host_session: host.into(),
        launcher_pid: std::process::id(),
        launcher_start: process_start(std::process::id()).unwrap(),
        manifest_fd: descriptor(&run_file),
        expires_at_ms: now + ttl_ms,
        authority_expires_at_ms: now + 180_000,
        authorities: BTreeMap::from([
            (
                "filesystem".into(),
                digest(format!("{host}:filesystem").as_bytes()),
            ),
            ("git".into(), digest(format!("{host}:git").as_bytes())),
        ]),
        files: vec![],
    };
    seal(&mut run_file, &run).unwrap();
    let mut consumer_file = manifest().unwrap();
    let registration = Registration {
        contract: CONTRACT.into(),
        run,
        consumer_pid: child.id(),
        consumer_start: process_start(child.id()).unwrap(),
        generation: crate::token::generate(),
        manifest_fd: descriptor(&consumer_file),
    };
    seal_bytes(
        &mut consumer_file,
        &serde_json::to_vec(&registration).unwrap(),
    )
    .unwrap();
    (registration, vec![run_file, consumer_file])
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn fixture() -> Registration {
        Registration {
            contract: CONTRACT.into(),
            run: Run {
                contract: "sw-pilot-run/1".into(),
                run_id: "a".repeat(32),
                home: PathBuf::from("/unused"),
                instance_id: "instance".into(),
                registry_sha256: "b".repeat(64),
                host_session: "host".into(),
                launcher_pid: 0,
                launcher_start: 0,
                manifest_fd: -1,
                expires_at_ms: 2000,
                authority_expires_at_ms: 3000,
                authorities: BTreeMap::from([
                    ("filesystem".into(), "c".repeat(64)),
                    ("git".into(), "d".repeat(64)),
                ]),
                files: vec![],
            },
            consumer_pid: 0,
            consumer_start: 0,
            generation: "generation".into(),
            manifest_fd: -1,
        }
    }

    #[test]
    fn copied_metadata_never_proves_runtime_and_strict_binding_rejects_changes() {
        let original = fixture();
        assert!(original.verify("instance", &"b".repeat(64), 1000).is_err());
        assert_eq!(
            original
                .verify("other", &"b".repeat(64), 1000)
                .unwrap_err()
                .to_string(),
            "consumer_instance"
        );
        assert_eq!(
            original
                .verify("instance", &"b".repeat(64), 2000)
                .unwrap_err()
                .to_string(),
            "consumer_expired"
        );
        let mut value = serde_json::to_value(&original).unwrap();
        value["drained"] = json!(true);
        assert!(serde_json::from_value::<Registration>(value).is_err());
        let mut changed = original.clone();
        changed.generation.clear();
        assert_eq!(
            changed
                .verify("instance", &"b".repeat(64), 1000)
                .unwrap_err()
                .to_string(),
            "consumer_generation"
        );
        changed = original;
        changed.run.authorities.remove("git");
        assert_eq!(
            changed
                .verify("instance", &"b".repeat(64), 1000)
                .unwrap_err()
                .to_string(),
            "consumer_authorities"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_consumer_bytes_and_real_child_generation_cannot_be_substituted() {
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let start = process_start(pid).unwrap();
        let parent = std::process::id();
        assert!(verify_child(pid, start, parent).is_ok());
        assert!(verify_child(pid, start + 1, parent).is_err());
        assert!(verify_child(pid, start, parent + 1).is_err());
        let mut held = manifest().unwrap();
        let bytes = b"exact consumer manifest";
        seal_bytes(&mut held, bytes).unwrap();
        let fd = descriptor(&held);
        let parent_start = process_start(parent).unwrap();
        assert!(verify_sealed_owner(parent, parent_start, fd, bytes).is_ok());
        assert!(verify_sealed_owner(parent, parent_start, fd, b"substituted").is_err());
        assert!(verify_sealed_owner(parent, parent_start + 1, fd, bytes).is_err());
        drop(held);
        assert!(verify_sealed_owner(parent, parent_start, fd, bytes).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(verify_child(pid, start, parent).is_err());
    }
}

#[cfg(test)]
pub(crate) fn transaction_fixture() -> Registration {
    tests::fixture()
}
