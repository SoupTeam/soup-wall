// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::{
    fs as stdfs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Barrier},
};
thread_local! { static BOUNDARY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const {std::cell::RefCell::new(None)}; }
pub(super) fn at_publication_boundary() {
    if let Some(f) = BOUNDARY.with(|v| v.borrow_mut().take()) {
        f()
    }
}
fn boundary(f: impl FnOnce() + 'static) {
    BOUNDARY.with(|v| *v.borrow_mut() = Some(Box::new(f)));
}
fn private(path: &Path, bytes: impl AsRef<[u8]>) {
    stdfs::write(path, bytes).unwrap();
    stdfs::set_permissions(path, stdfs::Permissions::from_mode(0o600)).unwrap();
}
struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    settings: Settings,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap();
        stdfs::set_permissions(&home, stdfs::Permissions::from_mode(0o700)).unwrap();
        private(&home.join("config.yaml"), b"port: 0\n");
        // Config rejects port zero; select an available endpoint instead.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        private(&home.join("config.yaml"), format!("port: {port}\n"));
        private(
            &home.join("credential"),
            format!("sw_agent_{}", "a".repeat(43)),
        );
        private(&home.join("issuers.json"),br#"{"schema_version":1,"issuers":[{"key_id":"operator","public_key_hex":"0101010101010101010101010101010101010101010101010101010101010101","revoked":false}]}"#);
        let settings = Settings {
            console: "http://127.0.0.1:12345/".into(),
            tenant: "tenant-1".into(),
            agent: "agent-1".into(),
            credential_file: home.join("credential"),
            issuer_keyring: home.join("issuers.json"),
            ca_file: None,
        };
        Self {
            _dir: dir,
            home,
            settings,
        }
    }
    fn preview(&self) -> String {
        preview(&self.home, &self.settings, true).unwrap()["confirmation"]
            .as_str()
            .unwrap()
            .into()
    }
}
#[test]
fn exact_consent_atomic_commit_and_retry_preserve_all_unrelated_files() {
    let f = Fixture::new();
    private(&f.home.join("user-policy-cache.json"), b"retained");
    private(&f.home.join("grants-spent.json"), b"ledger");
    let before: Vec<_> = stdfs::read_dir(&f.home)
        .unwrap()
        .map(|x| x.unwrap().file_name())
        .collect();
    let confirmation = f.preview();
    assert_eq!(before.len(), stdfs::read_dir(&f.home).unwrap().count());
    assert!(apply(&f.home, &f.settings, true, &"0".repeat(64)).is_err());
    assert!(!f.home.join(PROFILE).exists());
    let report = apply(&f.home, &f.settings, true, &confirmation).unwrap();
    assert_eq!(report["status"], "committed");
    assert_eq!(
        apply(&f.home, &f.settings, true, &confirmation).unwrap()["status"],
        "already_committed"
    );
    assert_eq!(
        stdfs::read(f.home.join("user-policy-cache.json")).unwrap(),
        b"retained"
    );
    assert_eq!(
        stdfs::read(f.home.join("grants-spent.json")).unwrap(),
        b"ledger"
    );
    let raw = stdfs::read(f.home.join(PROFILE)).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("sw_agent_"));
    assert_eq!(
        stdfs::metadata(f.home.join(PROFILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}
#[test]
fn stale_file_config_and_replaced_same_content_input_are_refused() {
    for kind in ["credential", "config", "issuer"] {
        let f = Fixture::new();
        let c = f.preview();
        match kind {
            "credential" => private(
                &f.settings.credential_file,
                format!("sw_agent_{}", "b".repeat(43)),
            ),
            "config" => private(&f.home.join("config.yaml"), b"enforce: true\nport: 30333\n"),
            _ => {
                let next = f.home.join("next");
                private(&next, stdfs::read(&f.settings.issuer_keyring).unwrap());
                stdfs::rename(next, &f.settings.issuer_keyring).unwrap();
            }
        }
        assert!(apply(&f.home, &f.settings, true, &c).is_err(), "{kind}");
        assert!(!f.home.join(PROFILE).exists());
    }
}
#[test]
fn concurrent_apply_cannot_overwrite_another_confirmation() {
    let f = Fixture::new();
    let c = f.preview();
    let mut other = f.settings.clone();
    other.agent = "other".into();
    let c2 = preview(&f.home, &other, true).unwrap()["confirmation"]
        .as_str()
        .unwrap()
        .to_string();
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = vec![];
    for (s, c) in [(f.settings.clone(), c), (other, c2)] {
        let home = f.home.clone();
        let b = barrier.clone();
        threads.push(std::thread::spawn(move || {
            b.wait();
            apply(&home, &s, true, &c).is_ok()
        }));
    }
    barrier.wait();
    assert_eq!(
        threads
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|ok| *ok)
            .count(),
        1
    );
    assert!(selected_profile(&f.home).is_ok());
}
#[test]
fn interruption_before_commit_preserves_old_selector_and_is_retryable() {
    let f = Fixture::new();
    let c = f.preview();
    apply(&f.home, &f.settings, true, &c).unwrap();
    let old = stdfs::read(f.home.join(PROFILE)).unwrap();
    let mut next = f.settings.clone();
    next.agent = "replacement".into();
    let c = preview(&f.home, &next, true).unwrap()["confirmation"]
        .as_str()
        .unwrap()
        .to_string();
    boundary(|| panic!("simulate interrupted writer"));
    let caught = std::panic::catch_unwind(|| apply(&f.home, &next, true, &c));
    assert!(caught.is_err());
    assert_eq!(stdfs::read(f.home.join(PROFILE)).unwrap(), old);
    assert!(apply(&f.home, &next, true, &c).is_ok());
}
#[test]
fn changed_during_staging_is_refused_before_any_selection() {
    let f = Fixture::new();
    let c = f.preview();
    let path = f.settings.credential_file.clone();
    boundary(move || private(&path, format!("sw_agent_{}", "b".repeat(43))));
    assert!(apply(&f.home, &f.settings, true, &c).is_err());
    assert!(!f.home.join(PROFILE).exists());
}
#[test]
fn unsafe_symlink_hardlink_permissions_fifo_size_and_malformed_state_fail_closed() {
    let f = Fixture::new();
    let c = f.preview();
    let safe = f.home.join("safe");
    stdfs::rename(&f.settings.credential_file, &safe).unwrap();
    std::os::unix::fs::symlink(&safe, &f.settings.credential_file).unwrap();
    assert!(apply(&f.home, &f.settings, true, &c).is_err());
    stdfs::remove_file(&f.settings.credential_file).unwrap();
    stdfs::rename(&safe, &f.settings.credential_file).unwrap();
    stdfs::hard_link(&f.settings.credential_file, &safe).unwrap();
    assert!(f.preview_result().is_err());
    stdfs::remove_file(safe).unwrap();
    stdfs::set_permissions(
        &f.settings.credential_file,
        stdfs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(f.preview_result().is_err());
    stdfs::set_permissions(
        &f.settings.credential_file,
        stdfs::Permissions::from_mode(0o600),
    )
    .unwrap();
    private(&f.home.join(PROFILE), b"{}");
    assert!(f.preview_result().is_err());
    private(&f.home.join(PROFILE), vec![b' '; MAX_PROFILE + 1]);
    assert!(f.preview_result().is_err());
    stdfs::remove_file(f.home.join(PROFILE)).unwrap();
    stdfs::remove_file(&f.settings.credential_file).unwrap();
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(f.settings.credential_file.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(f.preview_result().is_err());
}
impl Fixture {
    fn preview_result(&self) -> Result<serde_json::Value> {
        preview(&self.home, &self.settings, true)
    }
}
#[test]
fn parent_and_home_substitution_invalidate_consents() {
    let f = Fixture::new();
    let c = f.preview();
    let renamed = f
        .home
        .with_extension(format!("old-{}", crate::token::generate()));
    stdfs::rename(&f.home, &renamed).unwrap();
    stdfs::create_dir(&f.home).unwrap();
    stdfs::set_permissions(&f.home, stdfs::Permissions::from_mode(0o700)).unwrap();
    assert!(apply(&f.home, &f.settings, true, &c).is_err());
    assert!(!f.home.join(PROFILE).exists());
    stdfs::remove_dir_all(&f.home).unwrap();
    stdfs::rename(renamed, &f.home).unwrap();
}
#[test]
fn lifecycle_exclusion_and_foreign_listener_are_honest_blockers() {
    let f = Fixture::new();
    let c = f.preview();
    let manager = crate::lifecycle::Manager::new(&f.home);
    let lock = manager.lock().unwrap();
    assert!(apply(&f.home, &f.settings, true, &c).is_err());
    drop(lock);
    let config =
        crate::Config::from_yaml(&stdfs::read_to_string(f.home.join("config.yaml")).unwrap())
            .unwrap();
    let listener = std::net::TcpListener::bind(config.socket_address()).unwrap();
    assert!(apply(&f.home, &f.settings, true, &c).is_err());
    drop(listener);
    assert!(apply(&f.home, &f.settings, true, &c).is_ok());
}
#[test]
fn disconnect_keeps_last_trust_and_state_and_works_without_credentials() {
    let f = Fixture::new();
    let c = f.preview();
    apply(&f.home, &f.settings, true, &c).unwrap();
    let before = selected_profile(&f.home).unwrap();
    stdfs::remove_file(&f.settings.credential_file).unwrap();
    private(&f.home.join("user-policy-cache.json"), b"signed state");
    let c = preview(&f.home, &f.settings, false).unwrap()["confirmation"]
        .as_str()
        .unwrap()
        .to_string();
    apply(&f.home, &f.settings, false, &c).unwrap();
    let after = selected_profile(&f.home).unwrap();
    assert!(!after.enabled);
    assert_eq!(before.settings, after.settings);
    assert_ne!(before.generation, after.generation);
    assert_eq!(
        stdfs::read(f.home.join("user-policy-cache.json")).unwrap(),
        b"signed state"
    );
    assert_eq!(
        apply(&f.home, &f.settings, false, &c).unwrap()["status"],
        "already_committed"
    );
}

fn saved_policy(f: &Fixture) -> crate::managed_policy::SignedAgentPolicy {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let key = crate::managed_policy::PinnedIssuerKey {
        key_id: "operator".into(),
        public_key: pair.public_key().as_ref().try_into().unwrap(),
        revoked: false,
    };
    private(
        &f.settings.issuer_keyring,
        crate::managed_policy::serialize_keyring(&[key]).unwrap(),
    );
    let mut saved = crate::managed_policy::SignedAgentPolicy {
        schema_version: 1,
        tenant_id: f.settings.tenant.clone(),
        agent_id: f.settings.agent.clone(),
        revision: "retained".into(),
        deployment_sequence: 19,
        issued_at_unix: 1000,
        expires_at_unix: 2000,
        issuer_key_id: "operator".into(),
        policy_yaml: "default: deny\n".into(),
        policy_sha256: hash(b"default: deny\n"),
        signature_hex: String::new(),
    };
    saved.signature_hex = pair
        .sign(&saved.signing_transcript().unwrap())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    private(
        &f.home.join("managed-policy-active.json"),
        serde_json::to_vec(&saved).unwrap(),
    );
    saved
}
#[test]
fn incompatible_retained_policy_cannot_replace_previous_valid_connection() {
    let f = Fixture::new();
    saved_policy(&f);
    let consent = f.preview();
    apply(&f.home, &f.settings, true, &consent).unwrap();
    let old = stdfs::read(f.home.join(PROFILE)).unwrap();
    let mut other = f.settings.clone();
    other.agent = "other".into();
    assert!(preview(&f.home, &other, true).is_err());
    assert_eq!(stdfs::read(f.home.join(PROFILE)).unwrap(), old);
    let consent = preview(&f.home, &f.settings, false).unwrap()["confirmation"]
        .as_str()
        .unwrap()
        .to_owned();
    apply(&f.home, &f.settings, false, &consent).unwrap();
    assert_eq!(
        crate::managed_policy::parse_bounded(
            &stdfs::read(f.home.join("managed-policy-active.json")).unwrap()
        )
        .unwrap()
        .deployment_sequence,
        19
    );
}
#[test]
fn changed_cache_and_selector_invalidate_previews() {
    for change_cache in [false, true] {
        let f = Fixture::new();
        let mut saved = saved_policy(&f);
        let consent = f.preview();
        if change_cache {
            saved.deployment_sequence += 1;
            private(
                &f.home.join("managed-policy-active.json"),
                serde_json::to_vec(&saved).unwrap(),
            );
        } else {
            let another = f.preview();
            apply(&f.home, &f.settings, true, &another).unwrap();
            let p = selected_profile(&f.home).unwrap();
            let mut altered = p.clone();
            altered.generation = crate::token::generate();
            private(&f.home.join(PROFILE), serde_json::to_vec(&altered).unwrap());
        }
        assert!(apply(&f.home, &f.settings, true, &consent).is_err());
    }
}
#[test]
fn reference_aliases_and_wrong_profile_versions_are_refused() {
    let f = Fixture::new();
    let mut s = f.settings.clone();
    s.credential_file = f.home.join(".").join("credential");
    assert!(preview(&f.home, &s, true).is_err());
    let c = f.preview();
    apply(&f.home, &f.settings, true, &c).unwrap();
    let mut p = selected_profile(&f.home).unwrap();
    p.schema_version = 2;
    private(&f.home.join(PROFILE), serde_json::to_vec(&p).unwrap());
    assert!(f.preview_result().is_err());
}

#[test]
fn substituted_stage_is_not_published_or_deleted_as_owned() {
    let f = Fixture::new();
    let consent = f.preview();
    let home = f.home.clone();
    boundary(move || {
        let stage = stdfs::read_dir(&home)
            .unwrap()
            .map(|p| p.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .as_encoded_bytes()
                    .starts_with(b".managed-console-stage-")
            })
            .unwrap();
        stdfs::rename(&stage, home.join("unselected-original")).unwrap();
        private(&stage, b"unowned substituted stage");
    });
    assert!(apply(&f.home, &f.settings, true, &consent).is_err());
    assert!(!f.home.join(PROFILE).exists());
    assert!(stdfs::read_dir(&f.home)
        .unwrap()
        .filter_map(|p| p.ok())
        .any(|p| p
            .file_name()
            .as_encoded_bytes()
            .starts_with(b".managed-console-stage-")
            && stdfs::read(p.path()).unwrap() == b"unowned substituted stage"));
}
#[test]
fn recorded_unresponsive_process_and_registered_service_block_changes() {
    for service in [false, true] {
        let f = Fixture::new();
        let manager = crate::lifecycle::Manager::new(&f.home);
        drop(manager.lock().unwrap());
        if service {
            let dir = f.home.join("service");
            stdfs::create_dir(&dir).unwrap();
            stdfs::set_permissions(&dir, stdfs::Permissions::from_mode(0o700)).unwrap();
            private(&dir.join("ownership.json"), b"{}");
        } else {
            let instance = crate::token::generate();
            let state = crate::lifecycle::State {
                process: Some(crate::lifecycle::ProcessRecord {
                    pid: u32::MAX,
                    instance: instance.clone(),
                    binary_digest: "1".repeat(64),
                    config_digest: "2".repeat(64),
                    port: 31337,
                    bind: "127.0.0.1".into(),
                    launch_log: format!(".launch-{instance}.log"),
                }),
                ..Default::default()
            };
            private(
                &f.home.join("versions/lifecycle.json"),
                serde_json::to_vec(&state).unwrap(),
            );
        }
        let consent = f.preview();
        assert!(apply(&f.home, &f.settings, true, &consent).is_err());
        assert!(!f.home.join(PROFILE).exists());
    }
}
