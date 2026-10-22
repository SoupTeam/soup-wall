//! Negative tests for the worker handshake and reply binding (SOU-102).
//!
//! The package is the real frozen package, installed and verified by the real `Store`.
//! Only the program the interpreter runs is replaced (`with_bootstrap`, test builds only),
//! so each case injects one exact ready or reply frame and everything else, including the
//! frame checks, is the production code path. A control case proves the fake speaks the
//! protocol correctly; every negative case then fails for the one reason it names.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::*;
use crate::classifier_runtime::package::{self as pkg, Which};

const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn home() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Python expressions (evaluated inside the fake worker) for the ready line and the reply.
struct Fake {
    ready: String,
    reply: String,
}

fn ready_frame(extra: &str) -> String {
    format!(r#"json.dumps({{"v": P, "ready": True, "classifier_sha256": sha{extra}}})"#)
}

fn good_reply() -> String {
    reply_with(
        r#""v": P, "id": req["id"], "input_sha256": req["input_sha256"], "result_json": "{}""#,
    )
}

fn reply_with(fields: &str) -> String {
    format!("json.dumps({{{fields}}})")
}

fn program(marker: &Path, fake: &Fake) -> String {
    format!(
        r#"import json, os, sys, time
open({marker:?}, "w").write(str(os.getpid()))
P = "{proto}"
sha = sys.argv[2]
print({ready}, flush=True)
line = sys.stdin.readline()
req = json.loads(line) if line else {{}}
reply = {reply}
if reply is not None:
    print(reply, flush=True)
time.sleep(30)
"#,
        marker = marker.display().to_string(),
        proto = WORKER_PROTOCOL,
        ready = fake.ready,
        reply = fake.reply,
    )
}

struct Rig {
    _home: tempfile::TempDir,
    marker: PathBuf,
    classifier: PackagedClassifier,
}

fn rig(fake: Fake, prepared: bool) -> Rig {
    let dir = home();
    let store = Store::new(dir.path());
    store
        .install(
            &pkg::build(Which::Frozen, &root()).unwrap(),
            Path::new("/usr/bin/python3"),
        )
        .unwrap();
    let marker = dir.path().join("fake.pid");
    let mut classifier = PackagedClassifier::from_home(dir.path())
        .unwrap()
        .with_bootstrap(program(&marker, &fake));
    if prepared {
        classifier = classifier.prepared();
    }
    Rig {
        _home: dir,
        marker,
        classifier,
    }
}

/// The fake process that was started must be gone (killed and reaped), not left behind.
fn assert_fake_gone(marker: &Path) {
    let pid: u32 = std::fs::read_to_string(marker)
        .expect("the fake worker did not start")
        .trim()
        .parse()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    while Path::new(&format!("/proc/{pid}")).exists() {
        assert!(Instant::now() < until, "fake worker {pid} was left running");
        std::thread::sleep(Duration::from_millis(20));
    }
}

const MISMATCH: &str = "worker ready frame does not match the installed package";

fn ready_case(ready: String, expected: &str) {
    let rig = rig(
        Fake {
            ready,
            reply: "None".into(),
        },
        true,
    );
    let error = rig.classifier.prepare_worker().unwrap_err().to_string();
    let chain = format!("{error:#}");
    assert!(chain.contains(expected), "unexpected error: {chain}");
    assert!(
        rig.classifier.readiness().is_none(),
        "no readiness may be recorded"
    );
    assert!(
        rig.classifier.worker_pid().is_none(),
        "no worker may be retained"
    );
    assert_fake_gone(&rig.marker);
}

fn reply_case(reply: String, expected: &str) {
    let rig = rig(
        Fake {
            ready: ready_frame(""),
            reply,
        },
        false,
    );
    let error = format!("{:#}", rig.classifier.classify_raw("{}").unwrap_err());
    assert!(error.contains(expected), "unexpected error: {error}");
    assert!(
        rig.classifier.worker_pid().is_none(),
        "a bad reply must retire the worker"
    );
    assert_fake_gone(&rig.marker);
}

#[test]
fn control_correct_ready_and_reply_are_accepted() {
    let rig = rig(
        Fake {
            ready: ready_frame(""),
            reply: good_reply(),
        },
        true,
    );
    let readiness = rig
        .classifier
        .prepare_worker()
        .expect("a correct ready frame is accepted");
    assert_eq!(rig.classifier.readiness(), Some(readiness));
    assert_eq!(rig.classifier.classify_raw("{}").unwrap(), "{}");
    assert!(rig.classifier.worker_pid().is_some());
}

#[test]
fn ready_with_wrong_classifier_digest_is_refused() {
    ready_case(
        format!(r#"json.dumps({{"v": P, "ready": True, "classifier_sha256": "{ZERO}"}})"#),
        MISMATCH,
    );
}

#[test]
fn ready_with_wrong_protocol_version_is_refused() {
    ready_case(
        r#"json.dumps({"v": "sw-classifier-worker/0", "ready": True, "classifier_sha256": sha})"#
            .into(),
        MISMATCH,
    );
}

#[test]
fn ready_false_is_refused() {
    ready_case(
        r#"json.dumps({"v": P, "ready": False, "classifier_sha256": sha})"#.into(),
        MISMATCH,
    );
}

#[test]
fn ready_with_unknown_field_is_refused() {
    ready_case(ready_frame(r#", "extra": 1"#), "invalid ready frame");
}

#[test]
fn malformed_ready_frame_is_refused() {
    ready_case(r#""{not json""#.into(), "invalid ready frame");
}

#[test]
fn reply_with_wrong_request_id_is_refused() {
    reply_case(
        reply_with(
            r#""v": P, "id": req["id"] + 1, "input_sha256": req["input_sha256"], "result_json": "{}""#,
        ),
        "worker reply id does not match the request",
    );
}

#[test]
fn reply_bound_to_different_input_is_refused() {
    reply_case(
        reply_with(&format!(
            r#""v": P, "id": req["id"], "input_sha256": "{ZERO}", "result_json": "{{}}""#
        )),
        "worker reply is bound to different input",
    );
}

#[test]
fn reply_with_wrong_protocol_version_is_refused() {
    reply_case(
        reply_with(
            r#""v": "sw-classifier-worker/0", "id": req["id"], "input_sha256": req["input_sha256"], "result_json": "{}""#,
        ),
        "worker protocol mismatch",
    );
}

#[test]
fn reply_with_unknown_field_is_refused() {
    reply_case(
        reply_with(
            r#""v": P, "id": req["id"], "input_sha256": req["input_sha256"], "result_json": "{}", "extra": 1"#,
        ),
        "invalid worker reply",
    );
}

#[test]
fn malformed_reply_is_refused() {
    reply_case(r#""{not json""#.into(), "invalid worker reply");
}
