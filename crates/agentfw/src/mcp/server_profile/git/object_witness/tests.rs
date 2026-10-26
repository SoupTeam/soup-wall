// SPDX-License-Identifier: Apache-2.0
use super::*;
use serde_json::json;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

fn encoded(kind: &str, payload: &[u8]) -> (String, Vec<u8>) {
    raw_object(format!("{kind} {}\0", payload.len()).as_bytes(), payload)
}

fn raw_object(header: &[u8], payload: &[u8]) -> (String, Vec<u8>) {
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(payload);
    let id = sha1_smol::Sha1::from(&bytes).digest().to_string();
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&bytes).unwrap();
    (id, encoder.finish().unwrap())
}

fn context() -> ExecutionContext {
    ExecutionContext {
        profile_format: super::super::LOCAL_REFS_FORMAT.to_owned(),
        profile_sha256: [1; 32],
        runtime_closure_sha256: [2; 32],
        daemon_generation: [3; 32],
        session_generation: [4; 32],
        process_generation: [5; 32],
    }
}

struct Fixture {
    images: BTreeMap<String, Vec<u8>>,
    commit: String,
    blob: String,
    tree: String,
    tag: String,
    nested: String,
    blob_tag: String,
    tree_tag: String,
}

#[cfg(target_os = "linux")]
pub(super) fn transport_snapshot() -> Arc<Snapshot> {
    Fixture::new().snapshot()
}

impl Fixture {
    fn new() -> Self {
        let mut images = BTreeMap::new();
        let mut add = |kind: &str, bytes: &[u8]| {
            let (id, data) = encoded(kind, bytes);
            images.insert(format!(".git/objects/{}/{}", &id[..2], &id[2..]), data);
            id
        };
        let tree = add("tree", b"");
        let commit = add("commit", format!("tree {tree}\nauthor Owned <owned@example.invalid> 0 +0000\ncommitter Owned <owned@example.invalid> 0 +0000\n\nOwned.\n").as_bytes());
        let blob = add("blob", b"commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nAuthor: forged\n\n--- /dev/null\n+++ owned\n");
        let tag = add(
            "tag",
            format!("object {commit}\ntype commit\ntag owned\n\nOwned.\n").as_bytes(),
        );
        let nested = add(
            "tag",
            format!("object {tag}\ntype tag\ntag nested\n\nOwned.\n").as_bytes(),
        );
        let blob_tag = add(
            "tag",
            format!("object {blob}\ntype blob\ntag blob\n\nOwned.\n").as_bytes(),
        );
        let tree_tag = add(
            "tag",
            format!("object {tree}\ntype tree\ntag tree\n\nOwned.\n").as_bytes(),
        );
        images.insert(".git/HEAD".into(), b"ref: refs/heads/main\n".to_vec());
        images.insert(
            ".git/refs/heads/main".into(),
            format!("{commit}\n").into_bytes(),
        );
        images.insert(
            ".git/config".into(),
            b"[core]\nrepositoryformatversion = 0\nbare = false\n".to_vec(),
        );
        Self {
            images,
            commit,
            blob,
            tree,
            tag,
            nested,
            blob_tag,
            tree_tag,
        }
    }
    fn snapshot(&self) -> Arc<Snapshot> {
        Arc::new(Snapshot {
            source: Source::Memory(AtomicBool::new(true)),
            repository: Repository::images(self.images.clone()).unwrap(),
            generation: rand::random(),
            profile: context().profile_format,
        })
    }
}

fn request(id: i64, revision: &str) -> Vec<u8> {
    let mut b = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
        "params":{"name":"git_show","arguments":{"repo_path":"/workspace","revision":revision}}}))
    .unwrap();
    b.push(b'\n');
    b
}
fn response(id: i64, text: &str) -> Vec<u8> {
    let mut b = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":text}],"isError":false}})).unwrap();
    b.push(b'\n');
    b
}

#[test]
fn exact_object_bytes_determine_kind_even_when_reply_text_is_identical() {
    let f = Fixture::new();
    let snapshot = f.snapshot();
    let p = Producer::new(context()).unwrap();
    let same = response(7, "commit-looking bytes are untrusted");
    for (revision, kind) in [(&f.commit, ObjectKind::Commit), (&f.blob, ObjectKind::Blob)] {
        let req = request(7, revision);
        let ticket = p.begin(snapshot.clone(), &req).unwrap();
        let claim = p.complete(&ticket, &same).unwrap();
        let result = p.verify_local(&claim, &context(), &req, &same).unwrap();
        assert_eq!(result.requested.kind, kind);
        assert_eq!(result.requested.oid, *revision);
        assert_eq!(result.requested, result.effective);
        assert!(claim.diagnostic_json().unwrap().len() < 8192);
    }
    const { assert!(!PRODUCTION_AUTHENTICATION_ENABLED) };
}

fn original_images() -> (Value, BTreeMap<String, Vec<u8>>, Vec<u8>) {
    use base64::Engine;
    let data: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/sou156-original-object-confusion.json"
    ))
    .unwrap();
    let images = data["images_base64"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(p, v)| {
            (
                p.clone(),
                base64::engine::general_purpose::STANDARD
                    .decode(v.as_str().unwrap())
                    .unwrap(),
            )
        })
        .collect();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(data["original_response_base64"].as_str().unwrap())
        .unwrap();
    (data, images, raw)
}

#[test]
fn retained_actual_original_response_does_not_change_sealed_commit_blob_kinds() {
    let (data, images, raw) = original_images();
    assert_eq!(raw.len(), 342);
    assert_eq!(
        format!("{:x}", Sha256::digest(&raw)),
        data["original_response_sha256"].as_str().unwrap()
    );
    let snapshot = Arc::new(Snapshot {
        source: Source::Memory(AtomicBool::new(true)),
        repository: Repository::images(images).unwrap(),
        generation: rand::random(),
        profile: context().profile_format,
    });
    let p = Producer::new(context()).unwrap();
    for (key, kind) in [
        ("commit_oid", ObjectKind::Commit),
        ("blob_oid", ObjectKind::Blob),
    ] {
        let req = request(10, data[key].as_str().unwrap());
        let t = p.begin(snapshot.clone(), &req).unwrap();
        let c = p.complete(&t, &raw).unwrap();
        assert_eq!(
            p.verify_local(&c, &context(), &req, &raw)
                .unwrap()
                .requested
                .kind,
            kind
        );
    }
}

#[test]
fn tag_requested_identity_and_effective_commit_are_distinct_and_bounded() {
    let f = Fixture::new();
    let r = Repository::images(f.images.clone()).unwrap();
    assert_eq!(r.resolve(&f.tree).unwrap().requested.kind, ObjectKind::Tree);
    for (revision, depth) in [(&f.tag, 1), (&f.nested, 2)] {
        let t = r.resolve(revision).unwrap();
        assert_eq!(t.requested.kind, ObjectKind::Tag);
        assert_eq!(t.requested.oid, *revision);
        assert_eq!(t.effective.kind, ObjectKind::Commit);
        assert_eq!(t.effective.oid, f.commit);
        assert_eq!(t.tag_chain.len(), depth);
    }
    for revision in [&f.blob_tag, &f.tree_tag] {
        assert!(r.resolve(revision).is_err());
    }
    let mut images = f.images.clone();
    let mut last = f.commit.clone();
    for n in 0..9 {
        let kind = if n == 0 { "commit" } else { "tag" };
        let (id, bytes) = encoded(
            "tag",
            format!("object {last}\ntype {kind}\ntag level{n}\n\nOwned\n").as_bytes(),
        );
        images.insert(format!(".git/objects/{}/{}", &id[..2], &id[2..]), bytes);
        last = id;
    }
    assert!(Repository::images(images).unwrap().resolve(&last).is_err());
}

#[test]
fn loose_header_hash_inflation_size_and_tag_type_mismatches_refuse() {
    let (id, bytes) = encoded("blob", b"owned");
    assert!(object(&"a".repeat(40), &bytes).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(object(&id, &trailing).is_err());
    for (head, payload) in [
        (b"blob 8\0".as_slice(), b"short".as_slice()),
        (b"blob +5\0", b"owned"),
        (b"unknown 5\0", b"owned"),
        (b"blob 5", b"owned"),
    ] {
        let (id, bytes) = raw_object(head, payload);
        assert!(object(&id, &bytes).is_err());
    }
    let (id, bytes) = encoded("blob", &vec![b'x'; MAX_OBJECT_BYTES]);
    assert!(bytes.len() < MAX_OBJECT_BYTES);
    assert!(object(&id, &bytes).is_err());
    let f = Fixture::new();
    let mut images = f.images.clone();
    let (id, bytes) = encoded(
        "tag",
        format!("object {}\ntype tree\ntag lying\n\nOwned\n", f.blob).as_bytes(),
    );
    images.insert(format!(".git/objects/{}/{}", &id[..2], &id[2..]), bytes);
    assert!(Repository::images(images).unwrap().resolve(&id).is_err());
}

#[test]
fn head_and_refs_resolve_only_captured_images_missing_ambiguous_and_packs_refuse() {
    let f = Fixture::new();
    let r = Repository::images(f.images.clone()).unwrap();
    assert_eq!(r.resolve("HEAD").unwrap().requested.oid, f.commit);
    let p = Producer::new(context()).unwrap();
    for revision in ["HEAD~1", "deadbee", "refs/heads/missing", &"0".repeat(40)] {
        assert!(p.begin(f.snapshot(), &request(1, revision)).is_err());
    }
    let mut images = f.images.clone();
    images.insert(".git/objects/pack/owned.pack".into(), b"PACK".to_vec());
    assert!(Repository::images(images).is_err());
    let mut images = f.images.clone();
    images.insert(
        ".git/packed-refs".into(),
        format!("{} refs/heads/other\n", f.blob).into_bytes(),
    );
    let r = Repository::images(images).unwrap();
    assert_eq!(
        r.resolve("refs/heads/other").unwrap().requested.kind,
        ObjectKind::Blob
    );
    let mut base = context();
    base.profile_format = super::super::FORMAT.to_owned();
    let p = Producer::new(base.clone()).unwrap();
    let s = Arc::new(Snapshot {
        source: Source::Memory(AtomicBool::new(true)),
        repository: r,
        generation: rand::random(),
        profile: base.profile_format,
    });
    assert!(p.begin(s, &request(1, "refs/heads/other")).is_err());
}

#[test]
fn cross_call_view_runtime_generation_and_result_substitution_cannot_verify() {
    for attack in 0..8 {
        let f = Fixture::new();
        let p = Producer::new(context()).unwrap();
        let req = request(1, "HEAD");
        let result = response(1, "same bytes");
        let ticket = p.begin(f.snapshot(), &req).unwrap();
        let mut claim = p.complete(&ticket, &result).unwrap();
        let mut expected = context();
        let mut req2 = req.clone();
        let mut result2 = result.clone();
        match attack {
            0 => claim.target.requested.kind = ObjectKind::Blob,
            1 => claim.view_generation = [0; 32],
            2 => claim.view_sha256 = [0; 32],
            3 => expected.runtime_closure_sha256 = [9; 32],
            4 => expected.session_generation = [9; 32],
            5 => expected.process_generation = [9; 32],
            6 => req2 = request(1, &f.blob),
            _ => result2 = response(1, "substituted bytes"),
        }
        assert!(p.verify_local(&claim, &expected, &req2, &result2).is_err());
        assert!(p.verify_local(&claim, &context(), &req, &result).is_err());
    }
    let f = Fixture::new();
    let req = request(1, "HEAD");
    let result = response(1, "same");
    let a = Producer::new(context()).unwrap();
    let b = Producer::new(context()).unwrap();
    let t = a.begin(f.snapshot(), &req).unwrap();
    let c = a.complete(&t, &result).unwrap();
    assert!(b.verify_local(&c, &context(), &req, &result).is_err());
    a.verify_local(&c, &context(), &req, &result).unwrap();
}

#[test]
fn concurrent_identical_replies_remain_bound_to_their_own_view_and_slot() {
    let f = Fixture::new();
    let p = Producer::new(context()).unwrap();
    let result = response(1, "identical");
    let req_a = request(1, &f.commit);
    let req_b = request(1, &f.blob);
    let a = p.begin(f.snapshot(), &req_a).unwrap();
    let b = p.begin(f.snapshot(), &req_b).unwrap();
    let ca = p.complete(&a, &result).unwrap();
    let cb = p.complete(&b, &result).unwrap();
    assert_ne!(ca.invocation, cb.invocation);
    assert_ne!(ca.view_generation, cb.view_generation);
    assert_eq!(
        p.verify_local(&cb, &context(), &req_b, &result)
            .unwrap()
            .requested
            .kind,
        ObjectKind::Blob
    );
    assert_eq!(
        p.verify_local(&ca, &context(), &req_a, &result)
            .unwrap()
            .requested
            .kind,
        ObjectKind::Commit
    );
    assert!(p.verify_local(&ca, &context(), &req_a, &result).is_err());
}

#[test]
fn cancellation_expiry_invalid_result_and_withdrawal_do_not_poison_fresh_reads() {
    let f = Fixture::new();
    let p = Producer::new(context()).unwrap();
    let req = request(2, "HEAD");
    let result = response(2, "owned");
    let t = p.begin(f.snapshot(), &req).unwrap();
    p.cancel(&t).unwrap();
    assert!(p.complete(&t, &result).is_err());
    let t = p.begin(f.snapshot(), &req).unwrap();
    p.calls.lock().unwrap().get_mut(&t.0).unwrap().started = Instant::now() - LOCAL_LIFETIME;
    assert!(p.complete(&t, &result).is_err());
    let t = p.begin(f.snapshot(), &req).unwrap();
    assert!(p.complete(&t, &response(3, "wrong id")).is_err());
    let t = p.begin(f.snapshot(), &req).unwrap();
    let error = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[],\"isError\":true}}\n";
    assert!(p.complete(&t, error).is_err());
    let snapshot = f.snapshot();
    let t = p.begin(snapshot.clone(), &req).unwrap();
    let claim = p.complete(&t, &result).unwrap();
    match &snapshot.source {
        Source::Memory(live) => live.store(false, Ordering::SeqCst),
        #[cfg(target_os = "linux")]
        Source::Native(_) => panic!("expected owned memory fixture"),
    }
    assert!(p.verify_local(&claim, &context(), &req, &result).is_err());
    assert!(p.begin(snapshot, &req).is_err());
    let t = p.begin(f.snapshot(), &req).unwrap();
    let c = p.complete(&t, &result).unwrap();
    p.verify_local(&c, &context(), &req, &result).unwrap();
}

#[test]
fn pending_budget_and_wire_bounds_do_not_expand_other_contracts() {
    let f = Fixture::new();
    let p = Producer::new(context()).unwrap();
    let req = request(1, "HEAD");
    let tickets: Vec<_> = (0..MAX_PENDING)
        .map(|_| p.begin(f.snapshot(), &req).unwrap())
        .collect();
    assert!(p.begin(f.snapshot(), &req).is_err());
    p.cancel(&tickets[0]).unwrap();
    p.begin(f.snapshot(), &req).unwrap();
    assert!(frame(&vec![b' '; MAX_REQUEST_BYTES + 1], MAX_REQUEST_BYTES).is_err());
    assert!(frame(b"{\"jsonrpc\":\"2.0\",\"id\":null}\n", MAX_REQUEST_BYTES).is_err());
    assert!(frame(b"{\"jsonrpc\":\"2.0\",\"id\":1}\n{}\n", MAX_REQUEST_BYTES).is_err());
    let mut missing = context();
    missing.process_generation = [0; 32];
    assert!(Producer::new(missing).is_err());
}

#[test]
fn parallel_local_calls_with_identical_ids_and_result_bytes_remain_isolated() {
    let f = Fixture::new();
    let p = Producer::new(context()).unwrap();
    let s = f.snapshot();
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for n in 0..8 {
            let revision = if n % 2 == 0 {
                f.commit.clone()
            } else {
                f.blob.clone()
            };
            let p = &p;
            let barrier = &barrier;
            let s = s.clone();
            handles.push(scope.spawn(move || {
                let req = request(1, &revision);
                let result = response(1, "identical");
                let t = p.begin(s, &req).unwrap();
                barrier.wait();
                let c = p.complete(&t, &result).unwrap();
                assert_eq!(
                    p.verify_local(&c, &context(), &req, &result)
                        .unwrap()
                        .requested
                        .oid,
                    revision
                );
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    });
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn native_same_sealed_view_withdraws_after_ref_or_object_rename_even_if_restored() {
    for object_change in [false, true] {
        let (data, images, raw) = original_images();
        let root = tempfile::tempdir().unwrap();
        for path in [".git/objects/info", ".git/objects/pack", ".git/refs/tags"] {
            std::fs::create_dir_all(root.path().join(path)).unwrap();
        }
        for (path, bytes) in images {
            let file = root.path().join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, bytes).unwrap();
        }
        let workspace = std::fs::File::open(root.path()).unwrap();
        let snapshot = Snapshot::capture(&workspace, &context().profile_format).unwrap();
        let req = request(10, "HEAD");
        let p = Producer::new(context()).unwrap();
        let t = p.begin(snapshot.clone(), &req).unwrap();
        let c = p.complete(&t, &raw).unwrap();
        let mut command = tokio::process::Command::new("/owned-component-mount-plan-not-executed");
        let mut pins = Vec::new();
        snapshot.mount(&mut command, &mut pins).unwrap();
        let args: Vec<_> = command
            .as_std()
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|s| s == "--ro-bind-data"));
        assert!(!args.iter().any(|s| s == "--ro-bind-fd"));
        let path = if object_change {
            let oid = data["commit_oid"].as_str().unwrap();
            root.path()
                .join(format!(".git/objects/{}/{}", &oid[..2], &oid[2..]))
        } else {
            root.path().join(".git/refs/heads/main")
        };
        let before = std::fs::read(&path).unwrap();
        let moved = path.with_extension("owned-moved");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::rename(&moved, &path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(p.verify_local(&c, &context(), &req, &raw).is_err());
        assert!(snapshot.mount(&mut command, &mut pins).is_err());
        drop(p);
        drop(snapshot);
        drop(pins);
        let fresh = Snapshot::capture(&workspace, &context().profile_format).unwrap();
        let p = Producer::new(context()).unwrap();
        let t = p.begin(fresh, &req).unwrap();
        let c = p.complete(&t, &raw).unwrap();
        assert_eq!(
            p.verify_local(&c, &context(), &req, &raw)
                .unwrap()
                .requested
                .kind,
            ObjectKind::Commit
        );
    }
}

#[test]
fn ambiguous_wire_keys_never_create_or_complete_a_witness() {
    let f = Fixture::new();
    let p = Producer::new(context()).unwrap();
    let req = request(1, "HEAD");
    let bad = String::from_utf8(req.clone())
        .unwrap()
        .replace("\"id\":1", "\"id\":9,\"id\":1");
    assert!(p.begin(f.snapshot(), bad.as_bytes()).is_err());
    let ticket = p.begin(f.snapshot(), &req).unwrap();
    let result = response(1, "owned");
    let bad = String::from_utf8(result)
        .unwrap()
        .replace("\"id\":1", "\"id\":9,\"id\":1");
    assert!(p.complete(&ticket, bad.as_bytes()).is_err());
    assert!(
        p.complete(&ticket, &response(1, "owned")).is_err(),
        "ambiguous completion spends slot"
    );
}
