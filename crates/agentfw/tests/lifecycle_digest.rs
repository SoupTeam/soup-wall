// SPDX-License-Identifier: Apache-2.0
use agentfw::lifecycle::sha256_file;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::Instant;

// The previous streaming implementation is retained only as an independent
// compatibility oracle and a timing control on the exact built executable.
fn reference_digest(path: &Path) -> String {
    let mut file = File::open(path).unwrap();
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    format!("{:x}", hasher.finalize())
}

#[test]
fn file_digest_preserves_vectors_chunk_boundaries_and_detects_edits() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("candidate");
    for (bytes, expected) in [
        (
            b"".as_slice(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".as_slice(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ] {
        fs::write(&path, bytes).unwrap();
        assert_eq!(sha256_file(&path).unwrap(), expected);
    }
    for length in [55, 56, 63, 64, 65, 65535, 65536, 65537, 131073] {
        let mut bytes: Vec<u8> = (0..length).map(|n| (n % 251) as u8).collect();
        fs::write(&path, &bytes).unwrap();
        let before = sha256_file(&path).unwrap();
        assert_eq!(before, reference_digest(&path));
        bytes[length / 2] ^= 1;
        fs::write(&path, &bytes).unwrap();
        let after = sha256_file(&path).unwrap();
        assert_eq!(after, reference_digest(&path));
        assert_ne!(before, after, "same-length edits must invalidate identity");
    }
    fs::remove_file(&path).unwrap();
    assert!(sha256_file(&path).is_err());
}

#[test]
fn file_digest_matches_reference_for_actual_agent_executable() {
    let path = Path::new(env!("CARGO_BIN_EXE_agentfw"));
    let started = Instant::now();
    let reference = reference_digest(path);
    let reference_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let actual = sha256_file(path).unwrap();
    let native_ms = started.elapsed().as_millis();
    assert_eq!(actual, reference);
    // Timings are evidence, not a machine-dependent performance assertion.
    // The real launchd acceptance still enforces its unchanged 35-second limit.
    eprintln!(
        "lifecycle file digest: bytes={} reference_ms={reference_ms} native_ms={native_ms} sha256={actual}",
        fs::metadata(path).unwrap().len()
    );
}
