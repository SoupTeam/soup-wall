// SPDX-License-Identifier: Apache-2.0
//! Data proofs for the opt-in local-reference view, never cached permission.
//! No Git executable, repository helper or revision expansion runs here.

#[cfg(any(target_os = "linux", test))]
use std::{collections::BTreeMap, io::Read};

#[cfg(any(target_os = "linux", test))]
use anyhow::{ensure, Context};

#[cfg(any(target_os = "linux", test))]
pub(super) const MAX_REFS: usize = 64;
#[cfg(any(target_os = "linux", test))]
pub(super) const MAX_OBJECT_BYTES: usize = 262_144;
#[cfg(target_os = "linux")]
pub(super) const MAX_TAG_DEPTH: usize = 8;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::View;

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub(crate) struct View;
#[cfg(not(target_os = "linux"))]
impl View {
    pub(crate) fn validate_call(
        &self,
        _tool: &str,
        _args: &serde_json::Value,
    ) -> anyhow::Result<()> {
        anyhow::bail!("Git local-reference views require native Linux")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
pub(super) enum Object {
    Commit,
    Tag { target: String, target_is_tag: bool },
    Unsupported,
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn oid(value: &str) -> anyhow::Result<String> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "Git local reference requires a complete lowercase SHA-1"
    );
    Ok(value.to_owned())
}

/// Strictly bounded loose-object decoding. The original server still performs
/// the requested operation on its original arguments and returns original bytes.
#[cfg(any(target_os = "linux", test))]
pub(super) fn decode_object(expected: &str, compressed: &[u8]) -> anyhow::Result<Object> {
    oid(expected)?;
    ensure!(
        compressed.len() <= MAX_OBJECT_BYTES,
        "Git object exceeds limit"
    );
    let mut bytes = Vec::new();
    flate2::read::ZlibDecoder::new(compressed)
        .take(MAX_OBJECT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_OBJECT_BYTES,
        "Git object inflation exceeds limit"
    );
    ensure!(
        sha1_smol::Sha1::from(&bytes).digest().to_string() == expected,
        "Git local reference object identity mismatch"
    );
    let separator = bytes
        .iter()
        .position(|c| *c == 0)
        .context("Git object header missing")?;
    let header = std::str::from_utf8(&bytes[..separator])?;
    let (kind, size) = header
        .split_once(' ')
        .context("Git object header invalid")?;
    ensure!(
        !size.is_empty() && size.bytes().all(|c| c.is_ascii_digit()),
        "Git object size invalid"
    );
    let payload = &bytes[separator + 1..];
    ensure!(
        size.parse::<usize>()? == payload.len(),
        "Git object size mismatch"
    );
    let mut lines = payload.split(|c| *c == b'\n');
    match kind {
        "commit" => {
            let tree = std::str::from_utf8(lines.next().context("Git commit tree missing")?)?;
            oid(tree
                .strip_prefix("tree ")
                .context("Git commit tree invalid")?)?;
            Ok(Object::Commit)
        }
        "tag" => {
            let target = std::str::from_utf8(lines.next().context("Git tag target missing")?)?;
            let target = oid(target
                .strip_prefix("object ")
                .context("Git tag target invalid")?)?;
            let kind = lines.next().context("Git tag type missing")?;
            match kind {
                b"type commit" => Ok(Object::Tag {
                    target,
                    target_is_tag: false,
                }),
                b"type tag" => Ok(Object::Tag {
                    target,
                    target_is_tag: true,
                }),
                _ => Ok(Object::Unsupported),
            }
        }
        _ => Ok(Object::Unsupported),
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default)]
pub(super) struct PackedReferences {
    pub refs: BTreeMap<String, String>,
    pub peels: BTreeMap<String, String>,
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn packed_references(bytes: &[u8]) -> anyhow::Result<PackedReferences> {
    ensure!(bytes.len() <= 65_536, "Git packed references exceed limit");
    ensure!(
        (bytes.is_empty() || bytes.ends_with(b"\n"))
            && !bytes.contains(&b'\r')
            && !bytes.contains(&0),
        "Git packed reference framing unsupported"
    );
    let mut packed = PackedReferences::default();
    let mut can_peel: Option<String> = None;
    for line in std::str::from_utf8(bytes)?.lines() {
        if line.starts_with('#') {
            ensure!(
                line.starts_with("# pack-refs with:"),
                "Git packed reference header unsupported"
            );
            continue;
        }
        if let Some(peeled) = line.strip_prefix('^') {
            let name = can_peel
                .take()
                .context("Git packed reference peel is unbound")?;
            ensure!(
                name.starts_with("refs/tags/"),
                "Git branch peel unsupported"
            );
            packed.peels.insert(name, oid(peeled)?);
            continue;
        }
        let (target, name) = line
            .split_once(' ')
            .context("Git packed reference invalid")?;
        ensure!(
            super::is_local_reference(name),
            "Git packed namespace unsupported"
        );
        ensure!(
            packed.refs.insert(name.to_owned(), oid(target)?).is_none(),
            "duplicate Git packed reference"
        );
        ensure!(
            packed.refs.len() <= MAX_REFS,
            "Git local reference count exceeds limit"
        );
        can_peel = Some(name.to_owned());
    }
    Ok(packed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn object(kind: &str, payload: &[u8]) -> (String, Vec<u8>) {
        let mut raw = format!("{kind} {}\0", payload.len()).into_bytes();
        raw.extend_from_slice(payload);
        let oid = sha1_smol::Sha1::from(&raw).digest().to_string();
        let mut compressor =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        compressor.write_all(&raw).unwrap();
        (oid, compressor.finish().unwrap())
    }

    #[test]
    fn objects_are_typed_hashed_and_bounded_without_git_execution() {
        let (commit, compressed) = object(
            "commit",
            format!("tree {}\n\nOwned.\n", "a".repeat(40)).as_bytes(),
        );
        assert_eq!(decode_object(&commit, &compressed).unwrap(), Object::Commit);
        assert!(decode_object(&"b".repeat(40), &compressed).is_err());
        let (tag, compressed) = object(
            "tag",
            format!("object {commit}\ntype commit\ntag owned\n\nOwned.\n").as_bytes(),
        );
        assert_eq!(
            decode_object(&tag, &compressed).unwrap(),
            Object::Tag {
                target: commit,
                target_is_tag: false
            }
        );
        for kind in ["blob", "tree"] {
            let (id, compressed) = object(kind, b"Owned.");
            assert_eq!(
                decode_object(&id, &compressed).unwrap(),
                Object::Unsupported
            );
        }
        let (id, compressed) = object("blob", &vec![b'x'; MAX_OBJECT_BYTES + 1]);
        assert!(decode_object(&id, &compressed).is_err());
    }

    #[test]
    fn packed_references_reject_expansions_duplicates_and_unbound_peels() {
        let id = "a".repeat(40);
        assert_eq!(
            packed_references(
                format!("# pack-refs with: peeled sorted\n{id} refs/tags/owned\n^{id}\n")
                    .as_bytes()
            )
            .unwrap()
            .refs["refs/tags/owned"],
            id
        );
        for invalid in [
            format!("^{id}\n"),
            format!("{id} refs/heads/main\n^{id}\n"),
            format!("{id} refs/tags/owned\n^{id}\n^{id}\n"),
            format!("{id} refs/remotes/origin/main\n"),
            format!("{id} refs/heads/a~1\n"),
            format!("{id} refs/heads/main\r\n"),
            format!("{id} refs/heads/main"),
            format!("{id} refs/heads/a\n{id} refs/heads/a\n"),
        ] {
            assert!(packed_references(invalid.as_bytes()).is_err(), "{invalid}");
        }
    }
}
