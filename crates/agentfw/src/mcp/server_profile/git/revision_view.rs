// SPDX-License-Identifier: Apache-2.0
//! Data proofs for the opt-in file-revision view, never cached permission.
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
        anyhow::bail!("Git file-revision views require native Linux")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
pub(super) enum Object {
    Commit { tree: String },
    Tree(BTreeMap<Vec<u8>, (String, String)>),
    Blob,
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
        "Git file revision requires a complete lowercase SHA-1"
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
        "Git file revision object identity mismatch"
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
            let tree = oid(tree
                .strip_prefix("tree ")
                .context("Git commit tree invalid")?)?;
            Ok(Object::Commit { tree })
        }
        "blob" => Ok(Object::Blob),
        "tree" => {
            let mut entries = BTreeMap::new();
            let mut tail = payload;
            while !tail.is_empty() {
                ensure!(entries.len() < 1024, "Git tree entry limit");
                let end = tail
                    .iter()
                    .position(|b| *b == 0)
                    .context("Git tree framing invalid")?;
                let split = tail[..end]
                    .iter()
                    .position(|b| *b == b' ')
                    .context("Git tree entry invalid")?;
                let (mode, name) = (&tail[..split], &tail[split + 1..end]);
                ensure!(
                    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/'),
                    "Git tree name invalid"
                );
                ensure!(tail.len() >= end + 21, "Git tree object ID truncated");
                let target: String = tail[end + 1..end + 21]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let mode = std::str::from_utf8(mode)?;
                ensure!(
                    matches!(mode, "40000" | "100644" | "100755" | "120000" | "160000"),
                    "Git tree mode unsupported"
                );
                ensure!(
                    entries
                        .insert(name.to_vec(), (mode.to_owned(), target))
                        .is_none(),
                    "Git tree name duplicated"
                );
                tail = &tail[end + 21..];
            }
            Ok(Object::Tree(entries))
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
            is_metadata_reference(name),
            "Git packed namespace unsupported"
        );
        ensure!(
            packed.refs.insert(name.to_owned(), oid(target)?).is_none(),
            "duplicate Git packed reference"
        );
        ensure!(
            packed.refs.len() <= MAX_REFS,
            "Git file revision count exceeds limit"
        );
        can_peel = Some(name.to_owned());
    }
    Ok(packed)
}

/// Metadata names resolve HEAD only. This does not enable a named-reference call.
#[cfg(any(target_os = "linux", test))]
fn is_metadata_reference(reference: &str) -> bool {
    let Some(name) = reference
        .strip_prefix("refs/heads/")
        .or_else(|| reference.strip_prefix("refs/tags/"))
    else {
        return false;
    };
    reference.len() <= 255
        && !name.is_empty()
        && name.split('/').count() <= 8
        && !name.contains("..")
        && !name.contains("@{")
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '/' | '-' | '_' | '.' | '@' | '+')
                || literal_unicode(c)
        })
        && name.split('/').all(|p| {
            !p.is_empty()
                && !p.starts_with(['.', '-'])
                && !p.ends_with('.')
                && !p.ends_with(".lock")
        })
}

fn literal_unicode(c: char) -> bool {
    let n = c as u32;
    n >= 0xa1
        && !matches!(n, 0x1680 | 0x180e | 0x2000..=0x200f | 0x2028..=0x202f
        | 0x205f..=0x206f | 0x3000 | 0xfeff | 0xe0000..=0xe0fff)
}

/// A literal revision and normalized relative path; no Git revision expansion.
pub(super) fn file_revision(value: &str) -> Option<(&str, &str)> {
    let (revision, path) = value.split_once(':')?;
    if !(revision == "HEAD"
        || (revision.len() == 40 && revision.bytes().all(|b| b.is_ascii_hexdigit())))
        || path.is_empty()
        || path.len() > 1024
        || path.split('/').count() > 16
        || !path.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '/' | '.' | '_' | ' ' | '-')
                || literal_unicode(c)
        })
        || !path.split('/').all(|p| {
            !p.is_empty()
                && p.len() <= 255
                && !matches!(p, "." | "..")
                && !p.starts_with('-')
                && ![".git", ".gitmodules", ".gitattributes"]
                    .contains(&p.to_ascii_lowercase().as_str())
        })
    {
        return None;
    }
    Some((revision, path))
}

#[cfg(any(target_os = "linux", test))]
fn validate_path(
    objects: &BTreeMap<String, Object>,
    commit: &str,
    path: &str,
) -> anyhow::Result<()> {
    let Some(Object::Commit { tree }) = objects.get(commit) else {
        anyhow::bail!("Git file revision is not an available local commit");
    };
    let mut current = tree.as_str();
    let parts: Vec<_> = path.split('/').collect();
    ensure!(parts.len() <= 16, "Git file tree depth limit");
    for (index, part) in parts.iter().enumerate() {
        let Some(Object::Tree(entries)) = objects.get(current) else {
            anyhow::bail!("Git file tree unavailable or unsupported");
        };
        let (mode, target) = entries
            .get(part.as_bytes())
            .context("Git revision path absent")?;
        if index + 1 == parts.len() {
            ensure!(
                matches!(mode.as_str(), "100644" | "100755")
                    && objects.get(target) == Some(&Object::Blob),
                "Git revision path is not a regular local blob"
            );
        } else {
            ensure!(
                mode == "40000",
                "Git revision path traverses a non-tree object"
            );
            current = target;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    fn object(kind: &str, payload: &[u8]) -> (String, Vec<u8>) {
        let mut raw = format!("{kind} {}\0", payload.len()).into_bytes();
        raw.extend_from_slice(payload);
        let id = sha1_smol::Sha1::from(&raw).digest().to_string();
        let mut compressed =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        compressed.write_all(&raw).unwrap();
        (id, compressed.finish().unwrap())
    }

    #[test]
    fn selected_file_grammar_preserves_v1_and_rejects_combinations() {
        let selected = super::super::classify_manifest_with_extension(
            &super::super::original_manifest(),
            super::super::ReadExtension::FileRevisions,
        )
        .unwrap();
        let original = super::super::classify_manifest(&super::super::original_manifest()).unwrap();
        for value in [
            "HEAD:notes.txt".to_owned(),
            "HEAD:docs/機能 notes.txt".to_owned(),
            format!("{}:dir/café.txt", "a".repeat(40)),
        ] {
            let args = json!({"repo_path":"/workspace","revision":value});
            assert!(selected["git_show"].validate_arguments(&args).is_ok());
            assert!(original["git_show"].validate_arguments(&args).is_err());
            assert!(selected["git_diff"]
                .validate_arguments(&json!({"repo_path":"/workspace","target":value}))
                .is_err());
        }
        for value in [
            "HEAD:",
            "HEAD:/etc/passwd",
            "HEAD:../outside",
            "HEAD:./notes.txt",
            "HEAD:a//b",
            "HEAD:a/../b",
            "HEAD:a\\b",
            "HEAD:a:b",
            "HEAD:.git/config",
            "HEAD:dir/.GIT/HEAD",
            "HEAD:.gitattributes",
            "HEAD:-x",
            "HEAD:dir/-x",
            "HEAD:a\0b",
            "HEAD:a\nb",
            "HEAD:a\u{202e}b",
            "HEAD~1:notes.txt",
            "HEAD@{0}:notes.txt",
            ":notes.txt",
            ":/message",
            "refs/heads/main:notes.txt",
            "refs/heads/main",
            "HEAD:a*",
            "HEAD:a?",
            "HEAD:a[b",
            "--help:notes.txt",
        ] {
            assert!(file_revision(value).is_none(), "{value:?}");
        }
        assert!(file_revision(&format!("HEAD:{}", "x".repeat(256))).is_none());
        assert!(file_revision(&format!("HEAD:{}", ["x"; 17].join("/"))).is_none());
        assert!(file_revision(&format!("HEAD:{}", vec!["x".repeat(100); 11].join("/"))).is_none());
        for format in [
            "sw-mcp/git-readonly-file-revisions-local-refs/1",
            "sw-mcp/git-readonly-shallow-file-revisions/1",
        ] {
            assert!(!super::super::is_profile(format));
        }
    }

    #[test]
    fn file_proofs_require_commit_tree_regular_blob_and_exact_path() {
        let blob = "b".repeat(40);
        let tree = "c".repeat(40);
        let commit = "a".repeat(40);
        let mut objects = BTreeMap::from([
            (commit.clone(), Object::Commit { tree: tree.clone() }),
            (
                tree.clone(),
                Object::Tree(BTreeMap::from([(
                    "café notes.txt".as_bytes().to_vec(),
                    ("100644".into(), blob.clone()),
                )])),
            ),
            (blob.clone(), Object::Blob),
        ]);
        assert!(validate_path(&objects, &commit, "café notes.txt").is_ok());
        assert!(validate_path(&objects, &blob, "café notes.txt").is_err());
        assert!(validate_path(&objects, &commit, "absent").is_err());
        assert!(validate_path(&objects, &commit, "café notes.txt/child").is_err());
        for mode in ["120000", "160000", "40000"] {
            objects.insert(
                tree.clone(),
                Object::Tree(BTreeMap::from([(
                    "café notes.txt".as_bytes().to_vec(),
                    (mode.into(), blob.clone()),
                )])),
            );
            assert!(validate_path(&objects, &commit, "café notes.txt").is_err());
        }
        objects.insert(
            tree.clone(),
            Object::Tree(BTreeMap::from([(
                "café notes.txt".as_bytes().to_vec(),
                ("100644".into(), blob.clone()),
            )])),
        );
        objects.remove(&blob);
        assert!(validate_path(&objects, &commit, "café notes.txt").is_err());
    }

    #[test]
    fn packed_metadata_is_bounded_and_never_enables_named_arguments() {
        let id = "a".repeat(40);
        let bytes = format!("{id} refs/heads/main\n");
        assert_eq!(
            packed_references(bytes.as_bytes()).unwrap().refs["refs/heads/main"],
            id
        );
        assert!(packed_references(format!("{bytes}{bytes}").as_bytes()).is_err());
        assert!(packed_references(format!("{id} refs/remotes/origin/main\n").as_bytes()).is_err());
        assert!(packed_references(b"^unbound\n").is_err());
        assert!(!is_metadata_reference("refs/heads/a..b"));
        assert!(file_revision("refs/heads/main:notes.txt").is_none());
    }

    #[test]
    fn loose_objects_require_hash_type_framing_and_bounded_inflation() {
        let (id, compressed) = object("blob", b"owned bytes");
        assert_eq!(decode_object(&id, &compressed).unwrap(), Object::Blob);
        assert!(decode_object(&"a".repeat(40), &compressed).is_err());
        let (id, compressed) = object("blob", &vec![b'x'; MAX_OBJECT_BYTES + 1]);
        assert!(decode_object(&id, &compressed).is_err());
        for raw in [
            b"100644 file\0short".as_slice(),
            b"100644 ../escape\0aaaaaaaaaaaaaaaaaaaa",
            b"garbage file\0aaaaaaaaaaaaaaaaaaaa",
            b"100644 file\0aaaaaaaaaaaaaaaaaaaa100644 file\0bbbbbbbbbbbbbbbbbbbb",
        ] {
            let (id, compressed) = object("tree", raw);
            assert!(decode_object(&id, &compressed).is_err());
        }
    }
}
