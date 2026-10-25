// SPDX-License-Identifier: Apache-2.0
//! Data proofs for the opt-in shallow view, never cached permission.
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
        anyhow::bail!("Git shallow views require native Linux")
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
        "Git shallow repository requires a complete lowercase SHA-1"
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
        "Git shallow repository object identity mismatch"
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
            is_metadata_reference(name),
            "Git packed namespace unsupported"
        );
        ensure!(
            packed.refs.insert(name.to_owned(), oid(target)?).is_none(),
            "duplicate Git packed reference"
        );
        ensure!(
            packed.refs.len() <= MAX_REFS,
            "Git shallow repository count exceeds limit"
        );
        can_peel = Some(name.to_owned());
    }
    Ok(packed)
}

#[cfg(any(target_os = "linux", test))]
fn is_metadata_reference(reference: &str) -> bool {
    let Some(name) = reference
        .strip_prefix("refs/heads/")
        .or_else(|| reference.strip_prefix("refs/tags/"))
    else {
        return false;
    };
    reference.len() <= 255 && !name.is_empty() && name.split('/').count() <= 8
        && !name.contains("..") && !name.contains("@{")
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '@' | '+') || (c as u32 >= 0xa1 && !c.is_whitespace() && !matches!(c as u32, 0x180e | 0x2000..=0x200f | 0x2028..=0x202f | 0x205f..=0x206f | 0xfeff | 0xe0000..=0xe0fff)))
        && name.split('/').all(|p| !p.is_empty() && !p.starts_with(['.', '-']) && !p.ends_with('.') && !p.ends_with(".lock"))
}

#[cfg(any(target_os = "linux", test))]
fn boundaries(bytes: &[u8]) -> anyhow::Result<std::collections::BTreeSet<String>> {
    ensure!(
        !bytes.is_empty()
            && bytes.len() <= 64 * 41
            && bytes.ends_with(b"\n")
            && !bytes.contains(&b'\r')
            && !bytes.contains(&0),
        "Git shallow boundary framing or size unsupported"
    );
    let mut ids = std::collections::BTreeSet::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        ensure!(
            line.len() == 40 && ids.insert(oid(line)?),
            "Git shallow boundary duplicate or malformed"
        );
    }
    ensure!(ids.len() <= 64, "Git shallow boundary count limit");
    Ok(ids)
}

/// Validate the finite SHA-1 pack-v2/index-v2 envelope and non-delta metadata
/// objects. Delta records are explicitly unsupported in this finite profile;
/// no history or delta reconstruction is performed by Soup Wall.
/// https://git-scm.com/docs/gitformat-pack
#[cfg(any(target_os = "linux", test))]
fn packed_objects(pack: &[u8], index: &[u8]) -> anyhow::Result<BTreeMap<String, Object>> {
    fn u32_at(bytes: &[u8], offset: usize) -> anyhow::Result<u32> {
        let value: [u8; 4] = bytes
            .get(offset..offset + 4)
            .context("Git pack field truncated")?
            .try_into()?;
        Ok(u32::from_be_bytes(value))
    }
    fn digest(bytes: &[u8]) -> [u8; 20] {
        sha1_smol::Sha1::from(bytes).digest().bytes()
    }
    ensure!(
        pack.len() >= 32
            && pack.len() <= 16 * 1024 * 1024
            && index.len() >= 1072
            && index.len() <= 1072 + 128 * 28,
        "Git pack/index size unsupported"
    );
    ensure!(
        &pack[..4] == b"PACK"
            && u32_at(pack, 4)? == 2
            && &index[..4] == b"\xfftOc"
            && u32_at(index, 4)? == 2,
        "Git pack/index format unsupported"
    );
    let count = u32_at(pack, 8)? as usize;
    ensure!(
        count > 0
            && count <= 128
            && index.len() == 1072 + count * 28
            && u32_at(index, 1028)? as usize == count,
        "Git pack/index count mismatch"
    );
    let pack_end = pack.len() - 20;
    ensure!(
        digest(&pack[..pack_end]) == pack[pack_end..]
            && index[index.len() - 40..index.len() - 20] == pack[pack_end..]
            && digest(&index[..index.len() - 20]) == index[index.len() - 20..],
        "Git pack/index checksum mismatch"
    );
    let names = &index[1032..1032 + 20 * count];
    let mut previous: Option<&[u8]> = None;
    let mut offsets = BTreeMap::new();
    for i in 0..count {
        let id = &names[20 * i..20 * (i + 1)];
        ensure!(
            previous.is_none_or(|p| p < id),
            "Git pack object names duplicated or unsorted"
        );
        previous = Some(id);
        let offset = u32_at(index, 1032 + 24 * count + 4 * i)? as usize;
        ensure!(
            (12..pack_end).contains(&offset) && offsets.insert(offset, (id, i)).is_none(),
            "Git pack offset unsupported or duplicated"
        );
    }
    for n in 0..256 {
        let actual = names
            .as_chunks::<20>()
            .0
            .iter()
            .filter(|id| id[0] as usize <= n)
            .count();
        ensure!(
            u32_at(index, 8 + 4 * n)? as usize == actual,
            "Git index fanout mismatch"
        );
    }
    let rows: Vec<_> = offsets.into_iter().collect();
    ensure!(
        rows.first().is_some_and(|r| r.0 == 12),
        "Git pack first offset invalid"
    );
    let mut objects = BTreeMap::new();
    for (i, (offset, (id, position))) in rows.iter().enumerate() {
        let end = rows.get(i + 1).map_or(pack_end, |row| row.0);
        let record = &pack[*offset..end];
        let mut crc = flate2::Crc::new();
        crc.update(record);
        ensure!(
            crc.sum() == u32_at(index, 1032 + 20 * count + 4 * position)?,
            "Git packed object CRC mismatch"
        );
        let first = record[0];
        let kind = (first >> 4) & 7;
        ensure!(matches!(kind, 1..=4), "Git packed object type unsupported");
        let mut size = (first & 15) as usize;
        let mut cursor = 1;
        let mut shift = 4;
        let mut flag = first;
        while flag & 128 != 0 {
            ensure!(
                cursor < record.len() && shift <= 28,
                "Git packed object header invalid"
            );
            flag = record[cursor];
            cursor += 1;
            size |= ((flag & 127) as usize) << shift;
            shift += 7;
        }
        ensure!(size <= MAX_OBJECT_BYTES, "Git packed object exceeds limit");
        let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let object = if matches!(kind, 1..=4) {
            let mut decoded = Vec::new();
            let mut decoder = flate2::read::ZlibDecoder::new(&record[cursor..]);
            (&mut decoder)
                .take(MAX_OBJECT_BYTES as u64 + 1)
                .read_to_end(&mut decoded)?;
            ensure!(
                decoded.len() == size && decoder.total_in() as usize == record.len() - cursor,
                "Git packed object inflation/framing mismatch"
            );
            let kind = match kind {
                1 => "commit",
                2 => "tree",
                3 => "blob",
                4 => "tag",
                _ => unreachable!(),
            };
            let mut raw = format!("{kind} {size}\0").into_bytes();
            raw.extend_from_slice(&decoded);
            ensure!(
                sha1_smol::Sha1::from(&raw).digest().to_string() == id,
                "Git packed object identity mismatch"
            );
            // Reuse the exact loose-object metadata parser after recompression.
            use std::io::Write;
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(&raw)?;
            decode_object(&id, &encoder.finish()?)?
        } else {
            Object::Unsupported
        };
        objects.insert(id, object);
    }
    Ok(objects)
}

#[cfg(any(target_os = "linux", test))]
fn reverse_index(bytes: &[u8], pack: &[u8], index: &[u8]) -> anyhow::Result<()> {
    let read =
        |s: &[u8]| -> u32 { u32::from_be_bytes(s.try_into().expect("bounded four-byte field")) };
    ensure!(
        bytes.len() >= 52 && pack.len() >= 32 && index.len() >= 1072,
        "Git reverse index truncated"
    );
    let count = read(&index[1028..1032]) as usize;
    ensure!(
        count <= 128
            && index.len() == 1072 + 28 * count
            && bytes.len() == 52 + 4 * count
            && &bytes[..4] == b"RIDX"
            && read(&bytes[4..8]) == 1
            && read(&bytes[8..12]) == 1,
        "Git reverse index format unsupported"
    );
    ensure!(
        bytes[bytes.len() - 40..bytes.len() - 20] == pack[pack.len() - 20..]
            && sha1_smol::Sha1::from(&bytes[..bytes.len() - 20])
                .digest()
                .bytes()
                == bytes[bytes.len() - 20..],
        "Git reverse index checksum mismatch"
    );
    let mut seen = std::collections::BTreeSet::new();
    let mut previous = 0;
    for row in bytes[12..12 + 4 * count].as_chunks::<4>().0.iter() {
        let position = read(row) as usize;
        ensure!(
            position < count && seen.insert(position),
            "Git reverse index position invalid"
        );
        let offset =
            read(&index[1032 + 24 * count + 4 * position..1036 + 24 * count + 4 * position]);
        ensure!(offset > previous, "Git reverse index order invalid");
        previous = offset;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn pack_fixture() -> (String, Vec<u8>, Vec<u8>, Vec<u8>) {
        let payload = format!("tree {}\n\nOwned.\n", "a".repeat(40));
        let raw = format!("commit {}\0{payload}", payload.len());
        let id = sha1_smol::Sha1::from(raw.as_bytes()).digest();
        let mut record = Vec::new();
        let mut size = payload.len();
        let first = 0x10 | (size as u8 & 15);
        size >>= 4;
        record.push(first | if size > 0 { 128 } else { 0 });
        while size > 0 {
            let byte = size as u8 & 127;
            size >>= 7;
            record.push(byte | if size > 0 { 128 } else { 0 });
        }
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(payload.as_bytes()).unwrap();
        record.extend(encoder.finish().unwrap());
        let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
        pack.extend(&record);
        let checksum = sha1_smol::Sha1::from(&pack).digest().bytes();
        pack.extend(checksum);
        let mut index = b"\xfftOc\0\0\0\x02".to_vec();
        for i in 0..256 {
            index.extend(u32::to_be_bytes(u32::from(i >= id.bytes()[0] as usize)));
        }
        index.extend(id.bytes());
        let mut crc = flate2::Crc::new();
        crc.update(&record);
        index.extend(crc.sum().to_be_bytes());
        index.extend(12u32.to_be_bytes());
        index.extend(checksum);
        index.extend(sha1_smol::Sha1::from(&index).digest().bytes());
        let mut reverse = b"RIDX\0\0\0\x01\0\0\0\x01\0\0\0\0".to_vec();
        reverse.extend(checksum);
        reverse.extend(sha1_smol::Sha1::from(&reverse).digest().bytes());
        (id.to_string(), pack, index, reverse)
    }

    #[test]
    fn shallow_records_are_finite_exact_unique_lowercase_lines() {
        let id = "a".repeat(40);
        assert_eq!(boundaries(format!("{id}\n").as_bytes()).unwrap().len(), 1);
        for invalid in [
            String::new(),
            id.clone(),
            format!("{id}\r\n"),
            format!("{id}\n{id}\n"),
            format!("{}\n", "A".repeat(40)),
            format!("{id}\n\n"),
            format!("{id}\0\n"),
        ] {
            assert!(boundaries(invalid.as_bytes()).is_err(), "{invalid:?}");
        }
        assert!(boundaries(format!("{}\n", "a".repeat(41)).as_bytes()).is_err());
        assert!(boundaries(&vec![b'a'; 64 * 41 + 1]).is_err());
    }

    #[test]
    fn pack_index_and_reverse_index_require_matching_finite_identity() {
        let (id, pack, index, reverse) = pack_fixture();
        assert_eq!(packed_objects(&pack, &index).unwrap()[&id], Object::Commit);
        reverse_index(&reverse, &pack, &index).unwrap();
        for at in [0, 7, 11, 15, pack.len() - 1] {
            let mut bad = pack.clone();
            bad[at] ^= 1;
            assert!(packed_objects(&bad, &index).is_err());
        }
        for at in [0, 7, 1028, 1032, index.len() - 1] {
            let mut bad = index.clone();
            bad[at] ^= 1;
            assert!(packed_objects(&pack, &bad).is_err());
        }
        let mut bad = reverse;
        bad[12] = 1;
        assert!(reverse_index(&bad, &pack, &index).is_err());
        assert!(packed_objects(&pack, &index[..index.len() - 1]).is_err());
    }

    #[test]
    fn metadata_names_and_packed_refs_never_enable_revision_extensions() {
        let id = "a".repeat(40);
        assert_eq!(
            packed_references(format!("{id} refs/heads/main\n").as_bytes())
                .unwrap()
                .refs
                .len(),
            1
        );
        assert!(!is_metadata_reference("refs/remotes/origin/main"));
        assert!(packed_references(
            format!("{id} refs/heads/main\n{id} refs/heads/main\n").as_bytes()
        )
        .is_err());
        for value in ["HEAD:notes.txt", "refs/heads/main", "HEAD~1"] {
            assert!(super::super::validate_arguments(
                "git_show",
                &serde_json::json!({"repo_path":"/workspace","revision":value})
            )
            .is_err());
        }
        assert!(!super::super::is_profile(
            "sw-mcp/git-readonly-shallow-file-revisions/1"
        ));
    }
}
