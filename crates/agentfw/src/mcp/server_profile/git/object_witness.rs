// SPDX-License-Identifier: Apache-2.0
//! Local typed facts from a held sealed Git view. This module does NOT
//! authenticate a daemon/runtime/process or authorize any inspection relief.
//! SOU-155 owns that future integration; serialized claims are untrusted.

use anyhow::{ensure, Context};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(test)]
mod tests;

pub const FORMAT: &str = "sw-mcp/git-object-witness/1";
pub const PRODUCTION_AUTHENTICATION_ENABLED: bool = false;
const MAX_PENDING: usize = 8;
const LOCAL_LIFETIME: Duration = Duration::from_secs(30);
const MAX_OBJECT_BYTES: usize = 262_144;
const MAX_REQUEST_BYTES: usize = 65_536;
const MAX_RESULT_BYTES: usize = 1_048_576;
const MAX_OBJECTS: usize = 128;
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TAG_DEPTH: usize = 8;

fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FORMAT.as_bytes());
    h.update([0]);
    h.update((domain.len() as u64).to_be_bytes());
    h.update(domain);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}

fn oid(text: &str) -> anyhow::Result<String> {
    ensure!(
        text.len() == 40
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "object witness requires a full lowercase SHA-1"
    );
    Ok(text.to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Commit,
    Blob,
    Tree,
    Tag,
}

impl ObjectKind {
    fn parse(text: &str) -> anyhow::Result<Self> {
        Ok(match text {
            "commit" => Self::Commit,
            "blob" => Self::Blob,
            "tree" => Self::Tree,
            "tag" => Self::Tag,
            _ => anyhow::bail!("unsupported Git object kind"),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ObjectIdentity {
    pub oid: String,
    pub kind: ObjectKind,
}

#[derive(Clone, Debug)]
struct Object {
    identity: ObjectIdentity,
    tag: Option<(String, ObjectKind)>,
}

fn object(expected: &str, compressed: &[u8]) -> anyhow::Result<Object> {
    oid(expected)?;
    ensure!(
        compressed.len() <= MAX_OBJECT_BYTES,
        "compressed Git object bound"
    );
    let mut decoder = flate2::read::ZlibDecoder::new(compressed);
    let mut raw = Vec::new();
    (&mut decoder)
        .take(MAX_OBJECT_BYTES as u64 + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() <= MAX_OBJECT_BYTES && decoder.total_in() as usize == compressed.len(),
        "inflated Git object bound or trailing data"
    );
    ensure!(
        sha1_smol::Sha1::from(&raw).digest().to_string() == expected,
        "Git object OID mismatch"
    );
    let nul = raw
        .iter()
        .position(|b| *b == 0)
        .context("Git object header missing")?;
    let (kind, size) = std::str::from_utf8(&raw[..nul])?
        .split_once(' ')
        .context("Git object header invalid")?;
    ensure!(
        !size.is_empty() && size.bytes().all(|b| b.is_ascii_digit()),
        "Git object size invalid"
    );
    let payload = &raw[nul + 1..];
    ensure!(
        size.parse::<usize>()? == payload.len(),
        "Git object size mismatch"
    );
    let kind = ObjectKind::parse(kind)?;
    let mut lines = payload.split(|b| *b == b'\n');
    let tag = match kind {
        ObjectKind::Commit => {
            let tree = std::str::from_utf8(lines.next().context("commit tree missing")?)?;
            oid(tree.strip_prefix("tree ").context("commit tree invalid")?)?;
            None
        }
        ObjectKind::Tag => {
            let target = std::str::from_utf8(lines.next().context("tag object missing")?)?;
            let target = oid(target
                .strip_prefix("object ")
                .context("tag object invalid")?)?;
            let declared = std::str::from_utf8(lines.next().context("tag type missing")?)?;
            Some((
                target,
                ObjectKind::parse(declared.strip_prefix("type ").context("tag type invalid")?)?,
            ))
        }
        _ => None,
    };
    Ok(Object {
        identity: ObjectIdentity {
            oid: expected.to_owned(),
            kind,
        },
        tag,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ShowTarget {
    pub requested: ObjectIdentity,
    pub effective: ObjectIdentity,
    /// Includes every tag in order; the requested tag is never relabelled.
    pub tag_chain: Vec<ObjectIdentity>,
}

struct Repository {
    head: String,
    refs: BTreeMap<String, String>,
    objects: BTreeMap<String, Object>,
    digest: [u8; 32],
}

impl Repository {
    fn images(images: BTreeMap<String, Vec<u8>>) -> anyhow::Result<Self> {
        let mut manifest = Vec::new();
        let mut total = 0usize;
        let mut objects = BTreeMap::new();
        let mut refs = BTreeMap::new();
        if let Some(bytes) = images.get(".git/packed-refs") {
            refs = super::shallow_view::packed_references(bytes)?.refs;
        }
        for (path, bytes) in &images {
            total = total
                .checked_add(bytes.len())
                .context("Git image overflow")?;
            ensure!(total <= MAX_IMAGE_BYTES, "Git image byte bound");
            ensure!(
                !path.starts_with(".git/objects/pack/"),
                "packed object witness unsupported"
            );
            manifest.extend_from_slice(&(path.len() as u64).to_be_bytes());
            manifest.extend_from_slice(path.as_bytes());
            manifest.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            manifest.extend_from_slice(bytes);
            if let Some(name) = path.strip_prefix(".git/refs/") {
                let name = format!("refs/{name}");
                ensure!(
                    super::is_local_reference(&name),
                    "Git witness reference unsupported"
                );
                let id = std::str::from_utf8(bytes)?;
                let id = oid(id.strip_suffix('\n').unwrap_or(id))?;
                refs.insert(name, id);
                ensure!(refs.len() <= 64, "Git witness reference bound");
            }
            if let Some(name) = path.strip_prefix(".git/objects/") {
                let (prefix, suffix) = name.split_once('/').context("Git object image path")?;
                ensure!(
                    prefix.len() == 2 && suffix.len() == 38,
                    "Git object image path"
                );
                let id = format!("{prefix}{suffix}");
                ensure!(
                    objects.len() < MAX_OBJECTS
                        && objects.insert(id.clone(), object(&id, bytes)?).is_none(),
                    "Git witness object count or duplicate"
                );
            }
        }
        let head = std::str::from_utf8(
            images
                .get(".git/HEAD")
                .context("Git witness HEAD missing")?,
        )?;
        let head = head.strip_suffix('\n').unwrap_or(head);
        let head = if let Some(name) = head.strip_prefix("ref: ") {
            ensure!(
                name.starts_with("refs/heads/"),
                "Git witness HEAD reference unsupported"
            );
            refs.get(name)
                .context("Git witness HEAD target missing")?
                .clone()
        } else {
            oid(head)?
        };
        Ok(Self {
            head,
            refs,
            objects,
            digest: hash(b"sealed-git-image", &manifest),
        })
    }

    fn resolve(&self, revision: &str) -> anyhow::Result<ShowTarget> {
        let id = if revision == "HEAD" {
            self.head.clone()
        } else if super::is_local_reference(revision) {
            self.refs
                .get(revision)
                .context("Git witness reference missing")?
                .clone()
        } else {
            oid(&revision.to_ascii_lowercase())?
        };
        let mut current = self
            .objects
            .get(&id)
            .context("Git witness object missing")?;
        let requested = current.identity.clone();
        let mut chain = Vec::new();
        while let Some((id, declared)) = &current.tag {
            ensure!(chain.len() < MAX_TAG_DEPTH, "Git witness tag depth");
            chain.push(current.identity.clone());
            current = self
                .objects
                .get(id)
                .context("Git witness tag target missing")?;
            ensure!(
                current.identity.kind == *declared,
                "Git tag declared kind mismatch"
            );
        }
        // The original server calls repo.commit(revision) for any tag. A tag
        // ending at a blob/tree is an error, not a raw blob/tree show result.
        ensure!(
            chain.is_empty() || current.identity.kind == ObjectKind::Commit,
            "original git_show cannot format a tag to a non-commit"
        );
        Ok(ShowTarget {
            requested,
            effective: current.identity.clone(),
            tag_chain: chain,
        })
    }
}

enum Source {
    #[cfg(target_os = "linux")]
    Native(Arc<super::shallow_view::View>),
    #[cfg(test)]
    Memory(std::sync::atomic::AtomicBool),
}

/// A held sealed .git object/metadata image; not an immutable working tree.
/// It is not constructible from a serialized view digest or server claim.
pub struct Snapshot {
    source: Source,
    repository: Repository,
    generation: [u8; 32],
    profile: String,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl Snapshot {
    #[cfg(target_os = "linux")]
    pub fn capture(workspace: &std::fs::File, profile: &str) -> anyhow::Result<Arc<Self>> {
        linux::capture(workspace, profile)
    }

    /// Recheck sticky source withdrawal while the execution result is held.
    #[cfg(target_os = "linux")]
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        self.valid()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn show_target(&self, revision: &str) -> anyhow::Result<ShowTarget> {
        self.valid()?;
        let target = self.repository.resolve(revision)?;
        self.valid()?;
        Ok(target)
    }

    fn valid(&self) -> anyhow::Result<()> {
        match &self.source {
            #[cfg(target_os = "linux")]
            Source::Native(view) => view.object_witness_valid(),
            #[cfg(test)]
            Source::Memory(live) => {
                ensure!(
                    live.load(std::sync::atomic::Ordering::SeqCst),
                    "Git test snapshot withdrawn"
                );
                Ok(())
            }
        }
    }

    /// Only the trusted execution owner may consume these descriptors. This
    /// component has no launcher, daemon IPC, runtime authentication or relief.
    #[cfg(target_os = "linux")]
    pub fn mount(
        &self,
        command: &mut tokio::process::Command,
        pins: &mut Vec<std::fs::File>,
    ) -> anyhow::Result<()> {
        self.valid()?;
        match &self.source {
            Source::Native(view) => view.mount(command, pins),
            #[cfg(test)]
            Source::Memory(_) => anyhow::bail!("test memory view cannot be mounted"),
        }
    }
}

/// Proposed opaque identifiers from SOU-155's future trusted execution owner.
/// They are local correlation inputs here, never authenticated by this module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExecutionContext {
    pub profile_format: String,
    pub profile_sha256: [u8; 32],
    pub runtime_closure_sha256: [u8; 32],
    pub daemon_generation: [u8; 32],
    pub session_generation: [u8; 32],
    pub process_generation: [u8; 32],
}

impl ExecutionContext {
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            super::is_profile(&self.profile_format),
            "unsupported witness profile"
        );
        for id in [
            &self.profile_sha256,
            &self.runtime_closure_sha256,
            &self.daemon_generation,
            &self.session_generation,
            &self.process_generation,
        ] {
            ensure!(id.iter().any(|b| *b != 0), "missing local witness context");
        }
        Ok(())
    }
}

/// Local capability, deliberately not deserializable or a daemon authority.
#[derive(Clone)]
pub struct Ticket([u8; 32]);

/// Exportable diagnostic proposal; no deserialization-to-authority API exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Claim {
    format: &'static str,
    invocation: [u8; 32],
    context: ExecutionContext,
    schema_sha256: [u8; 32],
    view_sha256: [u8; 32],
    view_generation: [u8; 32],
    operation: &'static str,
    revision: String,
    target: ShowTarget,
    request_sha256: [u8; 32],
    result_sha256: [u8; 32],
    result_bytes: usize,
}

impl Claim {
    pub fn diagnostic_json(&self) -> anyhow::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= 8192, "local claim diagnostic bound");
        Ok(bytes)
    }
}

struct Pending {
    snapshot: Arc<Snapshot>,
    started: Instant,
    id: Value,
    revision: String,
    target: ShowTarget,
    request: [u8; 32],
    completed: Option<Claim>,
}

/// Private bounded local ledger, not a daemon/session/process authenticator.
pub struct Producer {
    context: ExecutionContext,
    calls: Mutex<BTreeMap<[u8; 32], Pending>>,
}

fn frame(bytes: &[u8], limit: usize) -> anyhow::Result<Value> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit && bytes.ends_with(b"\n"),
        "witness wire framing/bound"
    );
    ensure!(
        !bytes[..bytes.len() - 1].contains(&b'\n'),
        "witness requires one original wire line"
    );
    let crate::mcp::admission::Strict(value) = serde_json::from_slice(bytes)?;
    ensure!(value["jsonrpc"] == "2.0", "witness JSON-RPC version");
    ensure!(
        value["id"].as_i64().is_some()
            || value["id"].as_u64().is_some()
            || value["id"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 128),
        "witness request id"
    );
    Ok(value)
}

impl Producer {
    pub fn new(context: ExecutionContext) -> anyhow::Result<Self> {
        context.validate()?;
        Ok(Self {
            context,
            calls: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn begin(
        &self,
        snapshot: Arc<Snapshot>,
        original_request: &[u8],
    ) -> anyhow::Result<Ticket> {
        snapshot.valid()?;
        ensure!(
            snapshot.profile == self.context.profile_format,
            "witness profile/view mismatch"
        );
        let request = frame(original_request, MAX_REQUEST_BYTES)?;
        ensure!(
            request["method"] == "tools/call" && request["params"]["name"] == "git_show",
            "witness operation unsupported"
        );
        let args = &request["params"]["arguments"];
        super::validate_arguments_with_local_refs(
            "git_show",
            args,
            self.context.profile_format == super::LOCAL_REFS_FORMAT,
        )?;
        let revision = args["revision"]
            .as_str()
            .context("witness revision missing")?
            .to_owned();
        let target = snapshot.repository.resolve(&revision)?;
        snapshot.valid()?;
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("witness ledger unavailable"))?;
        calls.retain(|_, call| call.started.elapsed() < LOCAL_LIFETIME);
        ensure!(
            calls.len() < MAX_PENDING,
            "local witness pending-call bound"
        );
        let nonce = rand::random::<[u8; 32]>();
        ensure!(
            !calls.contains_key(&nonce),
            "local witness identity collision"
        );
        calls.insert(
            nonce,
            Pending {
                snapshot,
                started: Instant::now(),
                id: request["id"].clone(),
                revision,
                target,
                request: hash(b"original-request-wire", original_request),
                completed: None,
            },
        );
        Ok(Ticket(nonce))
    }

    pub fn cancel(&self, ticket: &Ticket) -> anyhow::Result<()> {
        let removed = self
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("witness ledger unavailable"))?
            .remove(&ticket.0);
        ensure!(removed.is_some(), "unknown or consumed local invocation");
        Ok(())
    }

    /// The caller must own the result channel. This method does not establish
    /// that custody, select an executable, or prove which process returned it.
    pub fn complete(&self, ticket: &Ticket, original_result: &[u8]) -> anyhow::Result<Claim> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("witness ledger unavailable"))?;
        let mut call = calls
            .remove(&ticket.0)
            .context("unknown or consumed local invocation")?;
        ensure!(
            call.started.elapsed() < LOCAL_LIFETIME && call.completed.is_none(),
            "expired or already completed local invocation"
        );
        call.snapshot.valid()?;
        let response = frame(original_result, MAX_RESULT_BYTES)?;
        ensure!(
            response["id"] == call.id && response.get("error").is_none(),
            "witness result correlation/error"
        );
        let profiles = super::classify_manifest(&super::original_manifest())?;
        ensure!(
            profiles["git_show"].validate_result(&response)? == "value",
            "error result has no object completion witness"
        );
        call.snapshot.valid()?;
        let claim = Claim {
            format: FORMAT,
            invocation: ticket.0,
            context: self.context.clone(),
            schema_sha256: Sha256::digest(include_bytes!(
                "../../../../../../profiles/mcp/git-readonly-v1/upstream-tools-list.json"
            ))
            .into(),
            view_sha256: call.snapshot.repository.digest,
            view_generation: call.snapshot.generation,
            operation: "git_show",
            revision: call.revision.clone(),
            target: call.target.clone(),
            request_sha256: call.request,
            result_sha256: hash(b"original-result-wire", original_result),
            result_bytes: original_result.len(),
        };
        call.completed = Some(claim.clone());
        calls.insert(ticket.0, call);
        Ok(claim)
    }

    /// Consumes the local slot even on mismatch. A returned typed target is
    /// local component evidence only; production authentication stays disabled.
    pub fn verify_local(
        &self,
        claim: &Claim,
        expected: &ExecutionContext,
        original_request: &[u8],
        original_result: &[u8],
    ) -> anyhow::Result<ShowTarget> {
        let call = self
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("witness ledger unavailable"))?
            .remove(&claim.invocation)
            .context("unknown or consumed local witness")?;
        ensure!(
            call.started.elapsed() < LOCAL_LIFETIME,
            "expired local witness"
        );
        call.snapshot.valid()?;
        ensure!(
            &self.context == expected && &claim.context == expected,
            "local execution context mismatch"
        );
        ensure!(
            original_request.len() <= MAX_REQUEST_BYTES
                && original_result.len() <= MAX_RESULT_BYTES,
            "local witness verification byte bound"
        );
        ensure!(
            call.completed.as_ref() == Some(claim)
                && claim.request_sha256 == hash(b"original-request-wire", original_request)
                && claim.result_sha256 == hash(b"original-result-wire", original_result)
                && claim.result_bytes == original_result.len(),
            "local witness request/result/view mismatch"
        );
        call.snapshot.valid()?;
        Ok(call.target)
    }
}
