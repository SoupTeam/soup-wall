// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Per-session provenance tracking: which untrusted content has entered, and whether
//! it is now showing up inside a tool call's arguments.

use std::collections::{HashMap, VecDeque};
use std::mem::size_of;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    OnceLock,
};

use serde::{Deserialize, Serialize};

use regex::Regex;

use crate::event::{Provenance, SessionId, Trust};
use crate::fingerprint::fingerprints;

/// How many fingerprints must match before content counts as tainted.
/// Below this, short coincidental overlaps produce false positives.
pub const MIN_MATCHES: usize = 3;

/// Why a piece of content is tainted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintMark {
    pub source: Provenance,
    /// Sequence number of the event that introduced the content.
    pub seq: u64,
}

/// Sensitive checkpoint data, intended only for private authenticated storage.
/// This contains provenance URL/path literals; never include it in audit output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceSnapshot {
    pub format: String,
    pub legacy_unknown_history: bool,
    pub sessions: Vec<SessionProvenanceSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionProvenanceSnapshot {
    pub session: String,
    pub incomplete: bool,
    pub fingerprints: Vec<(u64, TaintMark)>,
    pub literals: Vec<(String, TaintMark)>,
}

/// Shortest literal worth storing. Below this, matches are coincidental noise
/// (`/tmp`, `a.io`) rather than distinctive provenance evidence.
///
/// This threshold alone would silently drop the most sensitive credential paths
/// that exist (`/etc/passwd` is 11 chars, `~/.netrc` is 8) — see
/// `SENSITIVE_PATH_MARKERS`, which exempts them regardless of length.
const MIN_LITERAL_LEN: usize = 12;

/// Paths worth tracking regardless of length. `MIN_LITERAL_LEN` was tuned against
/// URL noise, and it happens to exclude nearly every high-value credential path
/// (`/etc/passwd` is 11 chars, `~/.netrc` is 8).
const SENSITIVE_PATH_MARKERS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/.ssh",
    "/.aws",
    "/.gnupg",
    "/.config/gcloud",
    "/.netrc",
    "/.npmrc",
    "/.docker",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "authorized_keys",
    ".env",
];

/// Distinctive short strings extracted from untrusted content: URLs and absolute
/// or `~`-relative paths. These are what fingerprinting structurally cannot catch —
/// a 33-character exfil URL yields fingerprints that match nothing.
///
/// **Deliberately NOT extracted: bare hostnames without a scheme.** An earlier
/// revision had a third branch, `\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b`, matching any
/// dotted lowercase token. Such a pattern also extracts `package.json`,
/// `docker-compose.yml`, `self.assertEqual`, `CONTRIBUTING.md`, and
/// `requirements.txt` — ordinary filenames and code tokens, indistinguishable
/// from hostnames by shape alone. Because a literal hit needs no `MIN_MATCHES`
/// threshold, any one of those appearing in untrusted content would taint every
/// later tool call that mentions the same filename, which makes the tool
/// unusable. A denylist of common filenames is endless and brittle; raising
/// `MIN_LITERAL_LEN` past 18 to dodge the worst offenders would start discarding
/// real exfil URLs too. The URL branch still matches a hostname inside a URL
/// (`https://evil.com/collect`). A tool call reaching a bare host with no scheme
/// is covered by egress host extraction and the unknown-host `ask` policy rule.
/// Do not re-add a bare-hostname branch without checking filename and code-token
/// false positives.
fn bounded_literals(text: &str, limit: usize) -> Result<Vec<String>, TrackingFailure> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?ix)
              \b[a-z][a-z0-9+.-]*://[^\s'\x22)>\]]+     # URLs
            | (?:^|[\s'\x22(<\[])(~?/[A-Za-z0-9._/-]{6,})  # absolute or ~ paths
            ",
        )
        .expect("literal regex")
    });
    let mut out = Vec::new();
    for c in re.captures_iter(text) {
        // Group 1 is the path alternative, which excludes its leading delimiter.
        // When it's unset, the URL branch matched instead (group 0).
        let is_path = c.get(1).is_some();
        let m = c.get(1).or_else(|| c.get(0));
        let Some(m) = m else { continue };
        let s = m.as_str().trim_end_matches(['.', ',', ';', ')', '"', '\'']);
        // Stored and matched lowercase: hosts are case-insensitive per RFC, and a
        // page writing `HTTPS://EXFIL.EXAMPLE.COM/COLLECT` must still be caught
        // when the agent naturally reuses it in lowercase. POSIX paths are
        // technically case-sensitive, so this can in principle miss a case-only
        // path difference — that false-negative risk is far smaller than leaving
        // a one-keystroke case bypass on every URL and host.
        let normalized_len = s
            .chars()
            .flat_map(char::to_lowercase)
            .try_fold(0usize, |n, ch| n.checked_add(ch.len_utf8()))
            .ok_or(TrackingFailure::Arithmetic)?;
        if normalized_len > limit {
            return Err(TrackingFailure::Literal);
        }
        let lower = s.to_lowercase();

        if !is_path {
            // URLs: length threshold only, same as before.
            if s.len() >= MIN_LITERAL_LEN {
                out.push(lower);
            }
            continue;
        }

        // Paths: a general absolute path with no sensitive marker and no leading
        // `~` must contain a `.` in some segment (a filename extension) to be
        // kept. Bare route fragments like `/v1/messages` or `/api/v2/users/list`
        // are extension-less, shared across unrelated services, and carry no
        // provenance signal — recording one taints every client of every API
        // that happens to share the route shape, regardless of host.
        let sensitive = SENSITIVE_PATH_MARKERS.iter().any(|m| lower.contains(m));
        let is_home = s.starts_with('~');
        let has_extension_segment = s.split('/').any(|seg| seg.contains('.'));
        // Generated resource names are usually unique enough to be useful provenance
        // evidence even if their path has no filename extension. Without this branch,
        // a poisoned instruction such as `rm -rf /srv/app/CACHE_9f3a2b` loses the only
        // reusable part of the command: normal fingerprints need a longer overlap.
        // Require both a digit and a separator in an 8+ byte segment so common routes
        // such as `/v1/messages` remain excluded.
        let has_generated_segment = s.split('/').any(|seg| {
            seg.len() >= 8
                && seg.chars().any(|c| c.is_ascii_digit())
                && seg.chars().any(|c| c == '_' || c == '-')
        });
        if !(sensitive || is_home || has_extension_segment || has_generated_segment) {
            continue;
        }
        if s.len() >= MIN_LITERAL_LEN || sensitive {
            out.push(lower);
        }
    }
    Ok(out)
}

#[cfg(test)]
fn literals(text: &str) -> Vec<String> {
    bounded_literals(text, usize::MAX).expect("unbounded test-only literal extraction")
}

/// Reviewed limits for retained provenance, separately from whole-process RSS.
/// Zero byte/session limits disable registration without allocating loss markers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TaintLimits {
    pub per_session_bytes: usize,
    pub total_bytes: usize,
    pub max_sessions: usize,
    pub max_input_bytes: usize,
    pub max_source_bytes: usize,
    pub max_literal_bytes: usize,
    pub max_session_id_bytes: usize,
}

impl Default for TaintLimits {
    fn default() -> Self {
        Self {
            per_session_bytes: 8 * 1024 * 1024,
            total_bytes: 64 * 1024 * 1024,
            max_sessions: 512,
            max_input_bytes: 262_144,
            max_source_bytes: 1024,
            max_literal_bytes: 4096,
            max_session_id_bytes: 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitError(&'static str);
impl std::fmt::Display for LimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for LimitError {}

impl TaintLimits {
    pub fn validate(&self) -> Result<(), LimitError> {
        if self.per_session_bytes > isize::MAX as usize || self.total_bytes > isize::MAX as usize {
            return Err(LimitError(
                "provenance byte budgets exceed the addressable allocation range",
            ));
        }
        if self.max_sessions > 65_536 || self.max_session_id_bytes > 4096 {
            return Err(LimitError(
                "provenance session limits exceed reviewed maxima",
            ));
        }
        if self.max_input_bytes > 1024 * 1024
            || self.max_source_bytes > 65_536
            || self.max_literal_bytes > 65_536
        {
            return Err(LimitError(
                "provenance extraction limits exceed reviewed maxima",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackingFailure {
    SessionCapacity,
    SessionId,
    Input,
    Source,
    Literal,
    EntryCapacity,
    SessionBytes,
    GlobalBytes,
    Arithmetic,
    Allocation,
}
impl TrackingFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::SessionCapacity => "session_capacity",
            Self::SessionId => "session_id",
            Self::Input => "input",
            Self::Source => "source",
            Self::Literal => "literal",
            Self::EntryCapacity => "entry_capacity",
            Self::SessionBytes => "session_bytes",
            Self::GlobalBytes => "global_bytes",
            Self::Arithmetic => "arithmetic",
            Self::Allocation => "allocation",
        }
    }
}
impl std::fmt::Display for TrackingFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for TrackingFailure {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaintUsage {
    pub retained_bytes: usize,
    pub max_session_retained_bytes: usize,
    pub sessions: usize,
    pub incomplete_sessions: usize,
    pub fingerprints: usize,
    pub literals: usize,
    pub legacy_unknown_history: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionTaintUsage {
    pub retained_bytes: usize,
    pub fingerprints: usize,
    pub literals: usize,
    pub incomplete: bool,
}

fn add(a: usize, b: usize) -> Result<usize, TrackingFailure> {
    a.checked_add(b).ok_or(TrackingFailure::Arithmetic)
}
fn sub(a: usize, b: usize) -> Result<usize, TrackingFailure> {
    a.checked_sub(b).ok_or(TrackingFailure::Arithmetic)
}
fn mul(a: usize, b: usize) -> Result<usize, TrackingFailure> {
    a.checked_mul(b).ok_or(TrackingFailure::Arithmetic)
}

/// Conservative std table allocation model: round the FRESH usable capacity to
/// buckets, charge all bucket payload/control bytes and 256 bytes of alignment /
/// group-control slack. The charge is saved at allocation, never recomputed after
/// tombstones lower `HashMap::capacity()`. Allocator bookkeeping and RSS are not
/// represented by this owned-storage metric. Fixed tracker headers are excluded.
fn table_bytes<K, V>(fresh_capacity: usize) -> Result<usize, TrackingFailure> {
    if fresh_capacity == 0 {
        return Ok(0);
    }
    let buckets = add(fresh_capacity, 1)?
        .checked_next_power_of_two()
        .ok_or(TrackingFailure::Arithmetic)?;
    add(mul(buckets, add(size_of::<(K, V)>(), 1)?)?, 256)
}
fn map_plan<K, V>(needed: usize) -> Result<usize, TrackingFailure> {
    table_bytes::<K, V>(mul(
        needed
            .checked_next_power_of_two()
            .ok_or(TrackingFailure::Arithmetic)?,
        2,
    )?)
}
fn queue_plan<T>(needed: usize) -> Result<usize, TrackingFailure> {
    mul(
        mul(
            needed
                .checked_next_power_of_two()
                .ok_or(TrackingFailure::Arithmetic)?,
            2,
        )?,
        size_of::<T>(),
    )
}
fn source_bytes(source: &Provenance, capacity: bool) -> Result<usize, TrackingFailure> {
    let bytes = |s: &String| if capacity { s.capacity() } else { s.len() };
    match source {
        Provenance::Network { host } => Ok(bytes(host)),
        Provenance::McpServer { name } | Provenance::Subagent { name } => Ok(bytes(name)),
        Provenance::Native { registry, tool } => add(bytes(registry), bytes(tool)),
        _ => Ok(0),
    }
}
fn owned_string(text: &str) -> Result<String, TrackingFailure> {
    let mut out = String::new();
    out.try_reserve_exact(text.len())
        .map_err(|_| TrackingFailure::Allocation)?;
    out.push_str(text);
    Ok(out)
}
fn grow_map<K: std::hash::Hash + Eq, V>(
    map: &mut HashMap<K, V>,
    allocated: &mut usize,
    plan: usize,
) -> Result<(), TrackingFailure> {
    let mut next = HashMap::new();
    next.try_reserve(add(map.len(), 1)?)
        .map_err(|_| TrackingFailure::Allocation)?;
    let actual = table_bytes::<K, V>(next.capacity())?;
    if actual > plan {
        return Err(TrackingFailure::Allocation);
    }
    next.extend(map.drain());
    *map = next;
    *allocated = actual;
    Ok(())
}
fn grow_queue<T>(
    queue: &mut VecDeque<T>,
    allocated: &mut usize,
    plan: usize,
) -> Result<(), TrackingFailure> {
    let mut next = VecDeque::new();
    next.try_reserve_exact(add(queue.len(), 1)?)
        .map_err(|_| TrackingFailure::Allocation)?;
    let actual = mul(next.capacity(), size_of::<T>())?;
    if actual > plan {
        return Err(TrackingFailure::Allocation);
    }
    next.append(queue);
    *queue = next;
    *allocated = actual;
    Ok(())
}

#[derive(Debug, Default)]
struct SessionTaint {
    incomplete: AtomicBool,
    marks: HashMap<u64, TaintMark>,
    order: VecDeque<u64>,
    literals: HashMap<String, TaintMark>,
    literal_order: VecDeque<String>,
    marks_allocation: usize,
    order_allocation: usize,
    literals_allocation: usize,
    literal_order_allocation: usize,
    /// Includes this session's inline table entry, identifier heap and all child
    /// backing allocations / owned strings. The outer table is charged globally.
    retained: usize,
}

impl SessionTaint {
    fn lose(&self) {
        self.incomplete.store(true, Ordering::Relaxed);
    }
    fn fits(
        &self,
        extra: usize,
        total: usize,
        limits: &TaintLimits,
    ) -> Result<(), TrackingFailure> {
        if add(self.retained, extra)? > limits.per_session_bytes {
            return Err(TrackingFailure::SessionBytes);
        }
        if add(total, extra)? > limits.total_bytes {
            return Err(TrackingFailure::GlobalBytes);
        }
        Ok(())
    }
    fn charge(&mut self, total: &mut usize, bytes: usize) -> Result<(), TrackingFailure> {
        let retained = add(self.retained, bytes)?;
        let global = add(*total, bytes)?;
        self.retained = retained;
        *total = global;
        Ok(())
    }
    fn release(&mut self, total: &mut usize, bytes: usize) -> Result<(), TrackingFailure> {
        let retained = sub(self.retained, bytes)?;
        let global = sub(*total, bytes)?;
        self.retained = retained;
        *total = global;
        Ok(())
    }
    fn evict(&mut self, total: &mut usize, literal_first: bool) -> Result<bool, TrackingFailure> {
        if literal_first {
            if let Some(key) = self.literal_order.pop_front() {
                let (stored, mark) = self
                    .literals
                    .remove_entry(&key)
                    .ok_or(TrackingFailure::Arithmetic)?;
                self.release(
                    total,
                    add(
                        add(key.capacity(), stored.capacity())?,
                        source_bytes(&mark.source, true)?,
                    )?,
                )?;
                self.lose();
                return Ok(true);
            }
        }
        if let Some(key) = self.order.pop_front() {
            let mark = self.marks.remove(&key).ok_or(TrackingFailure::Arithmetic)?;
            self.release(total, source_bytes(&mark.source, true)?)?;
            self.lose();
            return Ok(true);
        }
        if !literal_first && !self.literal_order.is_empty() {
            return self.evict(total, true);
        }
        Ok(false)
    }
    fn room(
        &mut self,
        total: &mut usize,
        limits: &TaintLimits,
        payload: usize,
        literal: bool,
    ) -> Result<(), TrackingFailure> {
        loop {
            let (map_len, map_capacity, queue_len, queue_capacity) = if literal {
                (
                    self.literals.len(),
                    self.literals.capacity(),
                    self.literal_order.len(),
                    self.literal_order.capacity(),
                )
            } else {
                (
                    self.marks.len(),
                    self.marks.capacity(),
                    self.order.len(),
                    self.order.capacity(),
                )
            };
            let map_grow = map_len >= map_capacity;
            let queue_grow = queue_len >= queue_capacity;
            let map_charge = if map_grow {
                if literal {
                    map_plan::<String, TaintMark>(add(map_len, 1)?)?
                } else {
                    map_plan::<u64, TaintMark>(add(map_len, 1)?)?
                }
            } else {
                0
            };
            let queue_charge = if queue_grow {
                if literal {
                    queue_plan::<String>(add(queue_len, 1)?)?
                } else {
                    queue_plan::<u64>(add(queue_len, 1)?)?
                }
            } else {
                0
            };
            let result = self.fits(
                add(payload, add(map_charge, queue_charge)?)?,
                *total,
                limits,
            );
            if let Err(failure) = result {
                if self.evict(total, literal)? {
                    continue;
                }
                return Err(failure);
            }
            // The old and empty replacement allocations BOTH fit before growth.
            // No old evidence is moved until the replacement capacity is checked.
            if literal {
                if map_grow {
                    let old = self.literals_allocation;
                    grow_map(
                        &mut self.literals,
                        &mut self.literals_allocation,
                        map_charge,
                    )?;
                    self.charge(total, self.literals_allocation)?;
                    self.release(total, old)?;
                }
                if queue_grow {
                    let old = self.literal_order_allocation;
                    grow_queue(
                        &mut self.literal_order,
                        &mut self.literal_order_allocation,
                        queue_charge,
                    )?;
                    self.charge(total, self.literal_order_allocation)?;
                    self.release(total, old)?;
                }
            } else {
                if map_grow {
                    let old = self.marks_allocation;
                    grow_map(&mut self.marks, &mut self.marks_allocation, map_charge)?;
                    self.charge(total, self.marks_allocation)?;
                    self.release(total, old)?;
                }
                if queue_grow {
                    let old = self.order_allocation;
                    grow_queue(&mut self.order, &mut self.order_allocation, queue_charge)?;
                    self.charge(total, self.order_allocation)?;
                    self.release(total, old)?;
                }
            }
            return Ok(());
        }
    }
    fn replace_source(
        &mut self,
        total: &mut usize,
        limits: &TaintLimits,
        old: usize,
        new: usize,
    ) -> Result<(), TrackingFailure> {
        if new > old {
            let delta = sub(new, old)?;
            self.fits(delta, *total, limits)?;
            self.charge(total, delta)
        } else {
            self.release(total, sub(old, new)?)
        }
    }
    fn record(
        &mut self,
        cap: usize,
        limits: &TaintLimits,
        total: &mut usize,
        seq: u64,
        source: &Provenance,
        text: &str,
    ) -> Result<(), TrackingFailure> {
        if cap == 0 {
            return Err(TrackingFailure::EntryCapacity);
        }
        if text.len() > limits.max_input_bytes {
            return Err(TrackingFailure::Input);
        }
        if source_bytes(source, false)? > limits.max_source_bytes {
            return Err(TrackingFailure::Source);
        }
        // Reject huge URL/path matches before lowercase / fingerprint allocation.
        let required_literals = bounded_literals(text, limits.max_literal_bytes)?;
        let required_marks = fingerprints(text);
        for fp in &required_marks {
            if let Some(existing) = self.marks.get(fp) {
                if seq < existing.seq {
                    let old = source_bytes(&existing.source, true)?;
                    let next = TaintMark {
                        source: source.clone(),
                        seq,
                    };
                    self.replace_source(total, limits, old, source_bytes(&next.source, true)?)?;
                    self.marks.insert(*fp, next);
                }
                continue;
            }
            if self.marks.len() >= cap {
                self.evict(total, false)?;
            }
            let next = TaintMark {
                source: source.clone(),
                seq,
            };
            let bytes = source_bytes(&next.source, true)?;
            self.room(total, limits, bytes, false)?;
            self.charge(total, bytes)?;
            self.marks.insert(*fp, next);
            self.order.push_back(*fp);
        }
        for lit in &required_literals {
            if let Some(existing) = self.literals.get(lit) {
                if seq < existing.seq {
                    let old = source_bytes(&existing.source, true)?;
                    let next = TaintMark {
                        source: source.clone(),
                        seq,
                    };
                    self.replace_source(total, limits, old, source_bytes(&next.source, true)?)?;
                    self.literals.insert(owned_string(lit)?, next);
                }
                continue;
            }
            if self.literals.len() >= cap {
                self.evict(total, true)?;
            }
            let next = TaintMark {
                source: source.clone(),
                seq,
            };
            let key = owned_string(lit)?;
            let queued = owned_string(lit)?;
            let bytes = add(
                source_bytes(&next.source, true)?,
                add(key.capacity(), queued.capacity())?,
            )?;
            self.room(total, limits, bytes, true)?;
            self.charge(total, bytes)?;
            self.literals.insert(key, next);
            self.literal_order.push_back(queued);
        }
        if required_marks.iter().any(|fp| !self.marks.contains_key(fp))
            || required_literals
                .iter()
                .any(|lit| !self.literals.contains_key(lit))
        {
            return Err(TrackingFailure::EntryCapacity);
        }
        Ok(())
    }
}

/// Bounded retained provenance. No active context or loss marker is evicted to
/// make room for another context. Unknown exposed legacy contexts use ONE sticky
/// fallback flag, never an unbounded tombstone map.
#[derive(Debug)]
pub struct TaintTracker {
    cap: usize,
    limits: TaintLimits,
    sessions: HashMap<SessionId, SessionTaint>,
    sessions_allocation: usize,
    retained: usize,
    legacy_unknown_history: AtomicBool,
}

impl TaintTracker {
    pub fn new(cap: usize) -> Self {
        Self::with_limits(cap, TaintLimits::default()).expect("reviewed provenance defaults")
    }
    pub fn with_limits(cap: usize, limits: TaintLimits) -> Result<Self, LimitError> {
        limits.validate()?;
        Ok(Self {
            cap,
            limits,
            sessions: HashMap::new(),
            sessions_allocation: 0,
            retained: 0,
            legacy_unknown_history: AtomicBool::new(false),
        })
    }
    pub fn mark_all_incomplete(&mut self) {
        self.legacy_unknown_history.store(true, Ordering::Relaxed);
        for session in self.sessions.values() {
            session.lose();
        }
    }

    /// Export evidence in insertion order so replay preserves eviction behavior.
    /// No grants, active agents, approvals or executable authority are exported.
    pub fn provenance_snapshot(&self) -> ProvenanceSnapshot {
        let mut sessions: Vec<_> = self
            .sessions
            .iter()
            .map(|(id, entry)| SessionProvenanceSnapshot {
                session: id.clone(),
                incomplete: entry.incomplete.load(Ordering::Relaxed),
                fingerprints: entry
                    .order
                    .iter()
                    .filter_map(|key| entry.marks.get(key).map(|mark| (*key, mark.clone())))
                    .collect(),
                literals: entry
                    .literal_order
                    .iter()
                    .filter_map(|key| {
                        entry
                            .literals
                            .get(key)
                            .map(|mark| (key.clone(), mark.clone()))
                    })
                    .collect(),
            })
            .collect();
        sessions.sort_by(|a, b| a.session.cmp(&b.session));
        ProvenanceSnapshot {
            format: "sw-provenance/checkpoint/1".into(),
            legacy_unknown_history: self.legacy_unknown_history.load(Ordering::Relaxed),
            sessions,
        }
    }

    /// Restore only a pristine tracker. Failed validation is atomic; lower
    /// budgets refuse startup rather than silently discarding an old risk floor.
    pub fn restore_provenance_snapshot(
        &mut self,
        snapshot: ProvenanceSnapshot,
    ) -> Result<(), &'static str> {
        if !self.sessions.is_empty() || self.legacy_unknown_history.load(Ordering::Relaxed) {
            return Err("provenance_restore_requires_pristine_tracker");
        }
        if snapshot.format != "sw-provenance/checkpoint/1" {
            return Err("provenance_checkpoint_version");
        }
        if snapshot.sessions.len() > self.limits.max_sessions {
            return Err("provenance_checkpoint_capacity");
        }
        let mut next = Self::with_limits(self.cap, self.limits.clone())
            .map_err(|_| "provenance_checkpoint_limits")?;
        for saved in snapshot.sessions {
            if saved.fingerprints.len() > self.cap || saved.literals.len() > self.cap {
                return Err("provenance_checkpoint_capacity");
            }
            if !next
                .try_register(&saved.session)
                .map_err(TrackingFailure::code)?
            {
                return Err("provenance_checkpoint_duplicate_session");
            }
            let entry = next
                .sessions
                .get_mut(&saved.session)
                .ok_or("provenance_checkpoint_session")?;
            let mark_count = saved.fingerprints.len();
            let literal_count = saved.literals.len();
            for (key, mark) in saved.fingerprints {
                if entry.marks.contains_key(&key) || mark.source.trust() != Trust::Untrusted {
                    return Err("provenance_checkpoint_fingerprint");
                }
                if source_bytes(&mark.source, false).map_err(TrackingFailure::code)?
                    > next.limits.max_source_bytes
                {
                    return Err("provenance_checkpoint_source");
                }
                let bytes = source_bytes(&mark.source, true).map_err(TrackingFailure::code)?;
                entry
                    .room(&mut next.retained, &next.limits, bytes, false)
                    .map_err(TrackingFailure::code)?;
                entry
                    .charge(&mut next.retained, bytes)
                    .map_err(TrackingFailure::code)?;
                entry.marks.insert(key, mark);
                entry.order.push_back(key);
            }
            for (key, mark) in saved.literals {
                if key.is_empty()
                    || key.len() > next.limits.max_literal_bytes
                    || entry.literals.contains_key(&key)
                    || mark.source.trust() != Trust::Untrusted
                {
                    return Err("provenance_checkpoint_literal");
                }
                if source_bytes(&mark.source, false).map_err(TrackingFailure::code)?
                    > next.limits.max_source_bytes
                {
                    return Err("provenance_checkpoint_source");
                }
                let queued = owned_string(&key).map_err(TrackingFailure::code)?;
                let bytes = add(
                    source_bytes(&mark.source, true).map_err(TrackingFailure::code)?,
                    add(key.capacity(), queued.capacity()).map_err(TrackingFailure::code)?,
                )
                .map_err(TrackingFailure::code)?;
                entry
                    .room(&mut next.retained, &next.limits, bytes, true)
                    .map_err(TrackingFailure::code)?;
                entry
                    .charge(&mut next.retained, bytes)
                    .map_err(TrackingFailure::code)?;
                entry.literals.insert(key, mark);
                entry.literal_order.push_back(queued);
            }
            if entry.marks.len() != mark_count || entry.literals.len() != literal_count {
                return Err("provenance_checkpoint_budget_would_erase_history");
            }
            entry.incomplete.store(saved.incomplete, Ordering::Relaxed);
        }
        next.legacy_unknown_history
            .store(snapshot.legacy_unknown_history, Ordering::Relaxed);
        *self = next;
        Ok(())
    }

    pub fn limits(&self) -> &TaintLimits {
        &self.limits
    }
    pub fn usage(&self) -> TaintUsage {
        TaintUsage {
            retained_bytes: self.retained,
            max_session_retained_bytes: self
                .sessions
                .values()
                .map(|s| s.retained)
                .max()
                .unwrap_or(0),
            sessions: self.sessions.len(),
            incomplete_sessions: self
                .sessions
                .values()
                .filter(|s| s.incomplete.load(Ordering::Relaxed))
                .count(),
            fingerprints: self
                .sessions
                .values()
                .fold(0usize, |n, s| n.saturating_add(s.marks.len())),
            literals: self
                .sessions
                .values()
                .fold(0usize, |n, s| n.saturating_add(s.literals.len())),
            legacy_unknown_history: self.legacy_unknown_history.load(Ordering::Relaxed),
        }
    }
    pub fn session_usage(&self, session: &str) -> Option<SessionTaintUsage> {
        if session.len() > self.limits.max_session_id_bytes {
            return None;
        }
        self.sessions.get(session).map(|s| SessionTaintUsage {
            retained_bytes: s.retained,
            fingerprints: s.marks.len(),
            literals: s.literals.len(),
            incomplete: s.incomplete.load(Ordering::Relaxed),
        })
    }
    /// Reserve a shell before selected-runtime authority is published. `true`
    /// means newly created and permits rollback of this unpublished shell only.
    pub fn try_register(&mut self, session: &str) -> Result<bool, TrackingFailure> {
        if session.is_empty() || session.len() > self.limits.max_session_id_bytes {
            return Err(TrackingFailure::SessionId);
        }
        if self.sessions.contains_key(session) {
            return Ok(false);
        }
        if self.sessions.len() >= self.limits.max_sessions {
            return Err(TrackingFailure::SessionCapacity);
        }
        let id = owned_string(session)?;
        let base = add(size_of::<(String, SessionTaint)>(), id.capacity())?;
        if base > self.limits.per_session_bytes {
            return Err(TrackingFailure::SessionBytes);
        }
        let grow = self.sessions.len() >= self.sessions.capacity();
        let plan = if grow {
            map_plan::<String, SessionTaint>(add(self.sessions.len(), 1)?)?
        } else {
            0
        };
        if add(self.retained, add(id.capacity(), plan)?)? > self.limits.total_bytes {
            return Err(TrackingFailure::GlobalBytes);
        }
        if grow {
            let old = self.sessions_allocation;
            grow_map(&mut self.sessions, &mut self.sessions_allocation, plan)?;
            self.retained = sub(add(self.retained, self.sessions_allocation)?, old)?;
        }
        self.retained = add(self.retained, id.capacity())?;
        let entry = SessionTaint {
            retained: base,
            incomplete: AtomicBool::new(self.legacy_unknown_history.load(Ordering::Relaxed)),
            ..Default::default()
        };
        self.sessions.insert(id, entry);
        Ok(true)
    }
    pub fn try_record(
        &mut self,
        session: &str,
        seq: u64,
        source: &Provenance,
        text: &str,
    ) -> Result<(), TrackingFailure> {
        if source.trust() != Trust::Untrusted {
            return Ok(());
        }
        self.try_register(session)?;
        let entry = self
            .sessions
            .get_mut(session)
            .ok_or(TrackingFailure::Arithmetic)?;
        let result = entry.record(
            self.cap,
            &self.limits,
            &mut self.retained,
            seq,
            source,
            text,
        );
        if result.is_err() {
            entry.lose();
        }
        result
    }
    /// Compatibility entry point for already-exposed hook/library content. A
    /// failed unrepresented context poisons unknown history conservatively.
    pub fn record(&mut self, session: &str, seq: u64, source: &Provenance, text: &str) {
        if self.try_record(session, seq, source, text).is_err()
            && (session.len() > self.limits.max_session_id_bytes
                || !self.sessions.contains_key(session))
        {
            self.legacy_unknown_history.store(true, Ordering::Relaxed);
        }
    }
    pub fn try_check(
        &self,
        session: &str,
        text: &str,
    ) -> Result<Option<TaintMark>, TrackingFailure> {
        if session.is_empty() || session.len() > self.limits.max_session_id_bytes {
            self.legacy_unknown_history.store(true, Ordering::Relaxed);
            return Err(TrackingFailure::SessionId);
        }
        if text.len() > self.limits.max_input_bytes {
            if let Some(entry) = self.sessions.get(session) {
                entry.lose();
            } else {
                self.legacy_unknown_history.store(true, Ordering::Relaxed);
            }
            return Err(TrackingFailure::Input);
        }
        let Some(entry) = self.sessions.get(session) else {
            return Ok(None);
        };
        let mut earliest: Option<&TaintMark> = None;
        let mut hits = 0usize;
        for fp in fingerprints(text) {
            if let Some(mark) = entry.marks.get(&fp) {
                hits += 1;
                if earliest.is_none_or(|old| mark.seq < old.seq) {
                    earliest = Some(mark);
                }
            }
        }
        if hits < MIN_MATCHES {
            earliest = None;
        }
        let lower = text.to_lowercase();
        for (literal, mark) in &entry.literals {
            if lower.contains(literal) && earliest.is_none_or(|old| mark.seq < old.seq) {
                earliest = Some(mark);
            }
        }
        Ok(earliest.cloned())
    }
    /// Recheck every required part of an admitted batch AFTER all its records.
    /// Another block in the same original delivery may have evicted an earlier
    /// block even though each individual record succeeded at the time.
    pub fn current_input_retained(
        &self,
        session: &str,
        seq: u64,
        source: &Provenance,
        text: &str,
    ) -> Result<bool, TrackingFailure> {
        if source.trust() != Trust::Untrusted {
            return Ok(true);
        }
        if session.is_empty() || session.len() > self.limits.max_session_id_bytes {
            return Err(TrackingFailure::SessionId);
        }
        let Some(entry) = self.sessions.get(session) else {
            return Ok(false);
        };
        let result = (|| {
            if self.cap == 0 {
                return Err(TrackingFailure::EntryCapacity);
            }
            if text.len() > self.limits.max_input_bytes {
                return Err(TrackingFailure::Input);
            }
            if source_bytes(source, false)? > self.limits.max_source_bytes {
                return Err(TrackingFailure::Source);
            }
            let required_literals = bounded_literals(text, self.limits.max_literal_bytes)?;
            Ok(fingerprints(text)
                .iter()
                .all(|fp| entry.marks.get(fp).is_some_and(|mark| mark.seq <= seq))
                && required_literals
                    .iter()
                    .all(|lit| entry.literals.get(lit).is_some_and(|mark| mark.seq <= seq)))
        })();
        if !matches!(result, Ok(true)) {
            entry.lose();
        }
        result
    }
    pub fn check(&self, session: &str, text: &str) -> Option<TaintMark> {
        self.try_check(session, text).ok().flatten()
    }
    /// The caller must authenticate actual retirement; duplicate starts and one
    /// child ending are NOT permission to call this for a shared active host.
    pub fn end_session(&mut self, session: &str) {
        if session.len() > self.limits.max_session_id_bytes {
            return;
        }
        if let Some(entry) = self.sessions.remove(session) {
            let dynamic = entry
                .retained
                .checked_sub(size_of::<(String, SessionTaint)>())
                .expect("owned provenance accounting invariant");
            self.retained = self
                .retained
                .checked_sub(dynamic)
                .expect("owned provenance accounting invariant");
        }
        // Retained outer table capacity stays charged after removal. When all
        // contexts retire, replace it so even that backing allocation is freed.
        if self.sessions.is_empty() {
            self.sessions = HashMap::new();
            self.retained = self
                .retained
                .checked_sub(self.sessions_allocation)
                .expect("owned provenance accounting invariant");
            self.sessions_allocation = 0;
        }
    }
    pub fn len(&self, session: &str) -> usize {
        self.session_usage(session).map_or(0, |s| s.fingerprints)
    }
    pub fn literal_len(&self, session: &str) -> usize {
        self.session_usage(session).map_or(0, |s| s.literals)
    }
    pub fn is_incomplete(&self, session: &str) -> bool {
        if session.is_empty() || session.len() > self.limits.max_session_id_bytes {
            return true;
        }
        self.sessions.get(session).map_or_else(
            || self.legacy_unknown_history.load(Ordering::Relaxed),
            |s| s.incomplete.load(Ordering::Relaxed),
        )
    }
    pub fn mark_incomplete(&mut self, session: &str) {
        if self.try_register(session).is_ok() {
            if let Some(entry) = self.sessions.get(session) {
                entry.lose();
            }
        } else {
            self.legacy_unknown_history.store(true, Ordering::Relaxed);
        }
    }
    pub fn is_empty(&self, session: &str) -> bool {
        !self.is_incomplete(session) && self.len(session) == 0 && self.literal_len(session) == 0
    }
}

#[cfg(test)]
mod tests;
