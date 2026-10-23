// SPDX-License-Identifier: Apache-2.0
//! Bounded selected-server response framing.
//!
//! A frame up to `RESULT_FRAME_BYTES` is buffered and parsed as before. A
//! longer frame is never buffered: its bytes are validated by a constant-memory
//! JSON scanner and discarded until the frame's newline. Only a complete,
//! syntactically valid JSON-RPC response with an unambiguous top-level scalar
//! `id` is reported as `Oversized`, so the relay can withhold it with a
//! correlated error and keep the session. Malformed, unterminated, endless or
//! slow frames return an error and the session fails closed.

use anyhow::{bail, ensure, Context};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::time::Instant;

use crate::mcp::server_profile::{RESULT_DRAIN_BYTES, RESULT_DRAIN_TIME, RESULT_FRAME_BYTES};

pub(super) const DRAIN_BYTES_ERROR: &str = "oversized MCP frame exceeds the drain byte bound";
pub(super) const DRAIN_TIME_ERROR: &str = "oversized MCP frame exceeds the drain time bound";
pub(super) const MALFORMED_ERROR: &str = "oversized MCP frame is malformed";
pub(super) const UNCORRELATED_ERROR: &str = "oversized MCP frame is not a correlatable response";
pub(super) const UNTERMINATED_ERROR: &str = "unterminated MCP frame";

/// Nesting allowed while scanning. Deeper input is refused, so the scanner's
/// memory is a fixed bit stack, not proportional to attacker input.
const MAX_SCAN_DEPTH: usize = 64;
/// A captured top-level `id` (a scalar; `id()` accepts at most 128 bytes).
const MAX_ID_BYTES: usize = 256;

pub(super) struct Oversized {
    pub id: Value,
    pub bytes: usize,
}

pub(super) enum Frame {
    Line(Vec<u8>),
    Oversized(Oversized),
}

struct Drain {
    scanner: Scanner,
    bytes: usize,
    deadline: Instant,
}

pub(super) struct ServerFrames {
    partial: Vec<u8>,
    drain: Option<Drain>,
    drain_time: std::time::Duration,
}

impl Default for ServerFrames {
    fn default() -> Self {
        Self {
            partial: Vec::new(),
            drain: None,
            drain_time: RESULT_DRAIN_TIME,
        }
    }
}

impl ServerFrames {
    /// Cancellation safe: every consumed byte is retained in `self` before
    /// the next await, exactly like the admission line reader.
    pub(super) async fn next<R: AsyncBufRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> anyhow::Result<Option<Frame>> {
        loop {
            let buffer = match &self.drain {
                Some(drain) => tokio::time::timeout_at(drain.deadline, reader.fill_buf())
                    .await
                    .map_err(|_| anyhow::anyhow!(DRAIN_TIME_ERROR))??,
                None => reader.fill_buf().await?,
            };
            if buffer.is_empty() {
                ensure!(
                    self.partial.is_empty() && self.drain.is_none(),
                    UNTERMINATED_ERROR
                );
                return Ok(None);
            }
            let end = buffer
                .iter()
                .position(|b| *b == b'\n')
                .map_or(buffer.len(), |index| index + 1);
            let complete = buffer[end - 1] == b'\n';
            if self.drain.is_none() && self.partial.len() + end <= RESULT_FRAME_BYTES {
                self.partial.extend_from_slice(&buffer[..end]);
                reader.consume(end);
                if complete {
                    return Ok(Some(Frame::Line(std::mem::take(&mut self.partial))));
                }
                continue;
            }
            if self.drain.is_none() {
                let mut scanner = Scanner::default();
                scanner.feed(&self.partial)?;
                let bytes = self.partial.len();
                // Release the bounded prefix; nothing else is retained.
                self.partial = Vec::new();
                self.drain = Some(Drain {
                    scanner,
                    bytes,
                    deadline: Instant::now() + self.drain_time,
                });
            }
            let drain = self.drain.as_mut().expect("active drain");
            drain.bytes += end;
            ensure!(drain.bytes <= RESULT_DRAIN_BYTES, DRAIN_BYTES_ERROR);
            drain.scanner.feed(&buffer[..end])?;
            reader.consume(end);
            if complete {
                let drain = self.drain.take().expect("active drain");
                let id = drain.scanner.finish()?;
                return Ok(Some(Frame::Oversized(Oversized {
                    id,
                    bytes: drain.bytes,
                })));
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Before the top-level value.
    Start,
    /// A value is expected (after `:` or `,` in an array, or `[`).
    Value,
    /// After `[`: a value or `]`.
    ArrayFirst,
    /// After `{`: a key or `}`.
    ObjectFirst,
    /// After `,` in an object: a key.
    Key,
    /// After a key: `:`.
    Colon,
    /// After a complete value inside a container: `,` or the closer.
    After,
    /// Inside a string; `key` marks an object key.
    Str {
        key: bool,
    },
    Escape {
        key: bool,
    },
    /// `\u` escape: remaining hex digits and the accumulated code unit.
    Unicode {
        key: bool,
        left: u8,
        unit: u16,
    },
    /// A high surrogate was decoded; `\` then `u` and a low surrogate must follow.
    LowBackslash {
        key: bool,
    },
    LowU {
        key: bool,
    },
    /// UTF-8 continuation bytes still required and the allowed range of the next one.
    Utf8 {
        key: bool,
        left: u8,
        low: u8,
        high: u8,
    },
    Literal {
        rest: &'static [u8],
    },
    Number(Num),
    /// The top-level value is complete; only whitespace may follow.
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Num {
    Minus,
    Zero,
    Int,
    Dot,
    Frac,
    Exp,
    ExpSign,
    ExpDigits,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TopKey {
    Jsonrpc,
    Id,
    Result,
    Error,
}

/// Constant-memory JSON syntax scanner for one top-level object. It records
/// only which top-level members appeared and the raw bytes of the scalar
/// `jsonrpc` and `id` values. Nested member names are not deduplicated: the
/// whole frame is withheld, so only its framing and top level carry meaning.
#[derive(Debug)]
struct Scanner {
    state: State,
    /// Container kinds, one bit per level (1 = object).
    stack: u64,
    depth: usize,
    /// Pending high surrogate of a `\u` pair.
    high: bool,
    /// Top-level member bookkeeping.
    seen: [bool; 4],
    key: Vec<u8>,
    key_overflow: bool,
    current: Option<TopKey>,
    capture: Option<Vec<u8>>,
    jsonrpc: Option<Vec<u8>>,
    id: Option<Vec<u8>>,
    uncorrelated: bool,
}

impl Default for Scanner {
    fn default() -> Self {
        Self {
            state: State::Start,
            stack: 0,
            depth: 0,
            high: false,
            seen: [false; 4],
            key: Vec::new(),
            key_overflow: false,
            current: None,
            capture: None,
            jsonrpc: None,
            id: None,
            uncorrelated: false,
        }
    }
}

fn whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

impl Scanner {
    fn feed(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        for &byte in bytes {
            self.byte(byte).context(MALFORMED_ERROR)?;
        }
        Ok(())
    }

    fn in_object(&self) -> bool {
        self.depth > 0 && self.stack & (1 << (self.depth - 1)) != 0
    }

    /// The value now starting is a direct member of the top-level object.
    fn top_member(&self) -> bool {
        self.depth == 1 && self.in_object()
    }

    fn push(&mut self, object: bool) -> anyhow::Result<()> {
        ensure!(self.depth < MAX_SCAN_DEPTH, "scan depth");
        if self.depth == 0 {
            ensure!(object, "top-level value is not an object");
        }
        if self.top_member() && matches!(self.current, Some(TopKey::Jsonrpc | TopKey::Id)) {
            // A container `id` or `jsonrpc` can never correlate a response.
            self.uncorrelated = true;
        }
        if object {
            self.stack |= 1 << self.depth;
        } else {
            self.stack &= !(1 << self.depth);
        }
        self.depth += 1;
        self.state = if object {
            State::ObjectFirst
        } else {
            State::ArrayFirst
        };
        Ok(())
    }

    fn pop(&mut self, object: bool) -> anyhow::Result<()> {
        ensure!(
            self.depth > 0 && self.in_object() == object,
            "mismatched closer"
        );
        self.depth -= 1;
        self.state = if self.depth == 0 {
            State::Done
        } else {
            State::After
        };
        Ok(())
    }

    fn capture(&mut self, byte: u8) {
        if let Some(capture) = &mut self.capture {
            if capture.len() < MAX_ID_BYTES {
                capture.push(byte);
            } else {
                self.uncorrelated = true;
            }
        }
    }

    /// A scalar value starts at the current position.
    fn begin_scalar(&mut self, byte: u8) {
        if self.top_member() && matches!(self.current, Some(TopKey::Jsonrpc | TopKey::Id)) {
            self.capture = Some(Vec::new());
            self.capture(byte);
        }
    }

    fn end_value(&mut self) -> anyhow::Result<()> {
        if let Some(capture) = self.capture.take() {
            match self.current {
                Some(TopKey::Jsonrpc) => self.jsonrpc = Some(capture),
                Some(TopKey::Id) => self.id = Some(capture),
                _ => {}
            }
        }
        self.state = if self.depth == 0 {
            State::Done
        } else {
            State::After
        };
        Ok(())
    }

    fn end_key(&mut self) -> anyhow::Result<()> {
        if self.depth == 1 {
            let key = match (self.key_overflow, self.key.as_slice()) {
                (false, b"jsonrpc") => TopKey::Jsonrpc,
                (false, b"id") => TopKey::Id,
                (false, b"result") => TopKey::Result,
                (false, b"error") => TopKey::Error,
                // The ordinary parser refuses any other top-level member.
                _ => bail!("unsupported top-level member"),
            };
            let index = key as usize;
            ensure!(!self.seen[index], "duplicate top-level member");
            self.seen[index] = true;
            self.current = Some(key);
        }
        self.key.clear();
        self.key_overflow = false;
        self.state = State::Colon;
        Ok(())
    }

    fn key_byte(&mut self, key: bool, byte: u8) {
        if key && self.depth == 1 {
            if self.key.len() < 16 {
                self.key.push(byte);
            } else {
                self.key_overflow = true;
            }
        }
    }

    fn value_start(&mut self, byte: u8) -> anyhow::Result<()> {
        match byte {
            b'{' => self.push(true),
            b'[' => self.push(false),
            b'"' => {
                self.begin_scalar(byte);
                self.state = State::Str { key: false };
                Ok(())
            }
            b't' | b'f' | b'n' => {
                self.begin_scalar(byte);
                self.state = State::Literal {
                    rest: match byte {
                        b't' => b"rue",
                        b'f' => b"alse",
                        _ => b"ull",
                    },
                };
                Ok(())
            }
            b'-' | b'0'..=b'9' => {
                ensure!(self.depth > 0, "top-level value is not an object");
                self.begin_scalar(byte);
                self.state = State::Number(match byte {
                    b'-' => Num::Minus,
                    b'0' => Num::Zero,
                    _ => Num::Int,
                });
                Ok(())
            }
            _ => bail!("unexpected value byte"),
        }
    }

    fn byte(&mut self, byte: u8) -> anyhow::Result<()> {
        match self.state {
            State::Start => {
                if !whitespace(byte) {
                    ensure!(byte == b'{', "top-level value is not an object");
                    self.push(true)?;
                }
            }
            State::Done => ensure!(whitespace(byte), "trailing bytes after the frame value"),
            State::Value => {
                if !whitespace(byte) {
                    self.value_start(byte)?;
                }
            }
            State::ArrayFirst => {
                if byte == b']' {
                    self.pop(false)?;
                } else if !whitespace(byte) {
                    self.value_start(byte)?;
                }
            }
            State::ObjectFirst | State::Key => {
                if byte == b'}' && self.state == State::ObjectFirst {
                    self.pop(true)?;
                } else if byte == b'"' {
                    self.state = State::Str { key: true };
                } else {
                    ensure!(whitespace(byte), "expected an object key");
                }
            }
            State::Colon => {
                if byte == b':' {
                    self.state = State::Value;
                } else {
                    ensure!(whitespace(byte), "expected a colon");
                }
            }
            State::After => match byte {
                b',' => {
                    self.state = if self.in_object() {
                        State::Key
                    } else {
                        State::Value
                    };
                }
                b'}' => self.pop(true)?,
                b']' => self.pop(false)?,
                _ => ensure!(whitespace(byte), "expected a separator"),
            },
            State::Str { key } => {
                ensure!(!self.high, "unpaired high surrogate");
                if !key {
                    self.capture(byte);
                }
                match byte {
                    b'"' => {
                        if key {
                            self.end_key()?;
                        } else {
                            self.end_value()?;
                        }
                    }
                    b'\\' => self.state = State::Escape { key },
                    0x00..=0x1f => bail!("control byte in string"),
                    0x20..=0x7f => self.key_byte(key, byte),
                    0xc2..=0xdf => self.utf8(key, byte, 1, 0x80, 0xbf),
                    0xe0 => self.utf8(key, byte, 2, 0xa0, 0xbf),
                    0xe1..=0xec | 0xee..=0xef => self.utf8(key, byte, 2, 0x80, 0xbf),
                    0xed => self.utf8(key, byte, 2, 0x80, 0x9f),
                    0xf0 => self.utf8(key, byte, 3, 0x90, 0xbf),
                    0xf1..=0xf3 => self.utf8(key, byte, 3, 0x80, 0xbf),
                    0xf4 => self.utf8(key, byte, 3, 0x80, 0x8f),
                    _ => bail!("invalid UTF-8"),
                }
            }
            State::Utf8 {
                key,
                left,
                low,
                high,
            } => {
                ensure!((low..=high).contains(&byte), "invalid UTF-8");
                self.key_byte(key, byte);
                if !key {
                    self.capture(byte);
                }
                self.state = if left == 1 {
                    State::Str { key }
                } else {
                    State::Utf8 {
                        key,
                        left: left - 1,
                        low: 0x80,
                        high: 0xbf,
                    }
                };
            }
            State::Escape { key } => {
                if !key {
                    self.capture(byte);
                }
                // Escaped key bytes never equal a supported top-level name.
                self.key_byte(key, b'\\');
                self.state = match byte {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                        ensure!(!self.high, "unpaired high surrogate");
                        State::Str { key }
                    }
                    b'u' => State::Unicode {
                        key,
                        left: 4,
                        unit: 0,
                    },
                    _ => bail!("invalid escape"),
                };
            }
            State::Unicode { key, left, unit } => {
                if !key {
                    self.capture(byte);
                }
                let digit = (byte as char)
                    .to_digit(16)
                    .context("invalid unicode escape")? as u16;
                let unit = (unit << 4) | digit;
                if left > 1 {
                    self.state = State::Unicode {
                        key,
                        left: left - 1,
                        unit,
                    };
                } else if self.high {
                    ensure!((0xdc00..=0xdfff).contains(&unit), "unpaired high surrogate");
                    self.high = false;
                    self.state = State::Str { key };
                } else if (0xd800..=0xdbff).contains(&unit) {
                    self.high = true;
                    self.state = State::LowBackslash { key };
                } else {
                    ensure!(!(0xdc00..=0xdfff).contains(&unit), "lone low surrogate");
                    self.state = State::Str { key };
                }
            }
            State::LowBackslash { key } => {
                ensure!(byte == b'\\', "unpaired high surrogate");
                if !key {
                    self.capture(byte);
                }
                self.state = State::LowU { key };
            }
            State::LowU { key } => {
                ensure!(byte == b'u', "unpaired high surrogate");
                if !key {
                    self.capture(byte);
                }
                self.state = State::Unicode {
                    key,
                    left: 4,
                    unit: 0,
                };
            }
            State::Literal { rest } => {
                ensure!(rest.first() == Some(&byte), "invalid literal");
                self.capture(byte);
                if rest.len() == 1 {
                    self.end_value()?;
                } else {
                    self.state = State::Literal { rest: &rest[1..] };
                }
            }
            State::Number(num) => {
                let next = match (num, byte) {
                    (Num::Minus, b'0') => Some(Num::Zero),
                    (Num::Minus, b'1'..=b'9') => Some(Num::Int),
                    (Num::Int, b'0'..=b'9') => Some(Num::Int),
                    (Num::Zero | Num::Int, b'.') => Some(Num::Dot),
                    (Num::Dot | Num::Frac, b'0'..=b'9') => Some(Num::Frac),
                    (Num::Zero | Num::Int | Num::Frac, b'e' | b'E') => Some(Num::Exp),
                    (Num::Exp, b'+' | b'-') => Some(Num::ExpSign),
                    (Num::Exp | Num::ExpSign | Num::ExpDigits, b'0'..=b'9') => Some(Num::ExpDigits),
                    _ => None,
                };
                match next {
                    Some(next) => {
                        self.capture(byte);
                        self.state = State::Number(next);
                    }
                    None => {
                        ensure!(
                            matches!(num, Num::Zero | Num::Int | Num::Frac | Num::ExpDigits),
                            "incomplete number"
                        );
                        self.end_value()?;
                        // The delimiter belongs to the enclosing container.
                        self.byte(byte)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn utf8(&mut self, key: bool, byte: u8, left: u8, low: u8, high: u8) {
        self.key_byte(key, byte);
        self.state = State::Utf8 {
            key,
            left,
            low,
            high,
        };
    }

    /// The scalar ID of a complete, well-formed JSON-RPC response.
    fn finish(self) -> anyhow::Result<Value> {
        ensure!(self.state == State::Done, MALFORMED_ERROR);
        let [jsonrpc, id, result, error] = self.seen;
        ensure!(
            !self.uncorrelated && jsonrpc && id && (result ^ error),
            UNCORRELATED_ERROR
        );
        ensure!(
            self.jsonrpc.as_deref() == Some(b"\"2.0\""),
            UNCORRELATED_ERROR
        );
        let raw = self.id.context(UNCORRELATED_ERROR)?;
        let value: Value = serde_json::from_slice(&raw).context(UNCORRELATED_ERROR)?;
        ensure!(value.is_string() || value.is_i64(), UNCORRELATED_ERROR);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scan(bytes: &[u8]) -> anyhow::Result<Value> {
        let mut scanner = Scanner::default();
        scanner.feed(bytes)?;
        scanner.finish()
    }

    /// Feeding in arbitrary chunks yields the same verdict as one feed.
    fn scan_chunked(bytes: &[u8], size: usize) -> anyhow::Result<Value> {
        let mut scanner = Scanner::default();
        for chunk in bytes.chunks(size.max(1)) {
            scanner.feed(chunk)?;
        }
        scanner.finish()
    }

    #[test]
    fn scanner_accepts_serialized_responses_and_extracts_only_the_top_level_id() {
        let text = "line \"quoted\" \\ back/slash \t tab \u{1F963} кириллица 日本語 \u{0} \u{1f}\n";
        for id in [json!(7), json!(-3), json!("call-1"), json!("ид\u{1F963}")] {
            for value in [
                json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":text}],
                    "structuredContent":{"content":text,"id":"nested-is-ignored"},"isError":false}}),
                json!({"result":{"content":[],"n":[1,-0.5,2e10,0,1E-3,true,false,null,[],{}]},"id":id,"jsonrpc":"2.0"}),
                json!({"jsonrpc":"2.0","error":{"code":-32603,"message":"x"},"id":id}),
            ] {
                let mut raw = value.to_string().into_bytes();
                raw.push(b'\n');
                assert_eq!(scan(&raw).unwrap(), id);
                for size in [1, 2, 3, 7, 64] {
                    assert_eq!(scan_chunked(&raw, size).unwrap(), id);
                }
                let pretty = serde_json::to_vec_pretty(&value).unwrap();
                assert_eq!(scan(&pretty).unwrap(), id);
            }
        }
        // Escaped surrogate pairs and other escapes are valid syntax.
        assert_eq!(
            scan(br#"{"jsonrpc":"2.0","id":"\ud83e\udd63\u00e9\n","result":{}}"#).unwrap(),
            json!("\u{1F963}\u{e9}\n")
        );
    }

    #[test]
    fn scanner_refuses_malformed_uncorrelatable_or_ambiguous_frames() {
        let malformed: &[&[u8]] = &[
            b"",
            b"[]",
            b"\"text\"",
            b"7",
            b"{",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}} {}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{},}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[1,]}",
            b"{\"jsonrpc\":\"2.0\",\"id\":01,\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1.,\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":-,\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1e,\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":tru}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":nul}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\x01\"}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\\x\"}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\\u12g4\"}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\\ud800\"}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\\udc00\"}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\\ud800\\u0041\"}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\xff\"}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\xc0\xaf\"}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\xed\xa0\x80\"}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\xe2\x82\"}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\xc3\xa9}",
            b"{\"jsonrpc\":\"2.0\" \"id\":1,\"result\":{}}",
            b"{\"jsonrpc\" \"2.0\",\"id\":1,\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{]}",
            b"{'jsonrpc':'2.0'}",
        ];
        for raw in malformed {
            assert!(
                scan(raw).is_err(),
                "accepted malformed {:?}",
                String::from_utf8_lossy(raw)
            );
            assert!(
                serde_json::from_slice::<Value>(raw).is_err() || !raw.starts_with(b"{"),
                "fixture is valid JSON: {:?}",
                String::from_utf8_lossy(raw)
            );
        }
        let uncorrelated: &[&[u8]] = &[
            b"{\"jsonrpc\":\"2.0\",\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{},\"error\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":2,\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":[1],\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":{\"x\":1},\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":null,\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":true,\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1.5,\"result\":{}}",
            b"{\"jsonrpc\":\"1.0\",\"id\":1,\"result\":{}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{},\"extra\":1}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{},\"j\\u0073onrpc\":1}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{}}",
        ];
        for raw in uncorrelated {
            assert!(
                scan(raw).is_err(),
                "correlated {:?}",
                String::from_utf8_lossy(raw)
            );
        }
        let long = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":\"{}\",\"result\":{{}}}}",
            "x".repeat(MAX_ID_BYTES)
        );
        assert!(scan(long.as_bytes()).is_err());
        let deep = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}{}}}",
            "[".repeat(MAX_SCAN_DEPTH),
            "]".repeat(MAX_SCAN_DEPTH)
        );
        assert!(scan(deep.as_bytes()).is_err());
    }

    #[test]
    fn scanner_never_accepts_what_the_strict_parser_refuses() {
        // Deterministic mutation sweep: one-byte edits of a valid frame.
        let base = json!({"jsonrpc":"2.0","id":"m","result":{"content":[{"type":"text",
            "text":"a\"b\\c\u{e9}\u{1F963}"}],"structuredContent":{"content":"x"},"n":[-1.5e3,0,true,null]}})
        .to_string()
        .into_bytes();
        let replacements = [
            b'{', b'}', b'[', b']', b'"', b'\\', b',', b':', b' ', b'0', b'-', b'e', b'.', b'u',
            b'x', 0x00, 0x1f, 0x80, 0xc3, 0xff,
        ];
        for index in 0..base.len() {
            for replacement in replacements {
                let mut raw = base.clone();
                raw[index] = replacement;
                if let Ok(id) = scan(&raw) {
                    let parsed: Value = serde_json::from_slice(&raw)
                        .unwrap_or_else(|_| panic!("scanner accepted invalid JSON at {index}"));
                    assert_eq!(parsed["id"], id);
                }
            }
            let mut removed = base.clone();
            removed.remove(index);
            if let Ok(id) = scan(&removed) {
                let parsed: Value = serde_json::from_slice(&removed)
                    .unwrap_or_else(|_| panic!("scanner accepted invalid JSON without {index}"));
                assert_eq!(parsed["id"], id);
            }
        }
    }

    async fn frames(input: Vec<u8>) -> Vec<anyhow::Result<Option<Frame>>> {
        let mut reader = tokio::io::BufReader::with_capacity(4096, std::io::Cursor::new(input));
        let mut state = ServerFrames::default();
        let mut out = Vec::new();
        loop {
            let next = state.next(&mut reader).await;
            let stop = !matches!(next, Ok(Some(_)));
            out.push(next);
            if stop {
                return out;
            }
        }
    }

    fn split(id: &Value, first: usize, second: usize) -> Vec<u8> {
        let mut raw = json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"q".repeat(first)}],
            "structuredContent":{"content":"q".repeat(second)}}})
        .to_string()
        .into_bytes();
        raw.push(b'\n');
        raw
    }

    fn response(id: Value, text_bytes: usize) -> Vec<u8> {
        split(&id, text_bytes, text_bytes)
    }

    /// A valid response line of exactly `total` bytes, newline included.
    fn sized(id: Value, total: usize) -> Vec<u8> {
        let text = total - split(&id, 0, 0).len();
        let raw = split(&id, text / 2, text - text / 2);
        assert_eq!(raw.len(), total);
        raw
    }

    #[tokio::test]
    async fn reader_buffers_up_to_the_envelope_budget_and_drains_larger_frames() {
        let at = sized(json!(1), RESULT_FRAME_BYTES);
        let above = sized(json!(1), RESULT_FRAME_BYTES + 1);
        let big = response(json!("big"), 2 * 1024 * 1024);
        let mut input = at.clone();
        input.extend_from_slice(&above);
        input.extend_from_slice(&big);
        input.extend_from_slice(&response(json!(9), 3));
        let out = frames(input).await;
        assert_eq!(out.len(), 5);
        assert!(matches!(&out[0], Ok(Some(Frame::Line(raw))) if *raw == at));
        assert!(
            matches!(&out[1], Ok(Some(Frame::Oversized(o))) if o.id == json!(1) && o.bytes == RESULT_FRAME_BYTES + 1)
        );
        assert!(
            matches!(&out[2], Ok(Some(Frame::Oversized(o))) if o.id == json!("big") && o.bytes == big.len())
        );
        assert!(matches!(&out[3], Ok(Some(Frame::Line(raw))) if raw.ends_with(b"}}\n")));
        assert!(matches!(&out[4], Ok(None)));
    }

    #[tokio::test]
    async fn reader_fails_closed_on_malformed_unterminated_or_endless_oversized_frames() {
        let mut malformed = response(json!(1), RESULT_FRAME_BYTES);
        // Inside the first text, past the buffered envelope budget.
        let inside = RESULT_FRAME_BYTES - 7;
        assert_eq!(malformed[inside], b'q');
        malformed[inside] = b'"';
        let out = frames(malformed).await;
        let last = out.last().unwrap().as_ref().err().map(ToString::to_string);
        assert_eq!(last.as_deref(), Some(MALFORMED_ERROR));

        let mut unterminated = response(json!(1), RESULT_FRAME_BYTES);
        unterminated.pop();
        let out = frames(unterminated).await;
        assert!(out
            .last()
            .unwrap()
            .as_ref()
            .is_err_and(|e| e.to_string() == UNTERMINATED_ERROR));

        // A well-formed string that never ends: refused at the byte bound,
        // without buffering it.
        let mut endless = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"".to_vec();
        endless.resize(RESULT_DRAIN_BYTES + 4096, b'q');
        let out = frames(endless).await;
        assert!(out
            .last()
            .unwrap()
            .as_ref()
            .is_err_and(|e| e.to_string() == DRAIN_BYTES_ERROR));

        let uncorrelated = {
            let text = "q".repeat(RESULT_FRAME_BYTES);
            let mut raw =
                json!({"jsonrpc":"2.0","method":"notifications/message","params":{"data":text}})
                    .to_string()
                    .into_bytes();
            raw.push(b'\n');
            raw
        };
        let out = frames(uncorrelated).await;
        assert!(out.last().unwrap().as_ref().is_err_and(
            |e| e.to_string() == MALFORMED_ERROR || e.to_string() == UNCORRELATED_ERROR
        ));
    }

    #[tokio::test]
    async fn reader_drain_is_bounded_in_time_for_a_stalled_oversized_frame() {
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);
        let mut reader = tokio::io::BufReader::new(reader);
        let task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            writer
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"")
                .await
                .unwrap();
            let chunk = vec![b'q'; 64 * 1024];
            for _ in 0..=RESULT_FRAME_BYTES / chunk.len() {
                writer.write_all(&chunk).await.unwrap();
            }
            // Stall with the frame open; keep the writer alive.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            drop(writer);
        });
        let mut state = ServerFrames {
            drain_time: std::time::Duration::from_millis(300),
            ..ServerFrames::default()
        };
        let started = std::time::Instant::now();
        let error = state.next(&mut reader).await.err().expect("drain timeout");
        assert_eq!(error.to_string(), DRAIN_TIME_ERROR);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        task.abort();
    }
}
