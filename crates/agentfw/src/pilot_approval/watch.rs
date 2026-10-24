use super::{
    approval, escaped, operator_to, read_file, string, Config, OperatorAction, OperatorArgs, Run,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
    time::{Duration, Instant},
};

const MAX_DISPLAY: usize = 16 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_INPUT: usize = 128;

#[cfg(target_os = "linux")]
struct Terminal(std::fs::File);

#[cfg(target_os = "linux")]
impl Write for Terminal {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut offset = 0;
        while offset < bytes.len() {
            let wait = deadline.saturating_duration_since(Instant::now());
            if wait.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "terminal output timed out",
                ));
            }
            let mut fd = libc::pollfd {
                fd: self.0.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut fd, 1, wait.as_millis().min(2000) as i32) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                continue;
            }
            match self.0.write(&bytes[offset..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "terminal closed")),
                Ok(n) => offset += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn terminal() -> Result<impl Write> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open("/proc/self/fd/1")?;
        ensure!(file.is_terminal(), "terminal output unavailable");
        Ok(Terminal(file))
    }
    #[cfg(not(target_os = "linux"))]
    Ok(io::stdout())
}

struct Output<W> {
    writer: W,
    remaining: usize,
}

impl<W: Write> Output<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            remaining: MAX_OUTPUT,
        }
    }
}

impl<W: Write> Write for Output<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_DISPLAY || bytes.len() > self.remaining {
            return Err(io::Error::other(
                "watch output limit reached; no inspection recorded",
            ));
        }
        let written = self.writer.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[derive(Default)]
struct Inbox {
    rows: Vec<Value>,
    inspected: Option<Value>,
}

enum Command {
    Inspect(Value),
    Decide(Value, bool),
    Quit,
    None,
}

impl Inbox {
    fn refresh(&mut self, rows: Vec<Value>) -> Result<()> {
        let inspected = self.inspected.take();
        self.rows.clear();
        ensure!(rows.len() <= 16, "pending list over limit");
        let mut ids = std::collections::BTreeSet::new();
        for row in &rows {
            let identifier = string(row, "pending_id")?;
            super::id(identifier)?;
            ensure!(ids.insert(identifier), "ambiguous pending list");
            ensure!(
                matches!(string(row, "server")?, "filesystem" | "git")
                    && row["state"] == "pending"
                    && string(row, "tool")?.len() <= 1024
                    && string(row, "binding_sha256")?.len() == 64
                    && string(row, "binding_sha256")?
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit())
                    && row["expires_at_ms"].as_u64().is_some(),
                "invalid pending summary"
            );
        }
        self.rows = rows;
        self.inspected = inspected.filter(|row| {
            self.rows.contains(row)
                && row["expires_at_ms"]
                    .as_u64()
                    .is_some_and(|t| t > approval::now_ms())
        });
        Ok(())
    }

    fn command(&mut self, line: &str) -> Command {
        match line {
            "quit" => Command::Quit,
            "approve" | "reject" => {
                let row = self.inspected.take();
                match row.filter(|row| {
                    self.rows.contains(row)
                        && row["expires_at_ms"]
                            .as_u64()
                            .is_some_and(|t| t > approval::now_ms())
                }) {
                    Some(row) => Command::Decide(row, line == "approve"),
                    None => Command::None,
                }
            }
            _ => {
                if let Some(number) = line
                    .strip_prefix("inspect ")
                    .and_then(|v| v.parse::<usize>().ok())
                {
                    self.inspected = None;
                    if let Some(row) = number.checked_sub(1).and_then(|i| self.rows.get(i)) {
                        return Command::Inspect(row.clone());
                    }
                }
                Command::None
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn read_input(input: i32, buffer: &mut Vec<u8>, wait: Duration) -> Result<Option<Option<String>>> {
    let mut fd = libc::pollfd {
        fd: input,
        events: libc::POLLIN,
        revents: 0,
    };
    let status = unsafe { libc::poll(&mut fd, 1, wait.as_millis().min(30_000) as i32) };
    if status < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
        return Ok(None);
    }
    ensure!(status >= 0, "terminal unavailable");
    if status == 0 {
        return Ok(None);
    }
    let mut byte = 0u8;
    let count = unsafe { libc::read(input, (&mut byte as *mut u8).cast(), 1) };
    ensure!(count >= 0, "terminal input unavailable");
    if count == 0 {
        return Ok(Some(None));
    }
    if byte == b'\n' {
        let line = String::from_utf8(std::mem::take(buffer)).context("use ASCII commands")?;
        return Ok(Some(Some(line)));
    }
    ensure!(
        buffer.len() < MAX_INPUT && byte.is_ascii() && !byte.is_ascii_control(),
        "invalid or oversized terminal command"
    );
    buffer.push(byte);
    Ok(None)
}

#[cfg(not(target_os = "linux"))]
fn read_input(
    _input: i32,
    _buffer: &mut Vec<u8>,
    _wait: Duration,
) -> Result<Option<Option<String>>> {
    anyhow::bail!("pilot watch requires Linux")
}

pub(super) fn run(run_id: String, home: Option<PathBuf>, refresh_seconds: u64) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "pilot watch requires Linux");
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "watch requires terminal input and output"
    );
    ensure!(
        (1..=30).contains(&refresh_seconds),
        "refresh must be 1..=30 seconds"
    );
    ensure!(
        run_id.len() == 32 && run_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid pilot run id"
    );
    let home = home
        .map(Ok)
        .unwrap_or_else(Config::home_path)?
        .canonicalize()?;
    let bytes = read_file(
        &home.join("pilot-runs").join(&run_id).join("run.json"),
        true,
    )
    .map_err(|_| anyhow::anyhow!("owned run unavailable"))?;
    let run: Run =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid run metadata"))?;
    let args = |action| OperatorArgs {
        run: run_id.clone(),
        home: Some(home.clone()),
        action,
    };
    let fetch = || -> Result<Vec<Value>> {
        let mut buffer = Vec::new();
        operator_to(
            args(OperatorAction::List),
            &mut Output::new(&mut buffer),
            Some(&bytes),
        )
        .map_err(|_| {
            anyhow::anyhow!("owned run or daemon unavailable; no further decision is possible")
        })?;
        Ok(serde_json::from_slice(&buffer)?)
    };
    let mut inbox = Inbox::default();
    inbox.refresh(fetch()?)?;
    let mut output = Output::new(terminal()?);
    writeln!(
        output,
        "{}",
        escaped(&json!({"run":run_id,"daemon_instance":run.instance_id,
        "registry_sha256":run.registry_sha256, "host_session":run.host_session,
        "profiles":{"filesystem_sha256":run.files[1].sha256,"git_sha256":run.files[2].sha256}}))?
    )?;
    writeln!(
        output,
        "Commands: inspect N, approve, reject, refresh, quit. Each decision needs inspection."
    )?;
    let mut shown = None;
    let mut buffer = Vec::new();
    let interval = Duration::from_secs(refresh_seconds);
    let deadline = Instant::now() + Duration::from_secs(3600);
    let mut next_refresh = Instant::now() + interval;
    loop {
        ensure!(Instant::now() < deadline, "watch time limit reached");
        if shown.as_ref() != Some(&inbox.rows) {
            let rows: Vec<_> = inbox
                .rows
                .iter()
                .enumerate()
                .map(|(i, row)| json!({"number":i+1,"request":row}))
                .collect();
            writeln!(output, "{}", escaped(&json!({"pending":rows}))?)?;
            shown = Some(inbox.rows.clone());
        }
        output.flush()?;
        let input = read_input(
            0,
            &mut buffer,
            next_refresh.saturating_duration_since(Instant::now()),
        )?;
        if Instant::now() >= next_refresh {
            inbox.refresh(fetch()?)?;
            next_refresh = Instant::now() + interval;
        }
        let Some(input) = input else { continue };
        let Some(line) = input else { break };
        if line == "quit" {
            break;
        }
        if line.starts_with("inspect ") && shown.as_ref() != Some(&inbox.rows) {
            inbox.inspected = None;
            writeln!(
                output,
                "List changed. Select a request from the refreshed list."
            )?;
            continue;
        }
        match inbox.command(&line) {
            Command::Quit => break,
            Command::Inspect(row) => {
                let identifier = string(&row, "pending_id")?.to_owned();
                let live = fetch()?;
                if !live.contains(&row) {
                    inbox.refresh(live)?;
                    continue;
                }
                let result = operator_to(
                    args(OperatorAction::Inspect { id: identifier }),
                    &mut output,
                    Some(&bytes),
                );
                if result.is_ok() {
                    inbox.inspected = Some(row);
                    writeln!(output, "Type approve or reject for this inspected binding.")?;
                } else {
                    writeln!(
                        output,
                        "Inspection unavailable or over 16384 bytes. No decision submitted."
                    )?;
                }
            }
            Command::Decide(row, approve) => {
                let live = fetch()?;
                if !live.contains(&row) {
                    inbox.refresh(live)?;
                    writeln!(output, "Request changed or expired. Inspect again.")?;
                    continue;
                }
                let id = string(&row, "pending_id")?.to_owned();
                let binding = string(&row, "binding_sha256")?.to_owned();
                let action = if approve {
                    OperatorAction::Approve { id, binding }
                } else {
                    OperatorAction::Reject { id, binding }
                };
                if operator_to(args(action), &mut output, Some(&bytes)).is_err() {
                    writeln!(
                        output,
                        "Decision outcome unavailable. Inspect current state before retrying."
                    )?;
                }
                inbox.refresh(fetch()?)?;
            }
            Command::None => {
                if line == "refresh" {
                    shown = None;
                } else if !line.is_empty() {
                    writeln!(
                        output,
                        "Use inspect N, then approve or reject; refresh or quit."
                    )?;
                }
            }
        }
    }
    writeln!(output, "Watcher closed.")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row() -> Value {
        json!({"pending_id":"owned", "server":"filesystem", "tool":"read_text_file",
            "binding_sha256":"a".repeat(64), "expires_at_ms":u64::MAX, "state":"pending"})
    }

    #[test]
    fn every_decision_needs_a_new_successful_inspection() {
        let mut inbox = Inbox::default();
        inbox.refresh(vec![row()]).unwrap();
        for word in ["", "approve", "reject", "approve-all", "1", "yes"] {
            assert!(matches!(inbox.command(word), Command::None));
        }
        assert!(matches!(inbox.command("inspect 1"), Command::Inspect(_)));
        assert!(matches!(inbox.command("approve"), Command::None));
        inbox.inspected = Some(row());
        assert!(matches!(inbox.command("approve"), Command::Decide(_, true)));
        assert!(matches!(inbox.command("approve"), Command::None));
        inbox.inspected = Some(row());
        assert!(matches!(inbox.command("reject"), Command::Decide(_, false)));
    }

    #[test]
    fn refresh_invalidates_changed_expired_and_disappeared_requests() {
        for key in [
            "binding_sha256",
            "server",
            "tool",
            "expires_at_ms",
            "pending_id",
        ] {
            let mut inbox = Inbox::default();
            inbox.refresh(vec![row()]).unwrap();
            inbox.inspected = Some(row());
            let mut changed = row();
            changed[key] = if key == "expires_at_ms" {
                json!(0)
            } else {
                json!("changed")
            };
            let _ = inbox.refresh(vec![changed]);
            assert!(matches!(inbox.command("approve"), Command::None), "{key}");
        }
        let mut inbox = Inbox {
            inspected: Some(row()),
            ..Default::default()
        };
        inbox.refresh(vec![]).unwrap();
        assert!(matches!(inbox.command("reject"), Command::None));
    }

    #[test]
    fn refresh_rejects_ambiguous_or_oversized_lists() {
        let mut inbox = Inbox::default();
        assert!(inbox.refresh(vec![row(), row()]).is_err());
        assert!(inbox.refresh(vec![row(); 17]).is_err());
        assert!(inbox.refresh(vec![json!({})]).is_err());
    }

    #[test]
    fn output_is_complete_or_refused_before_any_write() {
        let mut sink = Vec::new();
        let mut out = Output::new(&mut sink);
        assert!(out.write_all(&vec![b'x'; MAX_DISPLAY + 1]).is_err());
        assert_eq!(out.remaining, MAX_OUTPUT);
        out.write_all(b"complete").unwrap();
        assert_eq!(sink, b"complete");
    }

    #[test]
    fn output_escapes_terminal_controls_and_preserves_the_full_json() {
        let original =
            json!({"tool":"quote\"\u{1b}[2J\u{202e}x", "args":{"path":"\n\u{9b}\u{2066}"}});
        let shown = super::super::escaped(&original).unwrap();
        assert!(shown.is_ascii());
        assert!(!shown.contains('\u{1b}') && !shown.contains('\u{7f}'));
        assert_eq!(serde_json::from_str::<Value>(&shown).unwrap(), original);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn eof_and_oversized_input_never_produce_a_decision() {
        use std::os::fd::{AsRawFd, FromRawFd};
        let mut descriptors = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let read = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
        let mut write = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
        let mut buffer = Vec::new();
        assert_eq!(
            read_input(read.as_raw_fd(), &mut buffer, Duration::ZERO).unwrap(),
            None
        );
        write.write_all(b"approve").unwrap();
        drop(write);
        for _ in 0..7 {
            assert_eq!(
                read_input(read.as_raw_fd(), &mut buffer, Duration::ZERO).unwrap(),
                None
            );
        }
        assert_eq!(
            read_input(read.as_raw_fd(), &mut buffer, Duration::ZERO).unwrap(),
            Some(None)
        );
        let mut descriptors = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let read = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
        let mut write = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
        write.write_all(&[b'a'; MAX_INPUT + 1]).unwrap();
        buffer.clear();
        for _ in 0..MAX_INPUT {
            assert!(read_input(read.as_raw_fd(), &mut buffer, Duration::ZERO)
                .unwrap()
                .is_none());
        }
        assert!(read_input(read.as_raw_fd(), &mut buffer, Duration::ZERO).is_err());
    }

    #[test]
    fn failed_inspection_output_does_not_record_a_receipt() {
        let root = tempfile::tempdir().unwrap();
        let receipt = root.path().join("inspected-owned.json");
        let mut sink = Vec::new();
        let mut out = Output::new(&mut sink);
        assert!(super::super::record_inspection(
            root.path(),
            &receipt,
            &json!({}),
            &"x".repeat(MAX_DISPLAY + 1),
            &mut out
        )
        .is_err());
        assert!(!receipt.exists() && sink.is_empty());
    }

    #[test]
    fn watch_cli_rejects_unbounded_refresh_intervals() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            args: OperatorArgs,
        }
        for seconds in ["0", "31", "18446744073709551615"] {
            assert!(Cli::try_parse_from([
                "operator",
                "--run",
                &"a".repeat(32),
                "watch",
                "--refresh-seconds",
                seconds
            ])
            .is_err());
        }
        assert!(Cli::try_parse_from(["operator", "--run", &"a".repeat(32), "watch"]).is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_reused_run_name_cannot_replace_the_pinned_selection() {
        let root = tempfile::tempdir().unwrap();
        super::super::create_dir(&root.path().join("pilot-runs")).unwrap();
        let run = "a".repeat(32);
        let directory = root.path().join("pilot-runs").join(&run);
        super::super::create_dir(&directory).unwrap();
        super::super::write_new(&directory.join("run.json"), &json!({})).unwrap();
        let mut output = Vec::new();
        let error = operator_to(
            OperatorArgs {
                run,
                home: Some(root.path().to_owned()),
                action: OperatorAction::List,
            },
            &mut output,
            Some(b"original-run"),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "pilot run identity changed");
        assert!(output.is_empty());
    }
}
