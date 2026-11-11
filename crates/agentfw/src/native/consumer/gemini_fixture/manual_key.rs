// SPDX-License-Identifier: Apache-2.0
//! Manual operator input only. Never read a key from stdin, argv or environment.
use anyhow::{bail, ensure, Result};
use std::io::Read;
use zeroize::Zeroizing;

fn read_key(input: &mut impl Read) -> Result<Zeroizing<String>> {
    // Reserve the whole bounded input so growing it never leaves old allocations.
    let mut key = Zeroizing::new(String::with_capacity(256));
    let mut byte = Zeroizing::new([0_u8; 1]);
    loop {
        input
            .read_exact(&mut *byte)
            .map_err(|_| anyhow::anyhow!("gemini_key_input_cancelled"))?;
        match byte[0] {
            b'\r' | b'\n' => {
                let trimmed = key.trim_matches([' ', '\t']);
                ensure!(trimmed.len() >= 20, "gemini_key_too_short");
                ensure!(
                    trimmed
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.'),
                    "gemini_key_shape"
                );
                return Ok(Zeroizing::new(trimmed.to_owned()));
            }
            3 | 4 => bail!("gemini_key_input_cancelled"),
            27 => {
                let mut sequence = Zeroizing::new([0_u8; 5]);
                input
                    .read_exact(&mut *sequence)
                    .map_err(|_| anyhow::anyhow!("gemini_key_escape_sequence"))?;
                ensure!(
                    &*sequence == b"[200~" || &*sequence == b"[201~",
                    "gemini_key_escape_sequence"
                );
            }
            22 => bail!("gemini_key_paste_shortcut"),
            8 | 127 => {
                key.pop();
            }
            c if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.' => {
                ensure!(key.len() < 256, "gemini_key_input_limit");
                key.push(char::from(c));
            }
            c if !c.is_ascii() => bail!("gemini_key_non_ascii"),
            b' ' | b'\t' => {
                ensure!(key.len() < 256, "gemini_key_input_limit");
                key.push(char::from(byte[0]));
            }
            c if c.is_ascii_control() => bail!("gemini_key_control"),
            b'"' | b'\'' | b'`' => bail!("gemini_key_quotes"),
            b':' | b'/' | b'\\' => bail!("gemini_key_path_punctuation"),
            _ => bail!("gemini_key_punctuation"),
        }
    }
}

/// Fixed allowlisted messages only: never expose library errors or input bytes.
pub(super) fn input_diagnostic(error: &anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "gemini_operator_confirmation" => "Confirmation text did not match. No API access occurred. Paste the complete RUN confirmation line and press Enter.",
        "gemini_key_too_short" => "Hidden input rejected before API access: fewer than 20 characters. Copy the FULL key with the AI Studio copy button; hidden input is not displayed.",
        "gemini_key_paste_shortcut" => "Hidden input rejected before API access: terminal sent Ctrl-V as a control byte, not pasted text. Use the terminal's Paste command.",
        "gemini_key_escape_sequence" => "Hidden input cancelled before API access: Escape or a terminal escape sequence was received (for example a paste wrapper). Do not keep retrying the real key; report this message.",
        "gemini_key_non_ascii" => "Hidden input rejected before API access: non-ASCII input. Check the English keyboard layout and copy only the full API key.",
        "gemini_key_whitespace" => "Hidden input rejected before API access: space or tab received. Copy only the full key with the AI Studio copy button.",
        "gemini_key_control" => "Hidden input rejected before API access: terminal control character received. Report this message; do not retry the real key.",
        "gemini_key_quotes" => "Hidden input rejected before API access: quote or backtick received. Use the key copy button, without surrounding formatting.",
        "gemini_key_path_punctuation" => "Hidden input rejected before API access: colon or slash received. Check that you copied the key rather than a URL or command.",
        "gemini_key_punctuation" => "Hidden input rejected before API access: unsupported printable punctuation received. The key value was not displayed or stored.",
        "gemini_key_shape" => "Hidden input rejected before API access: unsupported character or control byte. Copy only the full API key, without quotes, spaces or formatting.",
        "gemini_key_input_limit" => "Hidden input rejected before API access: input exceeds 256 characters. Do not paste a command, link or message.",
        "gemini_key_input_cancelled" => "Hidden input cancelled before API access (Ctrl-C, Ctrl-D or terminal input ended).",
        "gemini_terminal_mode" | "gemini_terminal_restore" | "gemini_operator_terminal_required" => "Hidden terminal setup/restoration failed before API access. Do not enter the key; report this message.",
        _ => "Operator run refused or stopped; inspect the private journal. Never replay an uncertain attempt.",
    }
}

#[test]
fn gemini_manual_key_input_diagnostics_never_echo_input() {
    for (bytes, code) in [
        (b"\x16".as_slice(), "gemini_key_paste_shortcut"),
        ("тест\n".as_bytes(), "gemini_key_non_ascii"),
        (b"short\n".as_slice(), "gemini_key_too_short"),
        (b"\0".as_slice(), "gemini_key_control"),
        (b"\x1a".as_slice(), "gemini_key_control"),
        (b"\"".as_slice(), "gemini_key_quotes"),
        (b"https:".as_slice(), "gemini_key_path_punctuation"),
        (b"@".as_slice(), "gemini_key_punctuation"),
        (b"\x03".as_slice(), "gemini_key_input_cancelled"),
    ] {
        let mut input = bytes;
        let error = read_key(&mut input).unwrap_err();
        assert_eq!(error.to_string(), code);
        assert!(input_diagnostic(&error).contains("before API access"));
        assert!(!input_diagnostic(&error).contains("synthetic_paste_only"));
    }
    for bytes in [
        b" \tsynthetic_manual_key_only\t \n".as_slice(),
        b"\x1b[200~synthetic_manual_key_only\x1b[201~\n".as_slice(),
    ] {
        assert_eq!(
            &*read_key(&mut &*bytes).unwrap(),
            "synthetic_manual_key_only"
        );
    }
    assert!(read_key(&mut b"synthetic manual_key_only\n".as_slice()).is_err());
    let dotted = b"AQ.synthetic_key.for_offline_test_123456\n";
    assert_eq!(
        &*read_key(&mut dotted.as_slice()).unwrap(),
        "AQ.synthetic_key.for_offline_test_123456"
    );
    assert!(super::Key::new("AQ.synthetic_key.for_offline_test_123456".to_owned()).is_ok());
    let canary = "synthetic_secret_do_not_echo";
    assert!(!input_diagnostic(&anyhow::anyhow!(canary)).contains(canary));
    assert!(
        input_diagnostic(&anyhow::anyhow!("wrapped: gemini_key_shape"))
            .starts_with("Operator run refused")
    );
}

#[cfg(target_os = "linux")]
pub(super) fn prompt() -> Result<Zeroizing<String>> {
    use std::io::{IsTerminal, Write};
    use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/tty")
        .map_err(|_| anyhow::anyhow!("gemini_operator_terminal_required"))?;
    ensure!(tty.is_terminal(), "gemini_operator_terminal_required");
    let mut guard = Terminal::hide(tty.as_raw_fd())?;
    let result = (|| {
        tty.write_all(b"Gemini API key (hidden; Enter to accept, Ctrl-C to cancel): ")?;
        tty.flush()?;
        read_key(&mut EscapeBoundedInput {
            input: &mut tty,
            remaining: 0,
        })
    })();
    // Flush unread pasted bytes while restoring the terminal, including errors.
    guard.restore()?;
    tty.write_all(b"\n")?;
    result
}

// Wait indefinitely for ordinary human input, but bound incomplete paste wrappers.
// A lone Escape must not strand the terminal in hidden noncanonical mode.
#[cfg(target_os = "linux")]
struct EscapeBoundedInput<'a> {
    input: &'a mut std::fs::File,
    remaining: usize,
}
#[cfg(target_os = "linux")]
impl Read for EscapeBoundedInput<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        if self.remaining > 0 {
            let mut descriptor = libc::pollfd {
                fd: self.input.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one initialized pollfd borrowing a live file descriptor.
            if unsafe { libc::poll(&mut descriptor, 1, 250) } <= 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
        }
        let read = self.input.read(buffer)?;
        if self.remaining == 0 && read == 1 && buffer[0] == 27 {
            self.remaining = 5;
        } else {
            self.remaining = self.remaining.saturating_sub(read);
        }
        Ok(read)
    }
}

#[cfg(target_os = "linux")]
struct Terminal {
    fd: std::os::fd::RawFd,
    original: libc::termios,
    active: bool,
}

#[cfg(target_os = "linux")]
impl Terminal {
    fn hide(fd: std::os::fd::RawFd) -> Result<Self> {
        let mut original = std::mem::MaybeUninit::uninit();
        // SAFETY: tcgetattr initializes this termios only on success; fd remains
        // owned by the caller for the guard's entire lifetime.
        ensure!(
            unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } == 0,
            "gemini_terminal_mode"
        );
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
        hidden.c_iflag &= !(libc::IXON | libc::ICRNL | libc::INLCR | libc::IGNCR);
        hidden.c_cc[libc::VMIN] = 1;
        hidden.c_cc[libc::VTIME] = 0;
        let mut guard = Self {
            fd,
            original,
            active: true,
        };
        // SAFETY: initialized termios and live terminal fd. Guard restores even
        // when setting the new mode fails. Ctrl-C is read as a cancellation byte.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &hidden) } != 0 {
            let _ = guard.restore();
            bail!("gemini_terminal_mode");
        }
        Ok(guard)
    }

    fn restore(&mut self) -> Result<()> {
        if self.active {
            // SAFETY: caller keeps the terminal open until this guard is dropped.
            ensure!(
                unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) } == 0,
                "gemini_terminal_restore"
            );
            self.active = false;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[test]
fn gemini_manual_key_bounded_edit_cancel_and_static_errors() {
    let sample = "synthetic_manual_key_only";
    let mut edited = format!("{sample}x\u{7f}\n").into_bytes();
    assert_eq!(&*read_key(&mut edited.as_slice()).unwrap(), sample);
    for suffix in [vec![3], vec![4], vec![27], vec![], vec![b' '], vec![255]] {
        edited = sample.as_bytes().iter().copied().chain(suffix).collect();
        let error = read_key(&mut edited.as_slice()).unwrap_err().to_string();
        assert!(!error.contains(sample));
        assert!(error.starts_with("gemini_key_"));
    }
    assert!(read_key(&mut b"short\n".as_slice()).is_err());
    assert!(read_key(&mut format!("{}\n", "x".repeat(256)).as_bytes()).is_ok());
    assert!(read_key(&mut format!("{}\n", "x".repeat(257)).as_bytes()).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn gemini_manual_key_terminal_hides_and_restores_on_cancel() {
    // Keep the planned test-only entry compiled without prompting for a real
    // credential in an unattended test. Actual input below remains synthetic.
    let _interactive_entry = super::controller::runner::Controller::open_interactive;
    use std::os::fd::{AsRawFd, FromRawFd};
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: valid output pointers; no optional name/termios/winsize supplied.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let (_master, _slave) = unsafe {
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    };
    let state = || {
        let mut mode = std::mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(_slave.as_raw_fd(), mode.as_mut_ptr()) },
            0
        );
        unsafe { mode.assume_init() }
    };
    let before = state();
    {
        let _guard = Terminal::hide(slave).unwrap();
        let hidden = state();
        assert_eq!(
            hidden.c_lflag & (libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG),
            0
        );
        assert!(read_key(&mut b"partial\x03".as_slice()).is_err());
        use std::io::Write;
        let mut writer = &_master;
        writer.write_all(b"\x1b").unwrap();
        let mut reader = _slave.try_clone().unwrap();
        let started = std::time::Instant::now();
        let error = read_key(&mut EscapeBoundedInput {
            input: &mut reader,
            remaining: 0,
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "gemini_key_escape_sequence");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
    let after = state();
    assert_eq!(before.c_lflag, after.c_lflag);
    assert_eq!(before.c_iflag, after.c_iflag);
    assert_eq!(before.c_cc, after.c_cc);
}
