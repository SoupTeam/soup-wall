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
                ensure!(key.len() >= 20, "gemini_key_too_short");
                return Ok(key);
            }
            3 | 4 => bail!("gemini_key_input_cancelled"),
            27 => bail!("gemini_key_escape_sequence"),
            22 => bail!("gemini_key_paste_shortcut"),
            8 | 127 => {
                key.pop();
            }
            c if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' => {
                ensure!(key.len() < 256, "gemini_key_input_limit");
                key.push(char::from(c));
            }
            c if !c.is_ascii() => bail!("gemini_key_non_ascii"),
            _ => bail!("gemini_key_shape"),
        }
    }
}

/// Fixed allowlisted messages only: never expose library errors or input bytes.
pub(super) fn input_diagnostic(error: &anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "gemini_key_too_short" => "Hidden input rejected before API access: fewer than 20 characters. Copy the FULL key with the AI Studio copy button; hidden input is not displayed.",
        "gemini_key_paste_shortcut" => "Hidden input rejected before API access: terminal sent Ctrl-V as a control byte, not pasted text. Use the terminal's Paste command.",
        "gemini_key_escape_sequence" => "Hidden input cancelled before API access: Escape or a terminal escape sequence was received (for example a paste wrapper). Do not keep retrying the real key; report this message.",
        "gemini_key_non_ascii" => "Hidden input rejected before API access: non-ASCII input. Check the English keyboard layout and copy only the full API key.",
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
        (
            b"\x1b[200~synthetic_paste_only_123456\x1b[201~\n".as_slice(),
            "gemini_key_escape_sequence",
        ),
        ("тест\n".as_bytes(), "gemini_key_non_ascii"),
        (b"short\n".as_slice(), "gemini_key_too_short"),
        (b"\x03".as_slice(), "gemini_key_input_cancelled"),
    ] {
        let mut input = bytes;
        let error = read_key(&mut input).unwrap_err();
        assert_eq!(error.to_string(), code);
        assert!(input_diagnostic(&error).contains("before API access"));
        assert!(!input_diagnostic(&error).contains("synthetic_paste_only"));
    }
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
        read_key(&mut tty)
    })();
    // Flush unread pasted bytes while restoring the terminal, including errors.
    guard.restore()?;
    tty.write_all(b"\n")?;
    result
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
    }
    let after = state();
    assert_eq!(before.c_lflag, after.c_lflag);
    assert_eq!(before.c_iflag, after.c_iflag);
    assert_eq!(before.c_cc, after.c_cc);
}
