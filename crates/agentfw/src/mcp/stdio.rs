// SPDX-License-Identifier: Apache-2.0
//! Cancellation-safe native MCP pipe IO. Completion means an actual OS write,
//! not that a blocking worker accepted a buffer which the client may see later.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};

struct NonblockingDescriptor {
    fd: OwnedFd,
    original_flags: libc::c_int,
}

impl AsRawFd for NonblockingDescriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for NonblockingDescriptor {
    fn drop(&mut self) {
        // Duplicates share status flags with the original stdin/stdout handle.
        // Restore them on both successful shutdown and failed registration.
        // SAFETY: the owned descriptor remains open through this Drop implementation.
        unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFL, self.original_flags) };
    }
}

pub(super) struct Pipe {
    inner: AsyncFd<NonblockingDescriptor>,
}

impl Pipe {
    fn new(original: BorrowedFd<'_>, interest: Interest) -> io::Result<Self> {
        // A CLOEXEC duplicate keeps ownership separate from the process handle.
        let owned = original.try_clone_to_owned()?;
        let fd = owned.as_raw_fd();
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fd is owned and metadata points to writable stat storage.
        if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstat initialized the entire stat value.
        let kind = unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT;
        if kind != libc::S_IFIFO && kind != libc::S_IFSOCK {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native MCP stdio requires a pipe or socket",
            ));
        }
        // SAFETY: F_GETFL takes no third argument and fd remains owned.
        let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if original_flags == -1 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = NonblockingDescriptor {
            fd: owned,
            original_flags,
        };
        // SAFETY: F_SETFL takes the supplied integer status flags.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags | libc::O_NONBLOCK) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            inner: AsyncFd::with_interest(descriptor, interest)?,
        })
    }

    pub(super) fn stdin() -> io::Result<Self> {
        Self::new(std::io::stdin().as_fd(), Interest::READABLE)
    }

    pub(super) fn stdout() -> io::Result<Self> {
        Self::new(std::io::stdout().as_fd(), Interest::WRITABLE)
    }
}

impl AsyncRead for Pipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let mut ready = ready!(self.inner.poll_read_ready(cx))?;
            match ready.try_io(|inner| {
                let bytes = buf.initialize_unfilled();
                // SAFETY: the owned fd is open; bytes is writable for this
                // synchronous syscall, which cannot outlive the buffer.
                let count = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                };
                if count == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            }) {
                Ok(Ok(count)) => {
                    buf.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => continue,
            }
        }
    }
}

impl AsyncWrite for Pipe {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let mut ready = ready!(self.inner.poll_write_ready(cx))?;
            match ready.try_io(|inner| {
                // SAFETY: fd and the immutable source remain valid throughout
                // the synchronous, nonblocking write.
                let count = unsafe {
                    libc::write(inner.get_ref().as_raw_fd(), buf.as_ptr().cast(), buf.len())
                };
                if count == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            }) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Each write goes directly to the OS; there is no deferred buffer.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_read_keeps_immediate_sequential_reply_and_eof_useful() {
        let (local, remote) = UnixStream::pair().unwrap();
        // SAFETY: local owns its descriptor for the entire assertion sequence.
        let flags = unsafe { libc::fcntl(local.as_raw_fd(), libc::F_GETFL) };
        let mut pipe = Pipe::new(local.as_fd(), Interest::READABLE | Interest::WRITABLE).unwrap();
        remote.set_nonblocking(true).unwrap();
        let mut remote = tokio::net::UnixStream::from_std(remote).unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(5), pipe.read(&mut byte))
                .await
                .is_err()
        );

        for index in 0..70 {
            let frame = format!("reply-{index}\n");
            pipe.write_all(frame.as_bytes()).await.unwrap();
            let mut received = vec![0; frame.len()];
            remote.read_exact(&mut received).await.unwrap();
            assert_eq!(received, frame.as_bytes());
            // The next input is submitted immediately after the actual newline,
            // without any worker-completion, flush task or scheduling delay.
            remote.write_all(b"n").await.unwrap();
            pipe.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, *b"n");
        }
        drop(remote);
        assert_eq!(pipe.read(&mut byte).await.unwrap(), 0);
        // SAFETY: local is still owned and open; observe OS status after actual IO.
        let after_io = unsafe { libc::fcntl(local.as_raw_fd(), libc::F_GETFL) };
        drop(pipe);
        // SAFETY: local remains open after its duplicated transport is dropped.
        // Compare the entire post-IO status word, undoing only our change.
        // Darwin retains FWASWRITTEN (0x10000) after real writes; it is not a
        // user-settable F_SETFL flag and must not be mistaken for a leaked flag.
        // See apple/darwin-xnu bsd/sys/fcntl.h (FWASWRITTEN and FCNTLFLAGS).
        assert_eq!(
            unsafe { libc::fcntl(local.as_raw_fd(), libc::F_GETFL) },
            (after_io & !libc::O_NONBLOCK) | (flags & libc::O_NONBLOCK)
        );
    }

    #[tokio::test]
    async fn no_io_drop_restores_entire_status_and_preserves_original_descriptor_flags() {
        let (local, _remote) = UnixStream::pair().unwrap();
        // SAFETY: local owns a valid descriptor throughout this test.
        let flags = unsafe { libc::fcntl(local.as_raw_fd(), libc::F_GETFL) };
        let descriptor_flags = unsafe { libc::fcntl(local.as_raw_fd(), libc::F_GETFD) };
        let pipe = Pipe::new(local.as_fd(), Interest::READABLE | Interest::WRITABLE).unwrap();
        // SAFETY: local remains owned. Construction changes only O_NONBLOCK.
        assert_eq!(
            unsafe { libc::fcntl(local.as_raw_fd(), libc::F_GETFL) },
            flags | libc::O_NONBLOCK
        );
        // SAFETY: the transport owns its duplicate, which must not cross exec.
        assert_ne!(
            unsafe { libc::fcntl(pipe.inner.get_ref().as_raw_fd(), libc::F_GETFD) }
                & libc::FD_CLOEXEC,
            0
        );
        drop(pipe);
        // SAFETY: local remains open. Check ALL status and descriptor bits.
        assert_eq!(
            unsafe { libc::fcntl(local.as_raw_fd(), libc::F_GETFL) },
            flags
        );
        assert_eq!(
            unsafe { libc::fcntl(local.as_raw_fd(), libc::F_GETFD) },
            descriptor_flags
        );
    }

    #[tokio::test]
    async fn non_pollable_stdio_is_explicitly_refused_without_flag_changes() {
        let file = tempfile::tempfile().unwrap();
        // SAFETY: file owns this descriptor for both flag observations.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        let error = Pipe::new(file.as_fd(), Interest::READABLE).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        // SAFETY: file remains open; registration failure must not change flags.
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) },
            flags
        );
    }
}
