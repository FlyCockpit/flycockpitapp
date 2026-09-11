//! Platform launch witness for replay crash-boundary tests.

use std::path::Path;

pub struct ReplayLaunchBarrier {
    command: String,
    #[cfg(unix)]
    reader: Option<tokio::io::unix::AsyncFd<std::fs::File>>,
    #[cfg(unix)]
    keep_reader_live: Option<std::fs::File>,
    #[cfg(unix)]
    path: std::path::PathBuf,
    #[cfg(windows)]
    server: tokio::net::windows::named_pipe::NamedPipeServer,
}

impl ReplayLaunchBarrier {
    pub fn new(project: &Path) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            let path = project.join("sandbox-launched");
            let fifo = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("FIFO path");
            // SAFETY: fifo is a valid NUL-terminated path and mode is private.
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
            return Self {
                command: format!("dd if=/dev/zero of={} bs=1", path.display()),
                reader: None,
                keep_reader_live: None,
                path,
            };
        }
        #[cfg(windows)]
        {
            let pipe_leaf = format!("cockpit-replay-launch-{}", uuid::Uuid::new_v4().simple());
            let pipe_name = format!(r"\\.\pipe\{pipe_leaf}");
            let server = tokio::net::windows::named_pipe::ServerOptions::new()
                .first_pipe_instance(true)
                .create(&pipe_name)
                .expect("create unique replay launch named pipe");
            let command = format!(
                "powershell.exe -NoProfile -NonInteractive -Command \"$p=[IO.Pipes.NamedPipeClientStream]::new('.', '{pipe_leaf}', [IO.Pipes.PipeDirection]::InOut);$p.Connect();$p.WriteByte(0);$p.Flush();$p.ReadByte()\""
            );
            return Self { command, server };
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = project;
            compile_error!("replay launch witness requires FIFO or Windows named pipes");
        }
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    /// Complete only after the real host operation has opened the platform
    /// IPC object and written its witness byte. Retained handles keep that
    /// operation blocked across the subsequent forced daemon termination.
    pub async fn wait_for_launch(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let reader = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&self.path)
                .expect("open sandbox launch-barrier reader");
            self.keep_reader_live = Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&self.path)
                    .expect("keep sandbox launch-barrier reader live"),
            );
            self.reader = Some(
                tokio::io::unix::AsyncFd::new(reader)
                    .expect("register sandbox launch-barrier reader"),
            );
            let reader = self.reader.as_ref().expect("launch reader");
            loop {
                let mut readiness = reader
                    .readable()
                    .await
                    .expect("sandbox launch-barrier readiness");
                let mut byte = [0_u8; 1];
                match readiness
                    .try_io(|inner| std::io::Read::read_exact(&mut inner.get_ref(), &mut byte))
                {
                    Ok(Ok(())) => {
                        assert_eq!(byte, [0], "sandbox launch-barrier byte");
                        return;
                    }
                    Ok(Err(error)) => panic!("read sandbox launch barrier: {error}"),
                    Err(_) => {}
                }
            }
        }
        #[cfg(windows)]
        {
            use tokio::io::AsyncReadExt as _;
            self.server
                .connect()
                .await
                .expect("connect replay launch named pipe");
            let mut byte = [0_u8; 1];
            self.server
                .read_exact(&mut byte)
                .await
                .expect("read replay launch named-pipe witness");
            assert_eq!(byte, [0], "replay launch named-pipe byte");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn unix_barrier_is_a_fifo_backed_live_operation() {
        use std::os::unix::fs::FileTypeExt as _;
        let root = tempfile::tempdir().expect("tempdir");
        let barrier = ReplayLaunchBarrier::new(root.path());
        assert!(
            std::fs::metadata(&barrier.path)
                .unwrap()
                .file_type()
                .is_fifo()
        );
        assert!(barrier.command().starts_with("dd if=/dev/zero of="));
        assert!(!barrier.command().contains("tail -f"));
    }

    #[test]
    #[cfg(windows)]
    fn windows_barrier_uses_unique_named_pipe_and_blocks_after_witness() {
        let root = tempfile::tempdir().expect("tempdir");
        let barrier = ReplayLaunchBarrier::new(root.path());
        assert!(barrier.command().contains("NamedPipeClientStream"));
        assert!(barrier.command().contains("WriteByte(0)"));
        assert!(barrier.command().contains("ReadByte()"));
        assert!(!barrier.command().contains("tail -f"));
    }
}
