//! Configurable writer for FFI streaming tracing.
//!
//! Mirrors the `KafkaWriter` pattern in `tracing-kafka/src/writer.rs`:
//! implements `Write + Clone + MakeWriter` so it can be plugged into
//! `log_utils::JsonFormattingLayer` as a drop-in replacement for `KafkaWriter`.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Writer that delegates to stdout, stderr, or a file.
#[derive(Clone)]
pub enum FfiWriter {
    Stdout,
    Stderr,
    File(Arc<Mutex<File>>),
}

impl FfiWriter {
    /// Open a file for append-mode writing.
    pub fn file(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self::File(Arc::new(Mutex::new(file))))
    }
}

impl Write for FfiWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stdout => io::stdout().write(buf),
            Self::Stderr => io::stderr().write(buf),
            Self::File(f) => f
                .lock()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
                .write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout => io::stdout().flush(),
            Self::Stderr => io::stderr().flush(),
            Self::File(f) => f
                .lock()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
                .flush(),
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FfiWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
