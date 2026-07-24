//! IPC between the (unprivileged) GUI process and the elevated L2 helper
//! process: a local Unix domain socket on Linux, a named pipe on Windows -
//! both natively supported by tokio, so no extra transport crate is needed.
//! Newline-delimited JSON keeps the wire format trivially debuggable.

use std::io;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Messages exchanged over the connection once it's established.
///
/// `PingRequest`/`DuplicateCheckRequest` carry an `id` so replies can be
/// matched up even though multiple requests can be in flight *from the GUI's
/// point of view* at once (queued). The engine on the helper side still
/// only ever works on one at a time (see `l2_engine`), it just doesn't block
/// the IPC connection itself while doing so.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum L2Message {
    /// Helper -> GUI: capability confirmed, ready for (future) L2 work.
    Ready { detail: String },
    /// Helper -> GUI: something's wrong even after elevation.
    Failed { reason: String },
    /// GUI -> Helper: please exit gracefully.
    Shutdown,

    /// GUI -> Helper: perform one ICMP-over-L2 echo, from `source_ip` to
    /// `target` - `source_ip` is the address the user intends to send from,
    /// not necessarily this interface's own configured address.
    PingRequest {
        id: u64,
        source_ip: IpAddr,
        target: IpAddr,
        vlan: Option<u16>,
        timeout_ms: u32,
    },
    /// Helper -> GUI: result of a `PingRequest` with the same `id`.
    PingResponse { id: u64, outcome: L2PingOutcomeWire },

    /// GUI -> Helper: check whether more than one host answers for
    /// `candidate` - a source address the user is considering using, not a
    /// ping target.
    DuplicateCheckRequest {
        id: u64,
        candidate: IpAddr,
        vlan: Option<u16>,
        timeout_ms: u32,
    },
    /// Helper -> GUI: result of a `DuplicateCheckRequest` with the same `id`.
    DuplicateCheckResponse {
        id: u64,
        outcome: L2DuplicateOutcomeWire,
    },
}

/// Wire-friendly mirror of `l2_engine::L2PingOutcome` (millis instead of
/// `Duration`, which isn't serde-friendly by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum L2PingOutcomeWire {
    Success { rtt_ms: u64 },
    Timeout,
    Error(String),
}

/// Wire-friendly mirror of `l2_engine::L2DuplicateOutcome`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum L2DuplicateOutcomeWire {
    Clear,
    Duplicate { macs: Vec<String> },
    Error(String),
}

/// The concrete stream type on the GUI side - the IPC *server*, always: the
/// GUI creates the endpoint and waits for the helper to connect to it.
#[cfg(unix)]
pub type ServerStream = tokio::net::UnixStream;
#[cfg(windows)]
pub type ServerStream = tokio::net::windows::named_pipe::NamedPipeServer;

/// The concrete stream type on the helper side - the IPC *client*.
#[cfg(unix)]
pub type ClientStream = tokio::net::UnixStream;
#[cfg(windows)]
pub type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

/// A unique-enough endpoint name for one GUI process's helper session - the
/// PID is unique among currently-running processes, which is all we need.
pub fn endpoint_name() -> String {
    format!("statorius-l2-{}", std::process::id())
}

#[cfg(unix)]
fn endpoint_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{name}.sock"))
}

#[cfg(windows)]
fn endpoint_path(name: &str) -> String {
    format!(r"\\.\pipe\{name}")
}

/// GUI side: create the endpoint and wait for the helper to connect. Must be
/// called *before* the helper process is spawned, so it can never race ahead
/// of us and fail to find anything to connect to.
#[cfg(unix)]
pub async fn listen_and_accept(name: &str) -> io::Result<ServerStream> {
    let path = endpoint_path(name);
    let _ = std::fs::remove_file(&path); // clear a stale socket from a previous crash
    let listener = tokio::net::UnixListener::bind(&path)?;
    let (stream, _addr) = listener.accept().await?;
    Ok(stream)
}

#[cfg(windows)]
pub async fn listen_and_accept(name: &str) -> io::Result<ServerStream> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let path = endpoint_path(name);
    let server = ServerOptions::new().first_pipe_instance(true).create(path)?;
    server.connect().await?;
    Ok(server)
}

/// Helper side: connect to the endpoint the GUI already created.
#[cfg(unix)]
pub async fn connect(name: &str) -> io::Result<ClientStream> {
    let path = endpoint_path(name);
    tokio::net::UnixStream::connect(&path).await
}

#[cfg(windows)]
pub async fn connect(name: &str) -> io::Result<ClientStream> {
    use tokio::net::windows::named_pipe::ClientOptions;
    const ERROR_PIPE_BUSY: i32 = 231;
    let path = endpoint_path(name);
    for _ in 0..20 {
        match ClientOptions::new().open(&path) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "named pipe busy after retries",
    ))
}

/// Send one message, newline-delimited JSON.
pub async fn send_message<S>(stream: &mut S, msg: &L2Message) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut line =
        serde_json::to_string(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    stream.write_all(line.as_bytes()).await
}

/// Receive one message. `Ok(None)` means the peer disconnected (EOF).
pub async fn recv_message<S>(stream: &mut BufReader<S>) -> io::Result<Option<L2Message>>
where
    S: AsyncRead + Unpin,
{
    let mut line = String::new();
    let n = stream.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    serde_json::from_str(line.trim_end())
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}