//! signet-client: what a Rust program that needs signatures holds instead of a key.
//!
//! It is the Rust twin of `signet.client` and speaks the same protocol (`signet/protocol.py`): one request and one
//! answer per connection over signet's Unix socket, each a 4-byte big-endian length then strict JSON.
//!
//! ```text
//! request   {"data":"<lowercase hex>","purpose":"humanity-slip","v":1}
//!           with approvals: {"approvals":["<key hex>:<sig hex>",...],"data":...,"summary_sha256":"<64 hex>","v":1}
//! signed    {"ok":true,"seq":41,"signature":"<hex of key_id:signature>","v":1}
//! refused   {"code":"wrong-label","ok":false,"reason":"...","v":1}
//! ```
//!
//! It FAILS CLOSED. A refusal is `Error::Refused` with signet's code; anything else that is not a well-formed
//! signature (no socket, a timeout, a cut-off frame, a reply that is not strict JSON or not exactly signet's shape) is
//! `Error::Unavailable`. It never returns anything but a signature in signet's envelope.
//!
//! With `expected_uid`, the client asks the kernel which account is at the other end of the socket (SO_PEERCRED)
//! BEFORE it sends anything. A program squatting on the socket path never sees the bytes. Pass it in production.
//!
//! What this client does NOT do: check the signature. The caller holds the public key it expects (pinned out of
//! band, or read from signet's registry) and checks every signature before relying on it. A squatter that slipped
//! past `expected_uid` could answer with junk; the caller's check is what refuses it.
//!
//! Linux only, like signet itself: SO_PEERCRED is a Linux interface.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod strict;

#[cfg(not(target_os = "linux"))]
compile_error!("signet-client needs SO_PEERCRED, which only Linux provides");

use std::fmt;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use strict::{parse_flat_object, Value};

/// The protocol version both sides speak.
pub const VERSION: i64 = 1;
/// The largest request frame signet reads.
pub const MAX_FRAME: usize = 1 << 20;
/// The most approvals one request carries (`signet/protocol.py`).
pub const MAX_APPROVALS: usize = 64;
/// The largest reply this client reads (the Python client's limit too).
pub const MAX_REPLY: usize = 64 * 1024;
/// Every code signet refuses with. Each one means no signature was made.
pub const REFUSAL_CODES: [&str; 8] = [
    "malformed",
    "too-large",
    "unknown-purpose",
    "not-allowed",
    "wrong-label",
    "not-approved",
    "log-failed",
    "internal",
];

/// Why no signature came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// signet answered and said no.
    Refused { code: String, reason: String },
    /// signet could not be reached, or did not answer with a well-formed reply.
    Unavailable(String),
    /// The caller asked for something this client will not send.
    Usage(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Refused { code, reason } => write!(f, "signet refused ({code}): {reason}"),
            Error::Unavailable(why) => write!(f, "signet unavailable: {why}"),
            Error::Usage(why) => write!(f, "not sent: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// A signature as signet returned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// The id of the key that signed (signet's registry names it).
    pub key_id: String,
    /// The 64-byte Ed25519 signature.
    pub signature: [u8; 64],
    /// signet's envelope: `key_id`, `:`, then the 64 bytes. The shape the Python libraries take.
    pub envelope: Vec<u8>,
    /// The signature's line in signet's log.
    pub seq: u64,
}

/// True for a valid key id or purpose name: 1 to 64 characters from A-Z a-z 0-9 . _ - (`signet/names.py`).
pub fn valid_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// signet's own two purposes. They are never served over the socket, so asking for one is a caller mistake.
pub const RESERVED_PURPOSES: [&str; 2] = ["signet-registry", "signet-log"];

/// Asks one signet for signatures for one purpose.
#[derive(Debug, Clone)]
pub struct Client {
    socket: PathBuf,
    purpose: String,
    expected_uid: Option<u32>,
    timeout: Duration,
}

impl Client {
    /// A client for `purpose` at `socket`. `expected_uid` is signet's account number; pass it in production.
    pub fn new(
        socket: impl AsRef<Path>,
        purpose: &str,
        expected_uid: Option<u32>,
        timeout: Duration,
    ) -> Result<Self, Error> {
        if !valid_name(purpose) {
            return Err(Error::Usage(format!(
                "a purpose is 1 to 64 characters from A-Z a-z 0-9 . _ - ; got {purpose:?}"
            )));
        }
        if RESERVED_PURPOSES.contains(&purpose) {
            return Err(Error::Usage(format!(
                "{purpose:?} is signet's own purpose and is never served"
            )));
        }
        if timeout.is_zero() {
            return Err(Error::Usage("the timeout must be above zero".into()));
        }
        Ok(Self {
            socket: socket.as_ref().to_path_buf(),
            purpose: purpose.to_string(),
            expected_uid,
            timeout,
        })
    }

    /// The purpose this client asks for.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Ask signet to sign `data`. A signature, or why not. Nothing is retried.
    pub fn sign(&self, data: &[u8]) -> Result<Signed, Error> {
        self.send(request_body(&self.purpose, data))
    }

    /// Ask signet to sign `data` for a purpose with an approval rule (`signet/approval.py`). Each approval is an
    /// approver's public key and their Ed25519 signature over the approval domain, SHA-256 of `data`, and
    /// `summary_sha256` (the digest of the summary the approver was shown). signet counts the approvals itself and
    /// refuses with `not-approved` below its quorum; this client does not count them.
    pub fn sign_approved(
        &self,
        data: &[u8],
        approvals: &[([u8; 32], [u8; 64])],
        summary_sha256: &[u8; 32],
    ) -> Result<Signed, Error> {
        if approvals.len() > MAX_APPROVALS {
            return Err(Error::Usage(format!(
                "at most {MAX_APPROVALS} approvals are sent; got {}",
                approvals.len()
            )));
        }
        self.send(approved_request_body(
            &self.purpose,
            data,
            approvals,
            summary_sha256,
        ))
    }

    fn send(&self, body: Vec<u8>) -> Result<Signed, Error> {
        if body.len() > MAX_FRAME {
            return Err(Error::Usage(format!(
                "a request of {} bytes is over signet's limit of {MAX_FRAME}",
                body.len()
            )));
        }
        let unavailable = |what: &str, e: std::io::Error| {
            Error::Unavailable(format!(
                "signet at {} did not answer ({what}): {e}",
                self.socket.display()
            ))
        };
        let mut sock = UnixStream::connect(&self.socket).map_err(|e| unavailable("connect", e))?;
        sock.set_read_timeout(Some(self.timeout))
            .map_err(|e| unavailable("timeout", e))?;
        sock.set_write_timeout(Some(self.timeout))
            .map_err(|e| unavailable("timeout", e))?;
        if let Some(want) = self.expected_uid {
            let got = peer_uid(&sock).map_err(|e| unavailable("peer account", e))?;
            if got != want {
                return Err(Error::Unavailable(format!(
                    "the program at {} runs as uid {got}, not signet's uid {want}; nothing was sent",
                    self.socket.display()
                )));
            }
        }
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        sock.write_all(&frame).map_err(|e| unavailable("send", e))?;
        let mut len = [0u8; 4];
        sock.read_exact(&mut len)
            .map_err(|e| unavailable("reply length", e))?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_REPLY {
            return Err(Error::Unavailable(format!(
                "a reply of {len} bytes is over the limit of {MAX_REPLY}"
            )));
        }
        let mut raw = vec![0u8; len];
        sock.read_exact(&mut raw)
            .map_err(|e| unavailable("reply", e))?;
        read_reply(&raw)
    }
}

/// The canonical request bytes: sorted keys, no spaces. Every character is already plain ASCII (hex, a checked
/// purpose name), so nothing needs escaping.
fn request_body(purpose: &str, data: &[u8]) -> Vec<u8> {
    let hex = to_hex(data);
    format!("{{\"data\":\"{hex}\",\"purpose\":\"{purpose}\",\"v\":{VERSION}}}").into_bytes()
}

/// The same, with the approvals and the summary digest, keys still in sorted order.
fn approved_request_body(
    purpose: &str,
    data: &[u8],
    approvals: &[([u8; 32], [u8; 64])],
    summary: &[u8; 32],
) -> Vec<u8> {
    let list: Vec<String> = approvals
        .iter()
        .map(|(key, sig)| format!("\"{}:{}\"", to_hex(key), to_hex(sig)))
        .collect();
    format!(
        "{{\"approvals\":[{}],\"data\":\"{}\",\"purpose\":\"{purpose}\",\"summary_sha256\":\"{}\",\"v\":{VERSION}}}",
        list.join(","),
        to_hex(data),
        to_hex(summary)
    )
    .into_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

fn peer_uid(sock: &UnixStream) -> std::io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes of the sizes passed, and the fd is open for the call.
    let rc = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(std::io::Error::other("the kernel's answer is not a ucred"));
    }
    Ok(cred.uid)
}

fn hex_lower(text: &str) -> Option<Vec<u8>> {
    if text.len() & 1 == 1 || !text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// signet's reply as a signature or a refusal, held to exactly the shape `signet.client` accepts.
pub fn read_reply(raw: &[u8]) -> Result<Signed, Error> {
    let bad = |why: String| Error::Unavailable(why);
    let answer = parse_flat_object(raw, MAX_REPLY)
        .map_err(|e| bad(format!("signet's answer is not strict JSON: {e}")))?;
    let keys: Vec<&str> = answer.keys().map(String::as_str).collect();
    if answer.get("v") != Some(&Value::Int(VERSION)) {
        return Err(bad("signet's answer is not a signet reply".into()));
    }
    match answer.get("ok") {
        Some(Value::Bool(false)) => {
            if keys != ["code", "ok", "reason", "v"] {
                return Err(bad("signet's refusal is not well formed".into()));
            }
            match (answer.get("code"), answer.get("reason")) {
                (Some(Value::Str(code)), Some(Value::Str(reason)))
                    if REFUSAL_CODES.contains(&code.as_str()) =>
                {
                    Err(Error::Refused {
                        code: code.clone(),
                        reason: reason.clone(),
                    })
                }
                _ => Err(bad("signet's refusal is not well formed".into())),
            }
        }
        Some(Value::Bool(true)) => {
            if keys != ["ok", "seq", "signature", "v"] {
                return Err(bad("signet's answer is not well formed".into()));
            }
            let seq = match answer.get("seq") {
                Some(Value::Int(n)) if *n >= 0 => *n as u64,
                _ => return Err(bad("signet's answer is not well formed".into())),
            };
            let envelope = match answer.get("signature") {
                Some(Value::Str(s)) => hex_lower(s)
                    .ok_or_else(|| bad("signet's signature is not lowercase hex".into()))?,
                _ => return Err(bad("signet's answer is not well formed".into())),
            };
            let colon = envelope.iter().position(|&b| b == b':').ok_or_else(|| {
                bad("a signature is key_id, ':', then 64 bytes of Ed25519 signature".into())
            })?;
            let (id, rest) = (&envelope[..colon], &envelope[colon + 1..]);
            let key_id = std::str::from_utf8(id)
                .ok()
                .filter(|s| valid_name(s))
                .ok_or_else(|| bad("signet's signature names a key id that is not valid".into()))?;
            let signature: [u8; 64] = rest.try_into().map_err(|_| {
                bad("a signature is key_id, ':', then 64 bytes of Ed25519 signature".into())
            })?;
            Ok(Signed {
                key_id: key_id.to_string(),
                signature,
                envelope,
                seq,
            })
        }
        _ => Err(bad("signet's answer is not a signet reply".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_is_canonical() {
        assert_eq!(
            request_body("p-1", b"\x00\xff"),
            br#"{"data":"00ff","purpose":"p-1","v":1}"#.to_vec()
        );
    }

    #[test]
    fn bad_purposes_are_refused_before_anything_is_sent() {
        for bad in [
            "",
            "a:b",
            "signet-registry",
            "signet-log",
            &"x".repeat(65),
            "caf\u{e9}",
        ] {
            assert!(
                matches!(
                    Client::new("/nonexistent", bad, None, Duration::from_secs(1)),
                    Err(Error::Usage(_))
                ),
                "{bad:?}"
            );
        }
    }
}
