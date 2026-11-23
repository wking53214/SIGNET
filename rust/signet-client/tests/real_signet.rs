//! The Rust client against the real signet (the Python program, started here as its own process). It proves the
//! two speak the same protocol: a signature comes back in signet's envelope and checks under the public key signet
//! printed, it is in signet's log, and each of signet's refusals arrives as `Refused` with its code.
//!
//! Needs a Python with signet installed (`pip install -e .` at the repository root). SIGNET_PYTHON names it
//! (default `python3`). If it is missing the test FAILS; it is never skipped.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use signet_client::{Client, Error};

fn python() -> String {
    std::env::var("SIGNET_PYTHON").unwrap_or_else(|_| "python3".into())
}

struct Signet {
    child: Child,
    socket: PathBuf,
    key_id: String,
    public: VerifyingKey,
    log: PathBuf,
}

impl Drop for Signet {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let at = line
        .find(&format!("\"{name}\": \""))
        .unwrap_or_else(|| panic!("fixture output lacks {name}: {line}"));
    let rest = &line[at + name.len() + 5..];
    &rest[..rest.find('"').unwrap()]
}

fn start(name: &str) -> Signet {
    start_with(name, &[])
}

/// A signet whose `humanity-slip` purpose needs two of `approvers` (public keys) when the list is not empty.
fn start_with(name: &str, approvers: &[[u8; 32]]) -> Signet {
    let root = std::env::temp_dir().join(format!("signet-real-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixture.py");
    let mut fixture_cmd = Command::new(python());
    fixture_cmd.arg(&fixture).arg(&root);
    if !approvers.is_empty() {
        let list: Vec<String> = approvers.iter().map(hex::encode).collect();
        fixture_cmd.arg(list.join(","));
    }
    let out = fixture_cmd.output().unwrap_or_else(|e| {
        panic!(
            "could not run {} (set SIGNET_PYTHON to a Python with signet installed): {e}",
            python()
        )
    });
    assert!(
        out.status.success(),
        "fixture failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = String::from_utf8(out.stdout).unwrap();
    let mut child = Command::new(python())
        .args(["-m", "signet", "serve", "--config", field(&line, "config")])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut first = String::new();
    err.read_line(&mut first).unwrap();
    assert!(
        first.contains("signet: serving"),
        "signet did not start: {first}"
    );
    // Keep reading signet's stderr: it prints a line per refusal, and a closed pipe would kill that request.
    std::thread::spawn(move || {
        let mut sink = String::new();
        while err.read_line(&mut sink).map(|n| n > 0).unwrap_or(false) {
            sink.clear();
        }
    });
    let pk: [u8; 32] = hex::decode(field(&line, "slip_public_key"))
        .unwrap()
        .try_into()
        .unwrap();
    Signet {
        child,
        socket: field(&line, "socket").into(),
        key_id: field(&line, "slip_key_id").into(),
        public: VerifyingKey::from_bytes(&pk).unwrap(),
        log: field(&line, "log").into(),
    }
}

fn me() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

#[test]
fn a_slip_signed_through_signet_checks_under_signets_key_and_is_logged() {
    let s = start("sign");
    let client = Client::new(
        &s.socket,
        "humanity-slip",
        Some(me()),
        Duration::from_secs(5),
    )
    .unwrap();
    let data = b"stack-capability/2\nthe exact signed region".to_vec();
    let got = client.sign(&data).unwrap();
    assert_eq!(got.key_id, s.key_id);
    s.public
        .verify(&data, &Signature::from_bytes(&got.signature))
        .expect("the signature checks under signet's key");
    assert!(s
        .public
        .verify(
            b"stack-capability/2\nother bytes",
            &Signature::from_bytes(&got.signature)
        )
        .is_err());
    let log = std::fs::read_to_string(&s.log).unwrap();
    assert!(
        log.lines().count() as u64 > got.seq,
        "the signature's seq is not in the log"
    );
    assert!(
        log.contains("\"outcome\":\"signed\""),
        "no signed line in the log"
    );
}

#[test]
fn bytes_without_the_purposes_label_are_refused_and_nothing_is_signed() {
    let s = start("label");
    let client = Client::new(
        &s.socket,
        "humanity-slip",
        Some(me()),
        Duration::from_secs(5),
    )
    .unwrap();
    for data in [
        &b"stack-capability/1\nold format"[..],
        b"zeta-lock-result-signature/1\nzeta bytes",
        b"",
    ] {
        match client.sign(data) {
            Err(Error::Refused { code, .. }) => assert_eq!(code, "wrong-label"),
            other => panic!("expected wrong-label, got {other:?}"),
        }
    }
}

#[test]
fn a_purpose_signet_does_not_serve_is_refused() {
    let s = start("purpose");
    let client = Client::new(
        &s.socket,
        "delta-receipt",
        Some(me()),
        Duration::from_secs(5),
    )
    .unwrap();
    match client.sign(b"delta-ledger-receipt-signature/1\nx") {
        Err(Error::Refused { code, .. }) => assert_eq!(code, "unknown-purpose"),
        other => panic!("expected unknown-purpose, got {other:?}"),
    }
}

#[test]
fn signet_killed_means_no_signature() {
    let mut s = start("killed");
    s.child.kill().unwrap();
    s.child.wait().unwrap();
    let client = Client::new(
        &s.socket,
        "humanity-slip",
        Some(me()),
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(matches!(
        client.sign(b"stack-capability/2\nx"),
        Err(Error::Unavailable(_))
    ));
}

const APPROVAL_DOMAIN: &[u8] = b"humanity-issuer/approval/1\n";

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

fn approve(key: &SigningKey, data: &[u8], summary: &[u8; 32]) -> ([u8; 32], [u8; 64]) {
    let mut m = APPROVAL_DOMAIN.to_vec();
    m.extend_from_slice(&sha256(data));
    m.extend_from_slice(summary);
    (key.verifying_key().to_bytes(), key.sign(&m).to_bytes())
}

#[test]
fn a_slip_with_two_approvals_is_signed_and_one_approval_is_refused() {
    let team: Vec<SigningKey> = (1u8..=3)
        .map(|i| SigningKey::from_bytes(&[i; 32]))
        .collect();
    let public: Vec<[u8; 32]> = team.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let s = start_with("approved", &public);
    let client = Client::new(
        &s.socket,
        "humanity-slip",
        Some(me()),
        Duration::from_secs(5),
    )
    .unwrap();
    let data = b"stack-capability/2\nan approved region".to_vec();
    let summary = sha256(b"APPROVE: run test.echo");

    match client.sign_approved(&data, &[approve(&team[0], &data, &summary)], &summary) {
        Err(Error::Refused { code, .. }) => assert_eq!(code, "not-approved"),
        other => panic!("expected not-approved for one approval, got {other:?}"),
    }
    match client.sign(&data) {
        Err(Error::Refused { code, .. }) => assert_eq!(code, "not-approved"),
        other => panic!("expected not-approved with no approvals, got {other:?}"),
    }
    let stranger = SigningKey::from_bytes(&[9; 32]);
    match client.sign_approved(
        &data,
        &[
            approve(&team[0], &data, &summary),
            approve(&stranger, &data, &summary),
        ],
        &summary,
    ) {
        Err(Error::Refused { code, .. }) => assert_eq!(code, "not-approved"),
        other => panic!("expected not-approved with a stranger, got {other:?}"),
    }
    let got = client
        .sign_approved(
            &data,
            &[
                approve(&team[0], &data, &summary),
                approve(&team[2], &data, &summary),
            ],
            &summary,
        )
        .unwrap();
    s.public
        .verify(&data, &Signature::from_bytes(&got.signature))
        .expect("the approved slip checks under signet's key");
    let log = std::fs::read_to_string(&s.log).unwrap();
    let line = log.lines().nth(got.seq as usize).unwrap();
    assert!(line.contains(&hex::encode(public[0])) && line.contains(&hex::encode(public[2])));
    assert!(!line.contains(&hex::encode(public[1])));
}
