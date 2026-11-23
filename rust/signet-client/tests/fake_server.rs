//! The client against a stand-in that answers whatever the test says: every malformed or two-faced reply is refused
//! as `Unavailable`, a refusal is `Refused`, and with the wrong `expected_uid` nothing is sent at all.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use signet_client::{Client, Error};

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("signet-client-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("s.sock")
}

/// Serve one connection with `reply` (a raw JSON body, framed here). Returns what the client sent.
fn serve_once(name: &str, reply: Vec<u8>) -> (PathBuf, mpsc::Receiver<Vec<u8>>) {
    let path = tmp(name);
    let listener = UnixListener::bind(&path).unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut got = Vec::new();
        let mut len = [0u8; 4];
        if conn.read_exact(&mut len).is_ok() {
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            conn.read_exact(&mut body).unwrap();
            got = body;
            let mut frame = (reply.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&reply);
            let _ = conn.write_all(&frame);
        }
        tx.send(got).unwrap();
    });
    (path, rx)
}

fn ask(name: &str, reply: &str) -> Result<signet_client::Signed, Error> {
    let (path, _) = serve_once(name, reply.as_bytes().to_vec());
    Client::new(&path, "humanity-slip", None, Duration::from_secs(2))
        .unwrap()
        .sign(b"stack-capability/2\nx")
}

fn good_sig() -> String {
    let mut env = b"slip-1:".to_vec();
    env.extend_from_slice(&[7u8; 64]);
    hex::encode(env)
}

#[test]
fn a_well_formed_signature_comes_back_whole() {
    let reply = format!(
        r#"{{"ok":true,"seq":3,"signature":"{}","v":1}}"#,
        good_sig()
    );
    let (path, sent) = serve_once("good", reply.into_bytes());
    let got = Client::new(&path, "humanity-slip", None, Duration::from_secs(2))
        .unwrap()
        .sign(b"stack-capability/2\nx")
        .unwrap();
    assert_eq!(
        (got.key_id.as_str(), got.signature, got.seq),
        ("slip-1", [7u8; 64], 3)
    );
    assert_eq!(
        sent.recv().unwrap(),
        br#"{"data":"737461636b2d6361706162696c6974792f320a78","purpose":"humanity-slip","v":1}"#
            .to_vec()
    );
}

#[test]
fn a_refusal_is_refused_with_its_code() {
    let got = ask(
        "refused",
        r#"{"code":"wrong-label","ok":false,"reason":"no","v":1}"#,
    );
    assert_eq!(
        got,
        Err(Error::Refused {
            code: "wrong-label".into(),
            reason: "no".into()
        })
    );
}

#[test]
fn every_two_faced_or_malformed_reply_is_unavailable() {
    let sig = good_sig();
    let cases: Vec<(&str, String)> = vec![
        (
            "dup-ok",
            format!(r#"{{"ok":false,"ok":true,"seq":3,"signature":"{sig}","v":1}}"#),
        ),
        (
            "dup-sig",
            format!(r#"{{"ok":true,"seq":3,"signature":"00","signature":"{sig}","v":1}}"#),
        ),
        (
            "float-seq",
            format!(r#"{{"ok":true,"seq":3.0,"signature":"{sig}","v":1}}"#),
        ),
        (
            "exp-seq",
            format!(r#"{{"ok":true,"seq":3e0,"signature":"{sig}","v":1}}"#),
        ),
        (
            "big-seq",
            format!(r#"{{"ok":true,"seq":9007199254740992,"signature":"{sig}","v":1}}"#),
        ),
        (
            "neg-seq",
            format!(r#"{{"ok":true,"seq":-1,"signature":"{sig}","v":1}}"#),
        ),
        (
            "extra-key",
            format!(r#"{{"extra":1,"ok":true,"seq":3,"signature":"{sig}","v":1}}"#),
        ),
        (
            "missing-seq",
            format!(r#"{{"ok":true,"signature":"{sig}","v":1}}"#),
        ),
        (
            "v2",
            format!(r#"{{"ok":true,"seq":3,"signature":"{sig}","v":2}}"#),
        ),
        (
            "ok-string",
            format!(r#"{{"ok":"true","seq":3,"signature":"{sig}","v":1}}"#),
        ),
        (
            "upper-hex",
            format!(
                r#"{{"ok":true,"seq":3,"signature":"{}","v":1}}"#,
                sig.to_uppercase()
            ),
        ),
        (
            "short-sig",
            r#"{"ok":true,"seq":3,"signature":"736c69702d313a0707","v":1}"#.into(),
        ),
        (
            "no-colon",
            format!(
                r#"{{"ok":true,"seq":3,"signature":"{}","v":1}}"#,
                hex::encode([7u8; 70])
            ),
        ),
        (
            "nested",
            r#"{"ok":true,"seq":{"n":3},"signature":"00","v":1}"#.into(),
        ),
        (
            "trailing",
            format!(r#"{{"ok":true,"seq":3,"signature":"{sig}","v":1}} x"#),
        ),
        ("top-array", "[1]".into()),
        ("not-json", "nope".into()),
        (
            "lone-surrogate",
            r#"{"code":"internal","ok":false,"reason":"\ud800","v":1}"#.into(),
        ),
        (
            "unknown-code",
            r#"{"code":"maybe","ok":false,"reason":"r","v":1}"#.into(),
        ),
        (
            "refusal-extra",
            r#"{"code":"internal","ok":false,"reason":"r","seq":1,"v":1}"#.into(),
        ),
        (
            "nan",
            r#"{"ok":true,"seq":NaN,"signature":"00","v":1}"#.into(),
        ),
    ];
    for (name, reply) in cases {
        match ask(name, &reply) {
            Err(Error::Unavailable(_)) => {}
            other => panic!("{name}: expected Unavailable, got {other:?}"),
        }
    }
}

#[test]
fn a_program_on_the_path_under_another_account_is_sent_nothing() {
    let (path, sent) = serve_once("squatter", b"{}".to_vec());
    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let got = Client::new(
        &path,
        "humanity-slip",
        Some(me.wrapping_add(1)),
        Duration::from_secs(2),
    )
    .unwrap()
    .sign(b"secret");
    assert!(
        matches!(got, Err(Error::Unavailable(ref why)) if why.contains("nothing was sent")),
        "{got:?}"
    );
    assert!(
        sent.recv().unwrap().is_empty(),
        "the squatter received bytes"
    );
}

#[test]
fn no_socket_is_unavailable() {
    let got = Client::new(
        "/nonexistent/signet.sock",
        "humanity-slip",
        None,
        Duration::from_secs(1),
    )
    .unwrap()
    .sign(b"x");
    assert!(matches!(got, Err(Error::Unavailable(_))));
}
