//! The independent verifier against docs/vectors/signet-vectors-v1.json: every answer must match, refusals included.
//! signet's own Python verifier is held to the same file by tests/test_vectors.py.

use signet_verify::json::{loads, Value};
use signet_verify::load_registry;

fn vectors() -> std::collections::BTreeMap<String, Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/vectors/signet-vectors-v1.json"
    );
    loads(&std::fs::read(path).expect("the vectors file"), 1 << 22, 16)
        .expect("the vectors file reads strictly")
}

fn s<'a>(c: &'a Value, k: &str) -> &'a str {
    c.as_obj().unwrap()[k].as_str().unwrap()
}

fn b(c: &Value, k: &str) -> bool {
    matches!(c.as_obj().unwrap()[k], Value::Bool(true))
}

fn n(c: &Value, k: &str) -> i64 {
    c.as_obj().unwrap()[k].as_int().unwrap()
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn every_registry_answer_matches() {
    let v = vectors();
    let mut wrong = vec![];
    for c in v["registries"].as_arr().unwrap() {
        let got = load_registry(s(c, "text").as_bytes(), s(c, "root"), n(c, "min_version"));
        if got.is_ok() != b(c, "accept") {
            wrong.push(format!(
                "{}: expected {}, got {:?}",
                s(c, "name"),
                b(c, "accept"),
                got.err()
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn every_signature_answer_matches() {
    let v = vectors();
    let regs = v["signature_registries"].as_arr().unwrap();
    let root = v["root"].as_str().unwrap();
    let mut wrong = vec![];
    for c in v["signatures"].as_arr().unwrap() {
        let r = load_registry(
            regs[n(c, "registry") as usize].as_str().unwrap().as_bytes(),
            root,
            1,
        )
        .unwrap();
        if r.verify(
            s(c, "purpose"),
            &unhex(s(c, "data")),
            &unhex(s(c, "signature")),
        ) != b(c, "accept")
        {
            wrong.push(s(c, "name").to_string());
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn every_checkpoint_answer_matches() {
    let v = vectors();
    let regs = v["signature_registries"].as_arr().unwrap();
    let root = v["root"].as_str().unwrap();
    let mut wrong = vec![];
    for c in v["checkpoints"].as_arr().unwrap() {
        let r = load_registry(
            regs[n(c, "registry") as usize].as_str().unwrap().as_bytes(),
            root,
            1,
        )
        .unwrap();
        let got = r.read_checkpoint(s(c, "text").as_bytes());
        let ok = match (&got, b(c, "accept")) {
            (Ok(cp), true) => cp.length == n(c, "length") && cp.head == s(c, "head"),
            (Err(_), false) => true,
            _ => false,
        };
        if !ok {
            wrong.push(format!("{}: {:?}", s(c, "name"), got));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn canonical_bytes_match_signets_rules() {
    // The expected string is Python's own output for the same input (DEL, 0x7f, is escaped: found by this test).
    use signet_verify::json::canonical;
    let m = loads(
        "{\"b\":1,\"a\":[true,null,\"\u{e9}\u{1f600}\\u0001\\n\\\"/\u{7f}\"]}".as_bytes(),
        1024,
        16,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(canonical(&Value::Obj(m))).unwrap(),
        "{\"a\":[true,null,\"\\u00e9\\ud83d\\ude00\\u0001\\n\\\"/\\u007f\"],\"b\":1}"
    );
}
