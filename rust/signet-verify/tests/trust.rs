//! The trust memory against signet's own (`signet.trust`): the same registry sequences, the same answer at every
//! step, and the same state file bytes. Then the file-backed store: a lost memory, a re-pin, a restart that keeps
//! refusing a rollback, and signet's Python reading the file this store wrote. Needs signet installed for the Python
//! named by SIGNET_PYTHON (default python3), as the other differential test does.

use std::collections::BTreeMap;
use std::process::Command;

use signet_verify::json::{loads, Value};
use signet_verify::load_registry;
use signet_verify::trust::{TrustState, TrustStore};

fn python() -> String {
    std::env::var("SIGNET_PYTHON").unwrap_or_else(|_| "python3".into())
}

fn scenarios() -> BTreeMap<String, Value> {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/trust_scenarios.py");
    let out = Command::new(python())
        .arg(script)
        .output()
        .expect("SIGNET_PYTHON (or python3) with signet installed");
    assert!(
        out.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    loads(&out.stdout, 1 << 22, 16).expect("the scenarios read strictly")
}

fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    &v.as_obj().unwrap()[k]
}

fn steps(s: &BTreeMap<String, Value>) -> &Vec<Value> {
    s["steps"].as_arr().unwrap()
}

#[test]
fn every_step_matches_signets_answer_and_state_bytes() {
    let s = scenarios();
    let root = s["root"].as_str().unwrap();
    let mut wrong = vec![];
    let mut states: BTreeMap<String, TrustState> = BTreeMap::new();
    for step in steps(&s) {
        let seq = field(step, "sequence").as_str().unwrap().to_string();
        let name = field(step, "name").as_str().unwrap();
        let max_step = field(step, "max_step").as_int();
        let state = states
            .entry(seq.clone())
            .or_insert_with(|| TrustState::new(root).unwrap())
            .clone();
        let got = load_registry(
            field(step, "text").as_str().unwrap().as_bytes(),
            root,
            state.version.max(1),
        )
        .and_then(|reg| state.accept(&reg, max_step));
        let accept = matches!(field(step, "accept"), Value::Bool(true));
        match (&got, accept) {
            (Ok(next), true) => {
                let theirs = field(step, "state").as_str().unwrap().as_bytes();
                if next.to_json() != theirs {
                    wrong.push(format!(
                        "{seq}/{name}: state bytes differ:\n ours   {}\n theirs {}",
                        String::from_utf8_lossy(&next.to_json()),
                        String::from_utf8_lossy(theirs)
                    ));
                }
                states.insert(seq, next.clone());
            }
            (Err(_), false) => {}
            _ => wrong.push(format!(
                "{seq}/{name}: signet says {accept}, we say {got:?}"
            )),
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn a_state_reads_back_as_itself_and_malformed_states_are_refused() {
    let s = scenarios();
    let last = steps(&s)
        .iter()
        .rev()
        .find_map(|st| field(st, "state").as_str())
        .unwrap();
    let state = TrustState::from_json(last.as_bytes()).unwrap();
    assert_eq!(state.to_json(), last.as_bytes());
    for bad in [
        last.replace("signet-trust-state/1", "signet-trust-state/2"),
        last.replace("\"version\":", "\"version\":-"),
        last.replace("\"digest\":\"", "\"digest\":\"0"),
        last.replace("\"schema\":", "\"extra\":1,\"schema\":"),
        r#"{"digest":"","revoked_ids":[],"revoked_keys":[],"root":"00","schema":"signet-trust-state/1","version":0}"#
            .into(),
    ] {
        assert!(TrustState::from_json(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn the_store_keeps_refusing_a_rollback_across_a_restart_and_signet_reads_its_file() {
    let s = scenarios();
    let root = s["root"].as_str().unwrap();
    let text = |name: &str| {
        steps(&s)
            .iter()
            .find(|st| field(st, "name").as_str() == Some(name))
            .map(|st| field(st, "text").as_str().unwrap().to_string())
            .unwrap()
    };
    let dir = std::env::temp_dir().join(format!("signet-verify-trust-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("trust.json");

    let missing = TrustStore::new(&path, root, None).unwrap();
    assert!(missing
        .load(text("v1").as_bytes())
        .unwrap_err()
        .contains("missing"));

    let store = TrustStore::create(&path, root, None).unwrap();
    assert!(
        TrustStore::create(&path, root, None).is_err(),
        "a memory is never started over silently"
    );
    assert_eq!(store.load(text("v1").as_bytes()).unwrap().version, 1);
    assert_eq!(
        store
            .load(text("v2 rotates zeta").as_bytes())
            .unwrap()
            .version,
        2
    );

    // A restart: a new store over the same file still remembers version 2.
    let again = TrustStore::new(&path, root, None).unwrap();
    assert!(
        again.load(text("v1").as_bytes()).is_err(),
        "rollback after restart"
    );
    assert_eq!(again.state().unwrap().version, 2);

    let other = "1".repeat(64);
    assert!(TrustStore::new(&path, &other, None)
        .unwrap()
        .state()
        .unwrap_err()
        .contains("another root"));

    // signet's Python reads the file this store wrote and moves it forward with the next registry.
    std::fs::write(dir.join("v3.json"), text("v3 revokes delta-1")).unwrap();
    let script = "import sys\nfrom signet.trust import TrustStore\nr = TrustStore(sys.argv[1], sys.argv[2]).load(open(sys.argv[3]).read())\nprint(r.version)\n";
    let out = Command::new(python())
        .args([
            "-c",
            script,
            path.to_str().unwrap(),
            root,
            dir.join("v3.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "3");
    let after = again.state().unwrap();
    assert_eq!(after.version, 3);
    assert!(after.revoked_ids.contains("delta-1"));
    std::fs::remove_dir_all(&dir).unwrap();
}
