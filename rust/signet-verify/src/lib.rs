//! signet-verify: an independent checker of signet's formats, written from the format rules in signet's docstrings
//! and README, in another language, with another JSON reader and another Ed25519 library (ed25519-dalek, where signet
//! uses OpenSSL). It shares no code with signet. Both are tested against docs/vectors/signet-vectors-v1.json and
//! must give every answer there; a disagreement is a finding about one of them.
//!
//! Three checks, each fail closed:
//!
//!   - `load_registry(text, pinned_root, min_version)`: the signed key registry (signet-registry/1);
//!   - `Registry::verify(purpose, data, signature)`: a signature for one purpose;
//!   - `Registry::read_checkpoint(text)`: a log checkpoint (signet-log-checkpoint/1 or /2).
//!
//! And `trust`: a checker's memory of the registries it has accepted, so an old, forked or resurrecting one is
//! refused, kept in the same file format as signet's `signet.trust`.

pub mod json;
pub mod trust;

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use json::{canonical, loads, Value};
use sha2::{Digest, Sha256};

pub const REGISTRY_LABEL: &[u8] = b"signet-registry/1\n";
pub const CHECKPOINT_LABEL: &[u8] = b"signet-log-checkpoint/1\n";
const REGISTRY_PURPOSE: &str = "signet-registry";
const LOG_PURPOSE: &str = "signet-log";

#[derive(Debug, Clone, PartialEq)]
pub struct Key {
    pub purpose: String,
    pub public_key: [u8; 32],
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct Registry {
    pub version: i64,
    pub labels: BTreeMap<String, Vec<u8>>,
    pub keys: BTreeMap<String, Key>,
    /// SHA-256 (64 lowercase hex) of the registry's signing input with its key list sorted by key id: one name for
    /// one registry content, whatever the order its file lists the keys in.
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Checkpoint {
    pub length: i64,
    pub head: String,
    pub at_ms: Option<i64>,
    pub previous: Option<String>,
}

type R<T> = Result<T, String>;

fn valid_name(v: &str) -> bool {
    (1..=64).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn valid_label(v: &str) -> bool {
    (2..=128).contains(&v.chars().count())
        && v.ends_with('\n')
        && v[..v.len() - 1].chars().all(|c| (' '..='~').contains(&c))
}

pub(crate) fn hex64_lower(v: &str) -> Option<[u8; 32]> {
    if v.len() != 64
        || !v
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&v[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Hex the way signet reads it: either case, ASCII whitespace allowed between byte pairs.
fn from_hex(v: &str) -> Option<Vec<u8>> {
    let b = v.as_bytes();
    let (mut i, mut out) = (0, Vec::new());
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let pair = b.get(i..i + 2)?;
        if !pair.iter().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        out.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
        i += 2;
    }
    Some(out)
}

/// `(key id, 64 signature bytes)` from the envelope `key_id:signature`.
pub fn split_signature(sig: &[u8]) -> Option<(String, [u8; 64])> {
    let colon = sig.iter().position(|&c| c == b':')?;
    let (id, body) = (&sig[..colon], &sig[colon + 1..]);
    let id = std::str::from_utf8(id)
        .ok()
        .filter(|s| s.is_ascii() && valid_name(s))?;
    Some((id.to_string(), body.try_into().ok()?))
}

fn ed25519_ok(public: &[u8; 32], data: &[u8], sig: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(public) {
        Ok(key) => key.verify_strict(data, &Signature::from_bytes(sig)).is_ok(),
        Err(_) => false,
    }
}

fn exact(m: &BTreeMap<String, Value>, want: &[&str]) -> bool {
    m.len() == want.len() && want.iter().all(|k| m.contains_key(*k))
}

fn check_rule(spec: &Value, label: &str) -> R<()> {
    let m = spec
        .as_obj()
        .filter(|m| exact(m, &["domain", "approvers", "quorum"]))
        .ok_or("bad approval rule")?;
    let domain = m["domain"]
        .as_str()
        .filter(|d| valid_label(d))
        .ok_or("bad approval domain")?;
    if domain == label {
        return Err("the approval domain equals the label".into());
    }
    let approvers = m["approvers"]
        .as_arr()
        .filter(|a| (1..=16).contains(&a.len()))
        .ok_or("bad approvers")?;
    let mut seen: Vec<&str> = Vec::new();
    for a in approvers {
        let a = a
            .as_str()
            .filter(|a| hex64_lower(a).is_some())
            .ok_or("bad approver key")?;
        seen.push(a);
    }
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != seen {
        return Err("approvers are not distinct and sorted".into());
    }
    let q = m["quorum"].as_int().ok_or("bad quorum")?;
    if q < 2 || q as usize > approvers.len() {
        return Err("bad quorum".into());
    }
    Ok(())
}

fn check_body(body: &Value) -> R<Registry> {
    let m = body
        .as_obj()
        .filter(|m| exact(m, &["schema", "version", "purposes", "keys"]))
        .ok_or("bad registry")?;
    if m["schema"].as_str() != Some("signet-registry/1") {
        return Err("bad schema".into());
    }
    let version = m["version"]
        .as_int()
        .filter(|v| *v >= 1)
        .ok_or("bad version")?;
    let purposes = m["purposes"].as_obj().ok_or("bad purposes")?;
    let list = m["keys"].as_arr().ok_or("bad keys")?;
    let reserved = BTreeMap::from([
        (REGISTRY_PURPOSE, "signet-registry/1\n"),
        (LOG_PURPOSE, "signet-log-checkpoint/1\n"),
    ]);
    let mut labels = BTreeMap::new();
    for (name, spec) in purposes {
        let s = spec.as_obj().ok_or("bad purpose")?;
        if !valid_name(name)
            || !s.contains_key("label")
            || !s.keys().all(|k| k == "label" || k == "approval")
        {
            return Err(format!("bad purpose {name}"));
        }
        let label = s["label"]
            .as_str()
            .filter(|l| valid_label(l))
            .ok_or("bad label")?;
        if let Some(rule) = s.get("approval") {
            if reserved.contains_key(name.as_str()) {
                return Err("an approval rule on signet's own purpose".into());
            }
            check_rule(rule, label)?;
        }
        if reserved
            .get(name.as_str())
            .is_some_and(|fixed| *fixed != label)
        {
            return Err("signet's own purpose with another label".into());
        }
        labels.insert(name.clone(), label.as_bytes().to_vec());
    }
    let (mut keys, mut publics, mut current) = (BTreeMap::new(), BTreeSet::new(), BTreeSet::new());
    for item in list {
        let e = item
            .as_obj()
            .filter(|e| exact(e, &["key_id", "purpose", "public_key", "status"]))
            .ok_or("bad key")?;
        let id = e["key_id"]
            .as_str()
            .filter(|i| valid_name(i))
            .ok_or("bad key id")?;
        let purpose = e["purpose"]
            .as_str()
            .filter(|p| labels.contains_key(*p))
            .ok_or("key for an unlisted purpose")?;
        let public = e["public_key"]
            .as_str()
            .and_then(hex64_lower)
            .ok_or("bad public key")?;
        let status = e["status"]
            .as_str()
            .filter(|s| ["current", "verify-only", "revoked"].contains(s))
            .ok_or("bad status")?;
        if keys.contains_key(id) || !publics.insert(public) {
            return Err("a key id or public key twice".into());
        }
        if status == "current" && !current.insert(purpose.to_string()) {
            return Err("two current keys for one purpose".into());
        }
        keys.insert(
            id.to_string(),
            Key {
                purpose: purpose.into(),
                public_key: public,
                status: status.into(),
            },
        );
    }
    Ok(Registry {
        version,
        labels,
        keys,
        digest: String::new(),
    })
}

/// The signing input of `body` with its key list sorted by key id, hashed.
fn sorted_digest(body: &Value) -> R<String> {
    let mut m = body.as_obj().ok_or("bad registry")?.clone();
    let mut list = m["keys"].as_arr().ok_or("bad keys")?.clone();
    list.sort_by(|a, b| {
        let id = |v: &Value| {
            v.as_obj()
                .and_then(|e| e["key_id"].as_str())
                .map(String::from)
        };
        id(a).cmp(&id(b))
    });
    m.insert("keys".into(), Value::Arr(list));
    let mut data = REGISTRY_LABEL.to_vec();
    data.extend(canonical(&Value::Obj(m)));
    Ok(to_hex(&Sha256::digest(&data)))
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A registry file checked against the pinned root public key (64 lowercase hex), or the reason it is refused.
pub fn load_registry(text: &[u8], root: &str, min_version: i64) -> R<Registry> {
    let pin = hex64_lower(root).ok_or("the pinned root is not 64 lowercase hex")?;
    let outer = loads(text, 1 << 20, 16)?;
    if !exact(&outer, &["registry", "signature"]) {
        return Err("a registry file has exactly registry and signature".into());
    }
    let envelope = outer["signature"]
        .as_str()
        .and_then(from_hex)
        .ok_or("bad signature hex")?;
    let (id, sig) = split_signature(&envelope).ok_or("bad signature envelope")?;
    let mut signed = REGISTRY_LABEL.to_vec();
    signed.extend(canonical(&outer["registry"]));
    if !ed25519_ok(&pin, &signed, &sig) {
        return Err("the registry signature does not check under the pinned root".into());
    }
    let mut reg = check_body(&outer["registry"])?;
    match reg.keys.get(&id) {
        Some(k)
            if k.purpose == REGISTRY_PURPOSE && k.status == "current" && k.public_key == pin => {}
        _ => return Err("signed by a key the registry does not list as its current root".into()),
    }
    if reg.version < min_version {
        return Err("older than the version this checker accepted".into());
    }
    reg.digest = sorted_digest(&outer["registry"])?;
    Ok(reg)
}

impl Registry {
    /// The key id and entry of the one `current` key of `purpose`, if the registry lists one.
    pub fn current(&self, purpose: &str) -> Option<(&str, &Key)> {
        self.keys
            .iter()
            .find(|(_, k)| k.purpose == purpose && k.status == "current")
            .map(|(id, k)| (id.as_str(), k))
    }

    /// True only if `signature` is a non-revoked key of this purpose over exactly `data`, which carries its label.
    pub fn verify(&self, purpose: &str, data: &[u8], signature: &[u8]) -> bool {
        let Some(label) = self.labels.get(purpose) else {
            return false;
        };
        if !data.starts_with(label) {
            return false;
        }
        let Some((id, sig)) = split_signature(signature) else {
            return false;
        };
        match self.keys.get(&id) {
            Some(k) if k.purpose == purpose && k.status != "revoked" => {
                ed25519_ok(&k.public_key, data, &sig)
            }
            _ => false,
        }
    }

    /// A checkpoint whose signature checks under this registry's signet-log keys, or the reason it does not.
    pub fn read_checkpoint(&self, text: &[u8]) -> R<Checkpoint> {
        let m = loads(text, 1 << 20, 16)?;
        let schema = m.get("schema").and_then(Value::as_str).ok_or("no schema")?;
        let two = match schema {
            "signet-log-checkpoint/1" if exact(&m, &["schema", "length", "head", "signature"]) => {
                false
            }
            "signet-log-checkpoint/2"
                if exact(
                    &m,
                    &["schema", "length", "head", "at_ms", "previous", "signature"],
                ) =>
            {
                true
            }
            _ => return Err("not a checkpoint".into()),
        };
        let length = m["length"]
            .as_int()
            .filter(|l| *l >= 0)
            .ok_or("bad length")?;
        let head = m["head"]
            .as_str()
            .filter(|h| h.chars().count() == 64)
            .ok_or("bad head")?;
        let mut fields = BTreeMap::from([
            ("schema".to_string(), m["schema"].clone()),
            ("length".to_string(), m["length"].clone()),
            ("head".to_string(), m["head"].clone()),
        ]);
        let (mut at_ms, mut previous) = (None, None);
        if two {
            let at = m["at_ms"].as_int().filter(|a| *a >= 0).ok_or("bad at_ms")?;
            let prev = m["previous"]
                .as_str()
                .filter(|p| p.is_empty() || hex64_lower(p).is_some())
                .ok_or("bad previous")?;
            fields.insert("at_ms".into(), m["at_ms"].clone());
            fields.insert("previous".into(), m["previous"].clone());
            (at_ms, previous) = (Some(at), Some(prev.to_string()));
        }
        let mut data = CHECKPOINT_LABEL.to_vec();
        data.extend(canonical(&Value::Obj(fields)));
        let sig = m["signature"]
            .as_str()
            .and_then(from_hex)
            .ok_or("bad signature hex")?;
        if !self.verify(LOG_PURPOSE, &data, &sig) {
            return Err("the checkpoint signature does not check under the signet-log keys".into());
        }
        Ok(Checkpoint {
            length,
            head: head.to_string(),
            at_ms,
            previous,
        })
    }
}
