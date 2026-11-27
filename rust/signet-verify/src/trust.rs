//! A checker's memory of the registries it has accepted, written from the rules in signet's `signet/trust.py`
//! docstring, not from its code. The state file is the same format, so either checker can read the other's memory:
//!
//! ```text
//! {"digest":"<64 hex>","revoked_ids":["zeta-1"],"revoked_keys":["<64 hex>"],"root":"<64 hex>",
//!  "schema":"signet-trust-state/1","version":3}
//! ```
//!
//! `TrustState::accept` refuses a registry that is older than the remembered version (rollback), has the remembered
//! version but another content (fork), lists a remembered revoked id or public key as anything but revoked
//! (resurrection; dropping it is allowed), or, when the checker sets `max_step`, is more than that many versions
//! ahead (a jump).
//!
//! `TrustStore` keeps the state in one file, written whole (temporary file, fsync, rename, directory fsync), moved
//! only forward, under a lock. A missing file is refused unless the store is started on purpose with
//! `TrustStore::create`, because a checker whose memory silently vanished would accept a rollback. A pin other than
//! the remembered root is refused too.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::json::{canonical, loads, Value};
use crate::{hex64_lower, load_registry, to_hex, Registry};

pub const SCHEMA: &str = "signet-trust-state/1";

type R<T> = Result<T, String>;

fn is_hex64(v: &str) -> bool {
    hex64_lower(v).is_some()
}

/// What a checker remembers. `revoked_ids` and `revoked_keys` only grow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustState {
    pub root: String,
    pub version: i64,
    pub digest: String,
    pub revoked_ids: BTreeSet<String>,
    pub revoked_keys: BTreeSet<String>,
}

impl TrustState {
    /// The memory of a checker that has accepted nothing yet, under the pinned root (64 lowercase hex).
    pub fn new(root: &str) -> R<Self> {
        if !is_hex64(root) {
            return Err("the pinned root public key is 64 lowercase hex characters".into());
        }
        Ok(Self {
            root: root.into(),
            version: 0,
            digest: String::new(),
            revoked_ids: BTreeSet::new(),
            revoked_keys: BTreeSet::new(),
        })
    }

    /// The next memory after accepting `reg`, or why the memory refuses it. Nothing changes on a refusal.
    pub fn accept(&self, reg: &Registry, max_step: Option<i64>) -> R<Self> {
        if reg.version < self.version {
            return Err(format!(
                "rollback: registry version {} is older than version {}, which this checker has accepted",
                reg.version, self.version
            ));
        }
        if reg.version == self.version && reg.digest != self.digest {
            return Err(format!(
                "fork: a second, different registry claims version {}",
                reg.version
            ));
        }
        if let Some(step) = max_step {
            if self.version != 0 && reg.version - self.version > step {
                return Err(format!(
                    "jump: registry version {} is more than {step} ahead of {}",
                    reg.version, self.version
                ));
            }
        }
        let mut next = self.clone();
        for (id, k) in &reg.keys {
            let public = to_hex(&k.public_key);
            if k.status == "revoked" {
                next.revoked_ids.insert(id.clone());
                next.revoked_keys.insert(public);
                continue;
            }
            if self.revoked_ids.contains(id) {
                return Err(format!(
                    "resurrection: key {id:?} was revoked and is now {:?}",
                    k.status
                ));
            }
            if self.revoked_keys.contains(&public) {
                return Err(format!(
                    "resurrection: the public key of {id:?} was revoked under another id"
                ));
            }
        }
        next.version = reg.version;
        next.digest = reg.digest.clone();
        Ok(next)
    }

    /// The state file's bytes: canonical JSON and a newline, as signet writes it.
    pub fn to_json(&self) -> Vec<u8> {
        let list = |s: &BTreeSet<String>| Value::Arr(s.iter().cloned().map(Value::Str).collect());
        let m = BTreeMap::from([
            ("schema".to_string(), Value::Str(SCHEMA.into())),
            ("root".to_string(), Value::Str(self.root.clone())),
            ("version".to_string(), Value::Int(self.version)),
            ("digest".to_string(), Value::Str(self.digest.clone())),
            ("revoked_ids".to_string(), list(&self.revoked_ids)),
            ("revoked_keys".to_string(), list(&self.revoked_keys)),
        ]);
        let mut out = canonical(&Value::Obj(m));
        out.push(b'\n');
        out
    }

    /// A state read back from its file, or why it cannot be.
    pub fn from_json(text: &[u8]) -> R<Self> {
        let m = loads(text, 1 << 20, 2)
            .map_err(|e| format!("the trust state is not strict JSON: {e}"))?;
        let want = [
            "schema",
            "root",
            "version",
            "digest",
            "revoked_ids",
            "revoked_keys",
        ];
        if m.len() != want.len()
            || !want.iter().all(|k| m.contains_key(*k))
            || m["schema"].as_str() != Some(SCHEMA)
        {
            return Err(format!("a trust state has exactly the {SCHEMA} fields"));
        }
        let malformed = || "the trust state's root, version or digest is malformed".to_string();
        let root = m["root"]
            .as_str()
            .filter(|r| is_hex64(r))
            .ok_or_else(malformed)?;
        let version = m["version"]
            .as_int()
            .filter(|v| *v >= 0)
            .ok_or_else(malformed)?;
        let digest = m["digest"].as_str().ok_or_else(malformed)?;
        if !((version == 0 && digest.is_empty()) || (version > 0 && is_hex64(digest))) {
            return Err(malformed());
        }
        let strings = |k: &str, hex: bool| -> R<BTreeSet<String>> {
            m[k].as_arr()
                .ok_or("the trust state's revoked lists are malformed")?
                .iter()
                .map(|v| {
                    v.as_str()
                        .filter(|s| !hex || is_hex64(s))
                        .map(String::from)
                        .ok_or_else(|| "the trust state's revoked lists are malformed".to_string())
                })
                .collect()
        };
        Ok(Self {
            root: root.into(),
            version,
            digest: digest.into(),
            revoked_ids: strings("revoked_ids", false)?,
            revoked_keys: strings("revoked_keys", true)?,
        })
    }
}

/// A `TrustState` kept in one file. `load(text)` checks a registry against it and moves it forward.
#[derive(Debug, Clone)]
pub struct TrustStore {
    path: PathBuf,
    root: String,
    max_step: Option<i64>,
}

impl TrustStore {
    /// A store over an existing memory file at `path`, for the pinned root.
    pub fn new(path: impl AsRef<Path>, root: &str, max_step: Option<i64>) -> R<Self> {
        TrustState::new(root)?;
        Ok(Self {
            path: path.as_ref().to_path_buf(),
            root: root.into(),
            max_step,
        })
    }

    /// Starts an empty memory for a checker that has never accepted a registry. Refuses an existing file.
    pub fn create(path: impl AsRef<Path>, root: &str, max_step: Option<i64>) -> R<Self> {
        let store = Self::new(path, root, max_step)?;
        store.write(&TrustState::new(root)?, true)?;
        Ok(store)
    }

    /// The remembered state, or why it cannot be trusted.
    pub fn state(&self) -> R<TrustState> {
        let raw = match std::fs::read(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!(
                    "{} is missing: this checker's memory of accepted registries is gone, so a rollback could not \
                     be seen. Restore it, or start again on purpose with TrustStore::create",
                    self.path.display()
                ))
            }
            Err(e) => return Err(format!("{}: {e}", self.path.display())),
        };
        let state = TrustState::from_json(&raw)?;
        if state.root != self.root {
            return Err(
                "the trust state was kept under another root key; a re-pin resets it on purpose"
                    .into(),
            );
        }
        Ok(state)
    }

    /// The registry, if it verifies under the pinned root AND this memory accepts it; the memory then moves
    /// forward. Otherwise the reason, and nothing changes.
    pub fn load(&self, text: &[u8]) -> R<Registry> {
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.sibling(".lock"))
            .map_err(|e| format!("the trust state's lock: {e}"))?;
        lock.lock()
            .map_err(|e| format!("the trust state's lock: {e}"))?;
        let state = self.state()?;
        let reg = load_registry(text, &self.root, state.version.max(1))?;
        self.write(&state.accept(&reg, self.max_step)?, false)?;
        Ok(reg)
    }

    fn sibling(&self, suffix: &str) -> PathBuf {
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.path.with_file_name(format!(".{name}{suffix}"))
    }

    fn write(&self, state: &TrustState, new: bool) -> R<()> {
        if new && std::fs::symlink_metadata(&self.path).is_ok() {
            return Err(format!(
                "{} already exists; a checker's memory is never started over silently",
                self.path.display()
            ));
        }
        let tmp = self.sibling(&format!(".tmp-{}", std::process::id()));
        let io = |e: std::io::Error| format!("writing the trust state: {e}");
        let result = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(io)?;
            f.write_all(&state.to_json()).map_err(io)?;
            f.sync_all().map_err(io)?;
            std::fs::rename(&tmp, &self.path).map_err(io)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
            return result;
        }
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(dir).and_then(|d| d.sync_all()).map_err(io)
    }
}
