//! Differential test: signet-verify's canonical writer against signet's own (Python), on 3,000 generated objects with
//! strings drawn from the awkward corners (control characters, DEL, quotes, backslashes, non-ASCII, astral
//! characters). Both must write the same bytes, because those are the bytes signatures cover. Needs signet
//! installed for the Python named by SIGNET_PYTHON (default python3), as the rust client's tests do.

use std::io::Write;
use std::process::{Command, Stdio};

use signet_verify::json::{canonical, loads, Value};

const ALPHABET: &[char] = &[
    'a',
    'Z',
    '0',
    ' ',
    '~',
    '"',
    '\\',
    '/',
    '\n',
    '\r',
    '\t',
    '\u{0}',
    '\u{8}',
    '\u{c}',
    '\u{1f}',
    '\u{7f}',
    '\u{80}',
    '\u{e9}',
    '\u{2028}',
    '\u{fffd}',
    '\u{ffff}',
    '\u{10000}',
    '\u{1f600}',
    '\u{10ffff}',
];

struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as usize) % n
    }
}

fn text(r: &mut Lcg) -> String {
    (0..r.next(6))
        .map(|_| ALPHABET[r.next(ALPHABET.len())])
        .collect()
}

fn value(r: &mut Lcg, depth: usize) -> Value {
    match if depth > 2 { r.next(4) } else { r.next(6) } {
        0 => Value::Int(r.next(2_000_001) as i64 - 1_000_000),
        1 => Value::Str(text(r)),
        2 => Value::Bool(r.next(2) == 1),
        3 => Value::Null,
        4 => Value::Arr((0..r.next(3)).map(|_| value(r, depth + 1)).collect()),
        _ => Value::Obj(
            (0..r.next(3))
                .map(|_| (text(r), value(r, depth + 1)))
                .collect(),
        ),
    }
}

#[test]
fn canonical_bytes_agree_with_signets_python_on_generated_objects() {
    let mut r = Lcg(0x5167_4e54);
    let cases: Vec<Value> = (0..3000)
        .map(|_| {
            Value::Obj(
                (0..1 + r.next(4))
                    .map(|_| (text(&mut r), value(&mut r, 1)))
                    .collect(),
            )
        })
        .collect();
    // Hand Python each case as Rust's canonical text; it reads it strictly and writes it canonically again.
    let ours: Vec<String> = cases
        .iter()
        .map(|c| String::from_utf8(canonical(c)).unwrap())
        .collect();
    for line in &ours {
        assert!(
            loads(line.as_bytes(), 1 << 20, 16).is_ok(),
            "our own output does not read back: {line}"
        );
    }
    let python = std::env::var("SIGNET_PYTHON").unwrap_or_else(|_| "python3".into());
    let script = "import sys\nfrom signet.strict import loads, canonical\nfor line in sys.stdin.read().split('\\n')[:-1]:\n    sys.stdout.write(canonical(loads(line)).decode('ascii') + '\\n')\n";
    let mut child = Command::new(&python)
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("SIGNET_PYTHON (or python3) with signet installed");
    child
        .stdin
        .take()
        .unwrap()
        .write_all((ours.join("\n") + "\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let theirs: Vec<&str> = std::str::from_utf8(&out.stdout).unwrap().lines().collect();
    assert_eq!(theirs.len(), ours.len());
    let wrong: Vec<_> = ours
        .iter()
        .zip(&theirs)
        .filter(|(a, b)| a != *b)
        .take(5)
        .collect();
    assert!(wrong.is_empty(), "canonical bytes disagree: {wrong:#?}");
}
