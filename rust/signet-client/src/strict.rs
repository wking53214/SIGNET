//! strict: how this client reads signet's reply. It mirrors `signet.strict.loads` and is stricter where Rust's own
//! reader is lenient: `serde_json` keeps the LAST of two equal keys silently, so one reply could say two things.
//!
//! A reply is refused, with a reason, when it is: over the byte limit; not strict UTF-8; not exactly one JSON object
//! with nothing after it; an object holding a key twice; a fractional or exponent number, NaN or Infinity; an integer
//! outside +/-(2**53 - 1); a nested object or array (no signet reply has one); a string with a raw control character
//! or a lone surrogate escape.

use std::collections::BTreeMap;

/// Largest integer every common JSON reader agrees on.
pub const MAX_SAFE_INT: i64 = (1 << 53) - 1;

/// One value in a flat reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Null,
}

struct Reader<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected {:?} at byte {}", b as char, self.i))
        }
    }

    fn literal(&mut self, word: &[u8], v: Value) -> Result<Value, String> {
        if self.s[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("not valid JSON at byte {}", self.i))
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let end = self.i + 4;
        let chunk = self.s.get(self.i..end).ok_or("a \\u escape is cut short")?;
        let text = std::str::from_utf8(chunk).map_err(|_| "a \\u escape is not hex")?;
        if !text.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("a \\u escape is not hex".into());
        }
        self.i = end;
        u32::from_str_radix(text, 16).map_err(|_| "a \\u escape is not hex".into())
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("a string is not closed")?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or("a string ends inside an escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err("a lone surrogate escape is not a character".into());
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err("a lone surrogate escape is not a character".into());
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err("a lone surrogate escape is not a character".into());
                            } else {
                                hi
                            };
                            out.push(
                                char::from_u32(code).ok_or("a \\u escape is not a character")?,
                            );
                        }
                        _ => return Err(format!("an unknown escape at byte {}", self.i - 1)),
                    }
                }
                0x00..=0x1F => return Err("a raw control character inside a string".into()),
                _ => {
                    // The whole input is already checked as UTF-8; copy one character.
                    let rest =
                        std::str::from_utf8(&self.s[self.i..]).map_err(|_| "not strict UTF-8")?;
                    let ch = rest.chars().next().ok_or("a string is not closed")?;
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let digits = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let run = &self.s[digits..self.i];
        if run.is_empty() || (run.len() > 1 && run[0] == b'0') {
            return Err(format!("not valid JSON at byte {start}"));
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err("a fractional or exponent number is not accepted".into());
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| "not a number")?;
        if run.len() > 16 {
            return Err(format!(
                "the integer {} is outside +/-(2**53 - 1)",
                &text[..text.len().min(24)]
            ));
        }
        let n: i64 = text.parse().map_err(|_| "not a number")?;
        if n.abs() > MAX_SAFE_INT {
            return Err(format!("the integer {text} is outside +/-(2**53 - 1)"));
        }
        Ok(Value::Int(n))
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.peek().ok_or("a value is missing")? {
            b'"' => Ok(Value::Str(self.string()?)),
            b'-' | b'0'..=b'9' => self.number(),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'{' | b'[' => Err("nested deeper than a signet reply allows".into()),
            b'N' | b'I' => Err("NaN and Infinity are not accepted".into()),
            _ => Err(format!("not valid JSON at byte {}", self.i)),
        }
    }
}

/// Read one flat JSON object strictly, or say why not.
pub fn parse_flat_object(raw: &[u8], max_bytes: usize) -> Result<BTreeMap<String, Value>, String> {
    if raw.len() > max_bytes {
        return Err(format!(
            "{} bytes is more than the limit of {max_bytes}",
            raw.len()
        ));
    }
    std::str::from_utf8(raw).map_err(|_| "the bytes are not strict UTF-8".to_string())?;
    let mut r = Reader { s: raw, i: 0 };
    r.ws();
    if r.peek() != Some(b'{') {
        return Err("the top level must be an object".into());
    }
    r.i += 1;
    let mut out = BTreeMap::new();
    r.ws();
    if r.peek() == Some(b'}') {
        r.i += 1;
    } else {
        loop {
            r.ws();
            let key = r.string()?;
            r.ws();
            r.expect(b':')?;
            r.ws();
            let v = r.value()?;
            if out.contains_key(&key) {
                return Err(format!(
                    "the key {key:?} appears twice in one object; the last would win silently"
                ));
            }
            out.insert(key, v);
            r.ws();
            match r.peek() {
                Some(b',') => r.i += 1,
                Some(b'}') => {
                    r.i += 1;
                    break;
                }
                _ => return Err(format!("not valid JSON at byte {}", r.i)),
            }
        }
    }
    r.ws();
    if r.i != raw.len() {
        return Err("something follows the object".into());
    }
    Ok(out)
}
