//! Strict JSON, written from the format rules in signet's `strict.py` docstring, not from its code.
//!
//! Reading refuses: more than the byte limit, a key twice in one object (after escapes), any fraction, exponent,
//! NaN or Infinity, an integer outside +/-(2**53 - 1), nesting deeper than the limit, raw control characters in a
//! string, a lone surrogate, trailing bytes, and a top level that is not an object.
//!
//! Writing (`canonical`) gives sorted keys, no spaces, printable ASCII (space to tilde) only, everything else escaped as lowercase
//! `\uXXXX` (astral characters as a surrogate pair): the bytes signet signs.

use std::collections::BTreeMap;

pub const MAX_SAFE_INT: i64 = (1 << 53) - 1;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Value>),
    Obj(BTreeMap<String, Value>),
}

impl Value {
    pub fn as_obj(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Obj(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    max_depth: usize,
}

type R<T> = Result<T, String>;

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn eat(&mut self, lit: &[u8]) -> bool {
        if self.b[self.i..].starts_with(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }
    fn value(&mut self, depth: usize) -> R<Value> {
        if depth > self.max_depth {
            return Err(format!("nested deeper than {} levels", self.max_depth));
        }
        self.ws();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') if self.eat(b"true") => Ok(Value::Bool(true)),
            Some(b'f') if self.eat(b"false") => Ok(Value::Bool(false)),
            Some(b'n') if self.eat(b"null") => Ok(Value::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(format!("not valid JSON at byte {}", self.i)),
        }
    }
    fn object(&mut self, depth: usize) -> R<Value> {
        self.i += 1;
        let mut m = BTreeMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Obj(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err("an object key is not a string".into());
            }
            let k = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err("expected ':'".into());
            }
            self.i += 1;
            let v = self.value(depth + 1)?;
            if m.insert(k.clone(), v).is_some() {
                return Err(format!("the key {k:?} appears twice in one object"));
            }
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Obj(m));
                }
                _ => return Err("expected ',' or '}'".into()),
            }
        }
    }
    fn array(&mut self, depth: usize) -> R<Value> {
        self.i += 1;
        let mut a = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Arr(a));
        }
        loop {
            a.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Arr(a));
                }
                _ => return Err("expected ',' or ']'".into()),
            }
        }
    }
    fn number(&mut self) -> R<Value> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let digits = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        let d = &self.b[digits..self.i];
        if d.is_empty() || (d.len() > 1 && d[0] == b'0') {
            return Err("not a valid JSON number".into());
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err("a fractional or exponent number is not accepted".into());
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).map_err(|e| e.to_string())?;
        if d.len() > 16 {
            return Err(format!("the integer {text} is outside +/-(2**53 - 1)"));
        }
        let n: i64 = text
            .parse()
            .map_err(|_| "not a valid JSON number".to_string())?;
        if n.abs() > MAX_SAFE_INT {
            return Err(format!("the integer {text} is outside +/-(2**53 - 1)"));
        }
        Ok(Value::Int(n))
    }
    fn hex4(&mut self) -> R<u32> {
        let h = self.b.get(self.i..self.i + 4).ok_or("a short \\u escape")?;
        let s = std::str::from_utf8(h).map_err(|e| e.to_string())?;
        let v = u32::from_str_radix(s, 16).map_err(|_| "a bad \\u escape".to_string())?;
        if !h.iter().all(|c| c.is_ascii_hexdigit()) {
            return Err("a bad \\u escape".into());
        }
        self.i += 4;
        Ok(v)
    }
    fn string(&mut self) -> R<String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("an unterminated string")?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or("an unterminated escape")?;
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
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if !self.eat(b"\\u") {
                                    return Err("a lone surrogate is not a character".into());
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err("a lone surrogate is not a character".into());
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err("a lone surrogate is not a character".into());
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or("not a character")?);
                        }
                        _ => return Err("an unknown escape".into()),
                    }
                }
                0x00..=0x1f => return Err("a raw control character in a string".into()),
                _ => {
                    let rest = &self.b[self.i..];
                    let len = match c {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    let ch = std::str::from_utf8(
                        rest.get(..len).ok_or("bytes that are not strict UTF-8")?,
                    )
                    .map_err(|_| "bytes that are not strict UTF-8".to_string())?;
                    out.push_str(ch);
                    self.i += len;
                }
            }
        }
    }
}

/// One JSON object, strictly, or the reason it is refused.
pub fn loads(raw: &[u8], max_bytes: usize, max_depth: usize) -> R<BTreeMap<String, Value>> {
    if raw.len() > max_bytes {
        return Err(format!(
            "{} bytes is more than the limit of {max_bytes}",
            raw.len()
        ));
    }
    std::str::from_utf8(raw).map_err(|_| "the bytes are not strict UTF-8".to_string())?;
    let mut p = Parser {
        b: raw,
        i: 0,
        max_depth,
    };
    let v = p.value(0)?;
    p.ws();
    if p.i != raw.len() {
        return Err("bytes after the JSON value".into());
    }
    match v {
        Value::Obj(m) => Ok(m),
        _ => Err("the top level must be an object".into()),
    }
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Str(s) => write_str(s, out),
        Value::Arr(a) => {
            out.push('[');
            for (n, item) in a.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Value::Obj(m) => {
            out.push('{');
            for (n, (k, item)) in m.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                write_str(k, out);
                out.push(':');
                write(item, out);
            }
            out.push('}');
        }
    }
}

/// The canonical bytes of a value.
pub fn canonical(v: &Value) -> Vec<u8> {
    let mut out = String::new();
    write(v, &mut out);
    out.into_bytes()
}
