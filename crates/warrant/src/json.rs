//! 严格 JSON 解析器 —— 只接受 SPEC.md 3 节规范档允许的形状。
//!
//! 本模块逐字符手写，不借用任何 JSON 库的宽松行为：
//! - 仅整数（禁浮点 / 指数 / 前导零 / `+`）；`-0` 归一化为 `0`（与参考实现一致，
//! 分歧已由 conformance 测试钉死，任何人不得按规范文本"修"成拒绝）；
//! - 字符串全转义面 + 代理对；裸控制字符拒绝；孤立代理拒绝；
//! - **重复键在解析阶段原样保留**（Object 用保序 Vec），合并判定交给 canon
//! 在 NFC 归一化之后执行 —— "后者胜"会让字面重复键逃过重复检测；
//! - 单文档解析：尾部多余内容即拒绝。

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Value>),
    /// 保序存放；重复键不在这里合并
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, k: &str) -> Option<&Value> {
        match self {
            Value::Object(o) => o.iter().find(|(kk, _)| kk == k).map(|(_, v)| v),
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
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct JsonError {
    pub at: usize,
    pub msg: String,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "json error at byte {}: {}", self.at, self.msg)
    }
}

impl std::error::Error for JsonError {}

type R<T> = Result<T, JsonError>;

/// 解析**单个** JSON 文档；尾部有多余内容即拒绝。
pub fn parse(text: &str) -> R<Value> {
    let mut p = Parser { b: text.as_bytes(), i: 0 };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.i != p.b.len() {
        return Err(p.err("trailing content after the single JSON value"));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, msg: &str) -> JsonError {
        JsonError { at: self.i, msg: msg.to_string() }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            match c {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                _ => break,
            }
        }
    }

    fn value(&mut self) -> R<Value> {
        match self.peek() {
            Some(b'n') => {
                self.lit("null")?;
                Ok(Value::Null)
            }
            Some(b't') => {
                self.lit("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.lit("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => Err(self.err("unexpected byte")),
            None => Err(self.err("unexpected end of input")),
        }
    }

    fn lit(&mut self, s: &str) -> R<()> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Ok(())
        } else {
            Err(self.err("bad literal"))
        }
    }

    /// 规范档只允许整数：无小数、无指数、无 `+`、无前导零。
    /// `-0` 经 i64 解析归一化为 0 —— 与参考实现一致，差异已由测试钉死。
    fn number(&mut self) -> R<Value> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        return Err(self.err("leading zero is not allowed"));
                    }
                }
            }
            Some(c) if (b'1'..=b'9').contains(&c) => {
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        self.i += 1;
                    } else {
                        break;
                    }
                }
            }
            _ => return Err(self.err("digit expected")),
        }
        if let Some(c) = self.peek() {
            if c == b'.' {
                return Err(self.err("float is forbidden in the canonical profile"));
            }
            if c == b'e' || c == b'E' {
                return Err(self.err("exponent notation is forbidden in the canonical profile"));
            }
        }
        let tok = std::str::from_utf8(&self.b[start..self.i]).unwrap();
        tok.parse::<i64>()
            .map(Value::Int)
            .map_err(|_| self.err("integer out of signed 64-bit range"))
    }

    fn string(&mut self) -> R<String> {
        if self.peek() != Some(b'"') {
            return Err(self.err("string expected"));
        }
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or_else(|| self.err("unterminated string"))?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or_else(|| self.err("unterminated escape"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            let ch = if (0xD800..=0xDBFF).contains(&cp) {
                                if self.b[self.i..].starts_with(b"\\u") {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        return Err(self.err("bad low surrogate"));
                                    }
                                    let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                    char::from_u32(c).ok_or_else(|| self.err("bad code point"))?
                                } else {
                                    return Err(self.err("lone surrogate is not a code point"));
                                }
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                return Err(self.err("lone surrogate is not a code point"));
                            } else {
                                char::from_u32(cp).ok_or_else(|| self.err("bad code point"))?
                            };
                            out.push(ch);
                        }
                        _ => return Err(self.err("unknown escape")),
                    }
                }
                c if c < 0x20 => return Err(self.err("raw control character in string")),
                _ => {
                    let s = std::str::from_utf8(&self.b[self.i..])
                        .map_err(|_| self.err("invalid utf-8"))?;
                    let ch = s.chars().next().unwrap();
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }

    fn hex4(&mut self) -> R<u32> {
        if self.i + 4 > self.b.len() {
            return Err(self.err("truncated \\u escape"));
        }
        let s = std::str::from_utf8(&self.b[self.i..self.i + 4])
            .map_err(|_| self.err("bad \\u escape"))?;
        let v = u32::from_str_radix(s, 16).map_err(|_| self.err("bad \\u escape"))?;
        self.i += 4;
        Ok(v)
    }

    fn array(&mut self) -> R<Value> {
        self.i += 1;
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(out));
        }
        loop {
            self.skip_ws();
            out.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(out));
                }
                _ => return Err(self.err("expected , or ]")),
            }
        }
    }

    fn object(&mut self) -> R<Value> {
        self.i += 1;
        let mut out: Vec<(String, Value)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(out));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("object key must be a string"));
            }
            let k = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected :"));
            }
            self.i += 1;
            self.skip_ws();
            let v = self.value()?;
            out.push((k, v));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(out));
                }
                _ => return Err(self.err("expected , or }")),
            }
        }
    }
}