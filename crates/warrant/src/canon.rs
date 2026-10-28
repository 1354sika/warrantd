//! 规范序列化（SPEC.md 3 节）—— 事件 id、签名输入、账本链位哈希。
//!
//! 域分隔前缀是硬编码常量，不是从任何库借来的行为。
//! 可执行定义 = 规范文本 + vectors/*.json；本模块逐字节对齐。

use crate::json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use unicode_normalization::UnicodeNormalization;

pub const DOMAIN_ID: &[u8] = b"warrant/v1/id\x00";
pub const DOMAIN_SIG: &[u8] = b"warrant/v1/sig\x00";
pub const DOMAIN_LINK: &[u8] = b"warrant/v1/link\x00";
pub const ID_PREFIX: &str = "sha256:";

#[derive(Debug, Clone, PartialEq)]
pub enum CanonError {
    DuplicateKey(String),
    NotAnObject,
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonError::DuplicateKey(k) => {
                write!(f, "duplicate key after NFC normalization: {k:?}")
            }
            CanonError::NotAnObject => write!(f, "top level must be an object"),
        }
    }
}

impl std::error::Error for CanonError {}

pub fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let d = h.finalize();
    hex(&d[..])
}

/// 短转义优先；其余 C0 与 DEL 用 \uXXXX（小写十六进制）；`/` 不转义。
fn escape(s: &str, out: &mut Vec<u8>) {
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

fn emit(v: &Value, out: &mut Vec<u8>) -> Result<(), CanonError> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::Str(s) => {
            let n: String = s.nfc().collect();
            out.push(b'"');
            escape(&n, out);
            out.push(b'"');
        }
        Value::Array(a) => {
            out.push(b'[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                emit(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(o) => {
            let mut norm: Vec<(String, &Value)> = Vec::with_capacity(o.len());
            for (k, val) in o {
                let nk: String = k.nfc().collect();
                if norm.iter().any(|(x, _)| *x == nk) {
                    return Err(CanonError::DuplicateKey(nk));
                }
                norm.push((nk, val));
            }
            norm.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (k, val)) in norm.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.push(b'"');
                escape(k, out);
                out.extend_from_slice(b"\":");
                emit(val, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

pub fn canonical_bytes(v: &Value) -> Result<Vec<u8>, CanonError> {
    let mut out = Vec::new();
    emit(v, &mut out)?;
    Ok(out)
}

/// 条目 body 必须是对象（SPEC.md 3 节"顶层"）。
pub fn canonical_body(body: &Value) -> Result<Vec<u8>, CanonError> {
    if !matches!(body, Value::Object(_)) {
        return Err(CanonError::NotAnObject);
    }
    canonical_bytes(body)
}

/// 事件 id = "sha256:" + hex(sha256(域前缀 || canonical(body)))
pub fn event_id(body: &Value) -> Result<String, CanonError> {
    let cb = canonical_body(body)?;
    Ok(ID_PREFIX.to_string() + &sha256_hex(&[DOMAIN_ID, &cb]))
}

/// 签名载荷。任何附加字段（reason / based_on）必须并入此处之后再签名，
/// 挂在签名对象上却不进 payload 等于没有认证。
pub fn sig_payload(entry: &str, role: &str, signer: &str, signed_at: &str) -> Value {
    Value::Object(vec![
        ("entry".to_string(), Value::Str(entry.to_string())),
        ("role".to_string(), Value::Str(role.to_string())),
        ("signer".to_string(), Value::Str(signer.to_string())),
        ("signed_at".to_string(), Value::Str(signed_at.to_string())),
    ])
}

pub fn sig_payload_with(
    entry: &str,
    role: &str,
    signer: &str,
    signed_at: &str,
    reason: Option<&str>,
    based_on: Option<&[String]>,
) -> Value {
    let mut p = match sig_payload(entry, role, signer, signed_at) {
        Value::Object(o) => o,
        _ => unreachable!(),
    };
    if let Some(r) = reason {
        p.push(("reason".to_string(), Value::Str(r.to_string())));
    }
    if let Some(b) = based_on {
        p.push((
            "based_on".to_string(),
            Value::Array(b.iter().map(|x| Value::Str(x.clone())).collect()),
        ));
    }
    Value::Object(p)
}

/// 签名输入字节 = 域前缀 || canonical(payload)
pub fn sig_bytes(payload: &Value) -> Result<Vec<u8>, CanonError> {
    let mut v = DOMAIN_SIG.to_vec();
    v.extend_from_slice(&canonical_bytes(payload)?);
    Ok(v)
}

/// 链位哈希 = sha256(域前缀 || canonical(chain))
pub fn link_hash(chain: &Value) -> Result<String, CanonError> {
    Ok(sha256_hex(&[DOMAIN_LINK, &canonical_bytes(chain)?]))
}
