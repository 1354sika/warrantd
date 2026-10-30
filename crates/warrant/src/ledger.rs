//! 账本：信封、去重、链位校验（SPEC.md 2.1 / 2.7）。
//!
//! 本模块只做结构性校验：id 与 body 是否自洽、链位是否连续。
//! 它不判断条目内容是否可信 —— 那是投影（4 节）的事。

use crate::canon;
use crate::json::{self, Value};

pub const SPEC: &str = "warrant/1";

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub spec: String,
    pub id: String,
    pub body: Value,
    pub signatures: Vec<Value>,
}

/// 从已解析的信封对象构造条目。
pub fn entry_from_value(v: &Value) -> Option<Entry> {
    let obj = v.as_object()?;
    let get = |k: &str| obj.iter().find(|(kk, _)| kk == k).map(|(_, vv)| vv);
    let spec = get("spec").and_then(|x| x.as_str()).unwrap_or(SPEC).to_string();
    let id = get("id").and_then(|x| x.as_str())?.to_string();
    let body = get("body")?.clone();
    let signatures = get("signatures")
        .and_then(|x| x.as_array())
        .map(|a| a.to_vec())
        .unwrap_or_default();
    Some(Entry { spec, id, body, signatures })
}

pub fn parse_line(line: &str) -> Result<Entry, String> {
    let v = json::parse(line).map_err(|e| e.to_string())?;
    entry_from_value(&v).ok_or_else(|| "envelope must be an object with id and body".to_string())
}

pub fn load_jsonl(text: &str) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        out.push(parse_line(t).map_err(|e| format!("ledger line {}: {}", n + 1, e))?);
    }
    Ok(out)
}

/// 按 id 合并签名集合，保持首次出现顺序（SPEC.md 2.7"签名增长"）。
pub fn dedup(entries: &[Entry]) -> Vec<Entry> {
    let mut order: Vec<String> = Vec::new();
    let mut merged: Vec<Entry> = Vec::new();
    for e in entries {
        match order.iter().position(|x| *x == e.id) {
            None => {
                order.push(e.id.clone());
                merged.push(e.clone());
            }
            Some(i) => {
                for s in &e.signatures {
                    if !merged[i].signatures.contains(s) {
                        merged[i].signatures.push(s.clone());
                    }
                }
            }
        }
    }
    merged
}

/// 链位校验：entry[n].chain.seq == n 且 prev == 前一条 id（创世 prev 为 ""）。
/// 返回全部错误；**首个即篡改点**。
pub fn verify_chain(entries: &[Entry]) -> Vec<String> {
    let d = dedup(entries);
    let mut errs = Vec::new();
    let mut prev = String::new();
    for (i, e) in d.iter().enumerate() {
        match canon::event_id(&e.body) {
            Ok(id) => {
                if id != e.id {
                    errs.push(format!("entry {i}: id does not match body"));
                }
            }
            Err(err) => errs.push(format!("entry {i}: body not canonicalizable: {err}")),
        }
        let ch = e.body.get("chain");
        let seq = ch.and_then(|c| c.get("seq")).and_then(|s| s.as_int());
        if seq != Some(i as i64) {
            errs.push(format!("entry {i}: chain.seq={seq:?} expected {i}"));
        }
        let pv = ch
            .and_then(|c| c.get("prev"))
            .and_then(|s| s.as_str())
            .unwrap_or("");
        if pv != prev {
            errs.push(format!("entry {i}: chain.prev={pv:?} expected {prev:?}"));
        }
        prev = e.id.clone();
    }
    errs
}

pub fn chain_body(seq: i64, prev: &str) -> Value {
    Value::Object(vec![
        ("seq".to_string(), Value::Int(seq)),
        ("prev".to_string(), Value::Str(prev.to_string())),
    ])
}

// ---------------------------------------------------------------------------
// [F2-2026-09-29] 签名验证。
//
// 为什么必须有：账本是**文件**，AI 与账本同机且有写权限。在补上本模块之前，
// ZeroPage **从不验证任何签名**（crates/warrant 无 ed25519 依赖，core 只签名不验签），
// 于是任何人（包括 AI）只要往 entries.jsonl 追加一条 `role:"freeze"` + `signer.kind:"human"`
// 的条目，投影就会把它算成 WARRANTED —— **连密钥都不需要**。这是"能认定"的第一道地质层。
// ---------------------------------------------------------------------------

/// base64url（无填充）解码。
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for ch in s.bytes() {
        if ch == b'=' {
            break;
        }
        let i = T.iter().position(|c| *c == ch)? as u32;
        acc = (acc << 6) | i;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// 单签名验证（alg 可扩展）：`ed25519`（32 字节公钥 / 64 字节签名）
/// 与 `es256`（SEC1 未压缩点 65 字节 / 原始 r‖s 64 字节 —— 硬件令牌与 CTAP2 口径）。
fn verify_one(alg: &str, pubkey: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), String> {
    match alg {
        "ed25519" => {
            let pka = <[u8; 32]>::try_from(pubkey).map_err(|_| "public key must be 32 bytes".to_string())?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pka)
                .map_err(|_| "invalid public key".to_string())?;
            let sv = ed25519_dalek::Signature::from_slice(sig)
                .map_err(|_| "signature must be 64 bytes".to_string())?;
            vk.verify_strict(msg, &sv).map_err(|_| "verification FAILED".to_string())
        }
        "es256" => {
            use p256::ecdsa::signature::Verifier as _;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey)
                .map_err(|_| "invalid public key".to_string())?;
            let sv = p256::ecdsa::Signature::from_slice(sig)
                .map_err(|_| "signature must be 64 bytes (raw r||s)".to_string())?;
            vk.verify(msg, &sv).map_err(|_| "verification FAILED".to_string())
        }
        other => Err(format!("unsupported alg {other:?}")),
    }
}

/// 逐条逐签名做 **密码学校验**：签名必须能由 `key_id` 内嵌的公钥、在 `canon::sig_bytes(payload)`
/// 上验证通过，且 `over` 必须指向本条目。
///
/// 注意：**本函数只证明"签名与被嵌公钥自洽"**，证明不了"这把公钥就是那位人类"。
/// 防伪造必须再叠加 [`check_key_trust`]（key_id 必须落在已登记的信任集内）。
pub fn verify_signatures(entries: &[Entry]) -> Vec<String> {
    let mut errs = Vec::new();
    for e in dedup(entries) {
        for (i, sig) in e.signatures.iter().enumerate() {
            let g = |k: &str| sig.get(k).and_then(|x| x.as_str()).unwrap_or("");
            let alg = g("alg");
            let role = g("role");
            let at = g("signed_at");
            let over = g("over");
            let sigv = g("sig");
            let key_id = g("key_id");
            let sid = sig
                .get("signer")
                .and_then(|s| s.get("id"))
                .and_then(|x| x.as_str())
                .unwrap_or("");

            if alg != "ed25519" && alg != "es256" {
                errs.push(format!("{} sig[{i}]: unsupported alg {alg:?}", e.id));
                continue;
            }
            if !over.is_empty() && over != e.id {
                errs.push(format!("{} sig[{i}]: over={over:?} is not this entry", e.id));
                continue;
            }
            let prefix = format!("{alg}:");
            let Some(pkhex) = key_id.strip_prefix(&prefix) else {
                errs.push(format!("{} sig[{i}]: bad key_id {key_id:?} for alg {alg:?}", e.id));
                continue;
            };
            let Some(pkb) = hex_decode(pkhex) else {
                errs.push(format!("{} sig[{i}]: key_id not hex", e.id));
                continue;
            };
            let Some(sb) = b64url_decode(sigv) else {
                errs.push(format!("{} sig[{i}]: sig not base64url", e.id));
                continue;
            };
            // reason / based_on 必须并入 payload 再验（SPEC §2.6：挂在签名上却不进 payload = 未认证）
            let reason = sig.get("reason").and_then(|x| x.as_str());
            let based_on: Option<Vec<String>> = sig.get("based_on").and_then(|x| x.as_array()).map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            });
            let payload = canon::sig_payload_with(&e.id, role, sid, at, reason, based_on.as_deref());
            let Ok(bytes) = canon::sig_bytes(&payload) else {
                errs.push(format!("{} sig[{i}]: payload not canonicalizable", e.id));
                continue;
            };
            if let Err(m) = verify_one(alg, &pkb, &sb, &bytes) {
                errs.push(format!("{} sig[{i}]: {m}", e.id));
            }
        }
    }
    errs
}

/// 信任锚：每个签名的 `key_id` 必须落在 `trusted`（已登记公钥集）内。
/// 没有这一步，伪造者只要自造一对密钥、把公钥写进 `key_id`，[`verify_signatures`] 也会通过。
pub fn check_key_trust(entries: &[Entry], trusted: &std::collections::HashSet<String>) -> Vec<String> {
    let mut errs = Vec::new();
    for e in dedup(entries) {
        for (i, sig) in e.signatures.iter().enumerate() {
            let key_id = sig.get("key_id").and_then(|x| x.as_str()).unwrap_or("");
            if !trusted.contains(key_id) {
                errs.push(format!("{} sig[{i}]: signer key {key_id:?} is not registered", e.id));
            }
        }
    }
    errs
}