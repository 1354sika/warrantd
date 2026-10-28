//! [F2-2026-09-29] 签名验证测试。
//!
//! 钉死的核心事实：在补上 `ledger::verify_signatures` + `check_key_trust` 之前，
//! ZeroPage **从不验签** ⇒ 账本（一个普通文件）可被任意追加一条
//! `role:"freeze"` + `signer.kind:"human"` 的条目就"变成事实"。

use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashSet;
use warrant::canon;
use warrant::json::Value;
use warrant::ledger::{self, Entry};

fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if i + 1 < data.len() {
            out.push(T[((n >> 6) & 63) as usize] as char);
        }
        if i + 2 < data.len() {
            out.push(T[(n & 63) as usize] as char);
        }
        i += 3;
    }
    out
}

fn key_id_of(sk: &SigningKey) -> String {
    format!("ed25519:{}", canon::hex(&sk.verifying_key().to_bytes()))
}

/// 造一条**签名自洽**的条目（role/signer.kind 由调用方指定）。
fn make_entry(
    sk: &SigningKey,
    role: &str,
    signer_kind: &str,
    seq: i64,
    prev: &str,
    tamper_sig: bool,
) -> Entry {
    let base = warrant::json::parse(
        r#"{"kind":"claim","type":"warrant://types/t.demo@1","actor":{"id":"agent:revd","kind":"ai"},"subject":{"id":"s","kind":"warrant.entry"},"action":{"verb":"v","args":{"x":1}},"expect":{"x":1},"authority":{"grant_id":"","granted_by":"user:local-operator","kind":"self"},"scope":{"valid_within":["org:local"],"valid_across":[]},"horizon":{"issued_at":"2026-01-01T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"},"parents":[],"nonce":"n"}"#,
    )
    .unwrap();
    let mut pairs = match base {
        Value::Object(p) => p,
        _ => unreachable!(),
    };
    pairs.push(("chain".to_string(), ledger::chain_body(seq, prev)));
    let body = Value::Object(pairs);
    let id = canon::event_id(&body).unwrap();

    let signer_id = "user:alice";
    let at = "2026-09-29T00:00:00Z";
    let payload = canon::sig_payload(&id, role, signer_id, at);
    let bytes = canon::sig_bytes(&payload).unwrap();
    let mut raw = sk.sign(&bytes).to_bytes();
    if tamper_sig {
        raw[0] ^= 0x01;
    }
    let sig = Value::Object(vec![
        ("alg".to_string(), Value::Str("ed25519".to_string())),
        ("key_id".to_string(), Value::Str(key_id_of(sk))),
        ("over".to_string(), Value::Str(id.clone())),
        ("role".to_string(), Value::Str(role.to_string())),
        ("sig".to_string(), Value::Str(b64url(&raw))),
        ("signed_at".to_string(), Value::Str(at.to_string())),
        (
            "signer".to_string(),
            Value::Object(vec![
                ("id".to_string(), Value::Str(signer_id.to_string())),
                ("kind".to_string(), Value::Str(signer_kind.to_string())),
            ]),
        ),
    ]);
    Entry {
        spec: ledger::SPEC.to_string(),
        id,
        body,
        signatures: vec![sig],
    }
}

#[test]
fn valid_signature_passes_crypto_and_trust() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let e = make_entry(&sk, "declare", "human", 0, "", false);
    assert!(
        ledger::verify_signatures(&[e.clone()]).is_empty(),
        "自洽签名必须通过"
    );
    let mut trusted = HashSet::new();
    trusted.insert(key_id_of(&sk));
    assert!(
        ledger::check_key_trust(&[e], &trusted).is_empty(),
        "已登记公钥必须通过"
    );
}

#[test]
fn tampered_signature_fails_crypto() {
    let sk = SigningKey::from_bytes(&[8u8; 32]);
    let e = make_entry(&sk, "declare", "human", 0, "", true);
    let errs = ledger::verify_signatures(&[e]);
    assert!(!errs.is_empty(), "被篡改的签名必须被拒");
    assert!(errs[0].contains("verification FAILED"), "{errs:?}");
}

/// **这就是那个洞**：伪造者自造一对密钥，冒充人类签 freeze。
/// 密码学自洽 ⇒ `verify_signatures` 通过；但公钥没登记 ⇒ `check_key_trust` 拦下。
/// 若只做前者（或不验签），AI 就能凭一个文件写入伪造"事实"。
#[test]
fn forged_human_freeze_is_self_consistent_but_caught_by_trust_anchor() {
    let attacker = SigningKey::from_bytes(&[9u8; 32]);
    let forged = make_entry(&attacker, "freeze", "human", 0, "", false);

    assert!(
        ledger::verify_signatures(&[forged.clone()]).is_empty(),
        "自造密钥的签名在密码学上与自己的公钥自洽（所以只验签不够）"
    );

    // 信任集里只有引擎自有两把钥 —— 攻击者的 key_id 不在其中
    let engine_a = SigningKey::from_bytes(&[1u8; 32]);
    let engine_b = SigningKey::from_bytes(&[2u8; 32]);
    let mut trusted = HashSet::new();
    trusted.insert(key_id_of(&engine_a));
    trusted.insert(key_id_of(&engine_b));

    let errs = ledger::check_key_trust(&[forged], &trusted);
    assert!(
        !errs.is_empty(),
        "未登记公钥的「人类 freeze」必须被信任锚拦下"
    );
    assert!(errs[0].contains("not registered"), "{errs:?}");
}

/// [F2-2026-09-29] 硬件令牌以 ES256 为主（FIDO2 / 智能卡），故 alg 必须可扩展。
#[test]
fn es256_token_signature_verifies_and_tamper_fails() {
    use p256::ecdsa::{signature::Signer as _, Signature as P256Sig, SigningKey as P256Sk};

    let sk = P256Sk::from_slice(&[3u8; 32]).unwrap();
    let key_id = format!(
        "es256:{}",
        canon::hex(sk.verifying_key().to_encoded_point(false).as_bytes())
    );

    let build = |tamper: bool| -> Entry {
        let base = warrant::json::parse(
            r#"{"kind":"claim","type":"warrant://types/t.demo@1","actor":{"id":"agent:revd","kind":"ai"},"subject":{"id":"s","kind":"warrant.entry"},"action":{"verb":"v","args":{"x":1}},"expect":{"x":1},"authority":{"grant_id":"","granted_by":"user:local-operator","kind":"self"},"scope":{"valid_within":["org:local"],"valid_across":[]},"horizon":{"issued_at":"2026-01-01T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"},"parents":[],"nonce":"n"}"#,
        )
        .unwrap();
        let mut pairs = match base {
            Value::Object(p) => p,
            _ => unreachable!(),
        };
        pairs.push(("chain".to_string(), ledger::chain_body(0, "")));
        let body = Value::Object(pairs);
        let id = canon::event_id(&body).unwrap();
        let at = "2026-09-29T00:00:00Z";
        let payload = canon::sig_payload(&id, "freeze", "user:alice", at);
        let bytes = canon::sig_bytes(&payload).unwrap();
        let sigv: P256Sig = sk.sign(&bytes);
        let mut raw: Vec<u8> = sigv.to_bytes().to_vec();
        assert_eq!(raw.len(), 64, "ES256 原始签名 r||s = 64 字节");
        if tamper {
            raw[0] ^= 0x01;
        }
        let sig = Value::Object(vec![
            ("alg".to_string(), Value::Str("es256".to_string())),
            ("key_id".to_string(), Value::Str(key_id.clone())),
            ("over".to_string(), Value::Str(id.clone())),
            ("role".to_string(), Value::Str("freeze".to_string())),
            ("sig".to_string(), Value::Str(b64url(&raw))),
            ("signed_at".to_string(), Value::Str(at.to_string())),
            (
                "signer".to_string(),
                Value::Object(vec![
                    ("id".to_string(), Value::Str("user:alice".to_string())),
                    ("kind".to_string(), Value::Str("human".to_string())),
                ]),
            ),
        ]);
        Entry {
            spec: ledger::SPEC.to_string(),
            id,
            body,
            signatures: vec![sig],
        }
    };

    assert!(
        ledger::verify_signatures(&[build(false)]).is_empty(),
        "ES256 签名必须通过"
    );
    let errs = ledger::verify_signatures(&[build(true)]);
    assert!(!errs.is_empty(), "篡改后的 ES256 签名必须失败");
}
