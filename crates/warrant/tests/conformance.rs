//! 一致性档 C1-C4（信使 SPEC.md 7 节）—— 第三实现对拍。
//!
//! 被测对象 = 本 crate 自己的解析器 + 规范序列化。
//! serde_json 只用来读测试向量文件（脚手架），不参与被测路径。
//! 向量来源：信使仓 vectors/cases.json（只读夹具）。

use std::fs;
use std::path::PathBuf;
use warrant::{canon, json};

const SIG_TIME: &str = "2026-09-12T03:00:00Z";

/// 信使仓位置：可用 WARRANT_XINSHI_DIR 覆盖；默认本机桌面路径。
/// 夹具缺失时必须失败，不得跳过 —— 跳过等于假通过。
fn xinshi(parts: &[&str]) -> PathBuf {
    // [VECTORS-IN-REPO-2026-10-28] 夹具随仓库走。
    // 原来这里硬编码了某台机器上的「信使系统」目录 —— 开源后别人跑 cargo test 必然全红，
    // 而且暴露了个人路径。现在 vectors/ 已入库，路径以 CARGO_MANIFEST_DIR 为基准。
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for x in parts {
        p.push(x);
    }
    p
}

fn load(name: &str) -> serde_json::Value {
    let p = xinshi(&["vectors", name]);
    let t = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    serde_json::from_str(&t).unwrap_or_else(|e| panic!("parse {p:?}: {e}"))
}

/// 把向量的 body 重新紧致化成文本，再交给本实现自己的解析器。
fn body_of(case: &serde_json::Value) -> json::Value {
    let t = serde_json::to_string(&case["body"]).unwrap();
    json::parse(&t).unwrap_or_else(|e| panic!("own parser rejected a positive body: {e}"))
}

#[test]
fn c1_c2_c4_positive_cases() {
    let doc = load("cases.json");
    let mut checked = 0usize;
    let mut fails: Vec<String> = Vec::new();

    for case in doc["cases"].as_array().unwrap() {
        if case["kind"] != "positive" {
            continue;
        }
        let name = case["name"].as_str().unwrap().to_string();
        let body = body_of(case);

        match canon::canonical_bytes(&body) {
            Ok(cb) => {
                let got = String::from_utf8(cb.clone()).unwrap();
                let want = case["canonical"].as_str().unwrap();
                if got != want {
                    fails.push(format!(
                        "C1 {name}: canonical 字节不同\n  我方: {got}\n  向量: {want}"
                    ));
                }
                let h = canon::sha256_hex(&[&cb]);
                if h != case["canonical_sha256"].as_str().unwrap() {
                    fails.push(format!("C1 {name}: canonical_sha256 不同 ({h})"));
                }
            }
            Err(e) => {
                fails.push(format!("C1 {name}: canonical 失败: {e}"));
                continue;
            }
        }

        match canon::event_id(&body) {
            Ok(id) => {
                if id != case["id"].as_str().unwrap() {
                    fails.push(format!("C2 {name}: id 不同 ({id})"));
                }
            }
            Err(e) => fails.push(format!("C2 {name}: id 失败: {e}")),
        }

        let actor = body
            .get("actor")
            .and_then(|a| a.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("agent:pagediary") // [FIXTURE-2026-10-05] 该默认值绑定向量 sig_input_sha256；改名须信使侧同步重算
            .to_string();
        let id = case["id"].as_str().unwrap();
        let payload = canon::sig_payload(id, "declare", &actor, SIG_TIME);
        match canon::sig_bytes(&payload) {
            Ok(sb) => {
                let h = canon::sha256_hex(&[&sb]);
                if h != case["sig_input_sha256"].as_str().unwrap() {
                    fails.push(format!("C4 {name}: sig_input_sha256 不同 ({h})"));
                }
            }
            Err(e) => fails.push(format!("C4 {name}: 签名输入失败: {e}")),
        }
        checked += 1;
    }

    assert!(fails.is_empty(), "{}", fails.join("\n"));
    assert_eq!(checked, 6, "positive case 数量不对");
}

#[test]
fn c3_negative_cases_must_be_rejected() {
    let doc = load("cases.json");
    let mut rejected = 0usize;
    let mut fails: Vec<String> = Vec::new();

    for case in doc["cases"].as_array().unwrap() {
        if case["kind"] != "negative" {
            continue;
        }
        let name = case["name"].as_str().unwrap();
        let raw = case["json"].as_str().unwrap();
        let ok = match json::parse(raw) {
            Err(_) => true,
            Ok(v) => canon::canonical_body(&v).is_err(),
        };
        if ok {
            rejected += 1;
        } else {
            fails.push(format!("C3 {name}: 负例被接受了"));
        }
    }

    assert!(fails.is_empty(), "{}", fails.join("\n"));
    assert_eq!(rejected, 4, "negative case 数量不对");
}

#[test]
fn key_order_does_not_change_the_id() {
    let doc = load("cases.json");
    let mut a = None;
    let mut b = None;
    for case in doc["cases"].as_array().unwrap() {
        match case["name"].as_str() {
            Some("eda/component-replaced") => a = Some(body_of(case)),
            Some("eda/component-replaced-keyorder") => b = Some(body_of(case)),
            _ => {}
        }
    }
    let ia = canon::event_id(&a.expect("缺 case")).unwrap();
    let ib = canon::event_id(&b.expect("缺 case")).unwrap();
    assert_eq!(ia, ib, "键序改变了 id");
}

/// 分歧 1：规范文本（3 节）要求重复键"不是后者胜"，字面重复键也必须被拒绝。
/// 参考实现 canon.py 走 json.loads，站在"后者胜"一侧，静默取后者。
/// 本实现按规范文本拒绝。此分歧不在 C1-C4 向量覆盖范围内。
#[test]
fn spec_text_says_literal_duplicate_key_must_be_rejected() {
    let v = json::parse(r#"{"a":1,"a":2}"#).expect("解析器应保留重复键而不是吞掉");
    match canon::canonical_bytes(&v) {
        Err(canon::CanonError::DuplicateKey(k)) => assert_eq!(k, "a"),
        other => panic!("规范文本要求拒绝字面重复键，得到: {other:?}"),
    }
}

/// 分歧 2：规范文本说"禁……前导零、`+`、`-0`"，
/// 但参考实现把 `-0` 归一化成 `0`（json.loads("-0") -> int 0）。
/// 本实现与参考实现一致，在此钉死，免得日后按规范文本"修"成拒绝反而与向量不一致。
#[test]
fn negative_zero_is_normalised_to_zero_like_the_reference() {
    let v = json::parse(r#"{"n":-0}"#).unwrap();
    let cb = String::from_utf8(canon::canonical_bytes(&v).unwrap()).unwrap();
    assert_eq!(cb, r#"{"n":0}"#);
}

#[test]
fn nfc_normalisation_applies_to_values_too() {
    let a = json::parse("{\"s\":\"caf\u{00e9}\"}").unwrap();
    let b = json::parse("{\"s\":\"cafe\u{0301}\"}").unwrap();
    assert_eq!(
        canon::canonical_bytes(&a).unwrap(),
        canon::canonical_bytes(&b).unwrap()
    );
}
