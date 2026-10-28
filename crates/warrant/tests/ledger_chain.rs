//! 一致性档 C5（信使 SPEC.md 7 节）：账本链，篡改后必须在首个不一致处报错。
//!
//! 两路验证：
//! 甲、向量 vectors/ledger_cases.json（链位 + 链位哈希）
//! 乙、**信使仓里的真实账本** ledger/entries.jsonl —— 本实现要逐条算出
//! 与文件里完全相同的 id，并判定链位连续。合成向量远不如此有力。

use std::fs;
use std::path::PathBuf;
use warrant::{canon, json, ledger};

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

fn vectors(name: &str) -> serde_json::Value {
    let p = xinshi(&["vectors", name]);
    let t = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    serde_json::from_str(&t).unwrap_or_else(|e| panic!("parse {p:?}: {e}"))
}

#[test]
fn c5_link_hash_matches_vectors() {
    let doc = vectors("ledger_cases.json");
    let recs = doc["records"].as_array().unwrap();
    assert_eq!(recs.len(), 3);
    for r in recs {
        let txt = serde_json::to_string(&r["chain"]).unwrap();
        let chain = json::parse(&txt).unwrap();
        let got = canon::link_hash(&chain).unwrap();
        assert_eq!(
            got,
            r["link"].as_str().unwrap(),
            "seq {} 的链位哈希不同",
            r["seq"]
        );
    }
}

#[test]
fn c5_vector_records_chain_positions_are_self_consistent() {
    let doc = vectors("ledger_cases.json");
    let recs = doc["records"].as_array().unwrap();
    let mut prev = String::new();
    for (i, r) in recs.iter().enumerate() {
        assert_eq!(r["chain"]["seq"].as_i64().unwrap(), i as i64, "seq 不连续");
        assert_eq!(
            r["chain"]["prev"].as_str().unwrap(),
            prev,
            "第 {i} 条 prev 指错"
        );
        prev = r["id"].as_str().unwrap().to_string();
    }
}

/// 合成一份**链自洽**的账本。序号从 0 起，每条 `chain.prev` 指向前一条的 id。
///
/// [OPEN-SOURCE-2026-10-28] 这两个测试原来读 `ledger/entries.jsonl` —— 那是**真实业务账本**
/// （609 行），里面有真实工程操作记录，**不该随开源分发**；而且它让 `cargo test`
/// 依赖一台特定机器的外部路径，别人跑必红。
/// 合成数据测的是同一套逻辑（链位连续 / id 与 body 自洽 / 篡改定位），且可随仓库走。
fn synthesize(n: usize) -> Vec<ledger::Entry> {
    let mut out: Vec<ledger::Entry> = Vec::new();
    for i in 0..n {
        let prev = out
            .last()
            .map(|e: &ledger::Entry| e.id.clone())
            .unwrap_or_default();
        let mut pairs = vec![
            ("kind".to_string(), json::Value::Str("claim".into())),
            (
                "type".to_string(),
                json::Value::Str("warrant://types/t.demo@1".into()),
            ),
            ("nonce".to_string(), json::Value::Str(format!("n{i}"))),
        ];
        pairs.push(("chain".to_string(), ledger::chain_body(i as i64, &prev)));
        let body = json::Value::Object(pairs);
        let id = canon::event_id(&body).expect("event_id");
        let env = json::Value::Object(vec![
            ("spec".to_string(), json::Value::Str(ledger::SPEC.into())),
            ("id".to_string(), json::Value::Str(id)),
            ("body".to_string(), body),
            ("signatures".to_string(), json::Value::Array(vec![])),
        ]);
        out.push(ledger::entry_from_value(&env).expect("entry"));
    }
    out
}

/// C5 主线：**链位连续 + id 与 body 自洽**，本实现能从零算出每一个 id。
#[test]
fn c5_synthetic_ledger_chain_verifies() {
    let entries = synthesize(20);
    assert_eq!(entries.len(), 20);
    let errs = ledger::verify_chain(&entries);
    assert!(errs.is_empty(), "合成账本链校验失败:\n{errs:?}");
    // 每条的 id 都必须能被重新算出来（这是"可离线复算"的最小证明）
    for e in &entries {
        assert_eq!(canon::event_id(&e.body).unwrap(), e.id, "id 必须可重算");
    }
    // 去重不该改变任何东西（没有重复行）
    assert_eq!(ledger::dedup(&entries).len(), entries.len());
}

/// 篡改检测：改动一条 body 之后，链必须在**首个不一致处**报错。
/// 两种篡改方式都要被抓到，且定位点与向量 `ledger_cases.json` 的
/// `tamper.first_bad_index = 2` 语义一致。
#[test]
fn c5_tampering_is_caught_at_the_first_inconsistent_entry() {
    let entries = synthesize(5);
    assert!(
        ledger::verify_chain(&entries).is_empty(),
        "干净账本不该报错"
    );
    let target_id = entries[1].id.clone();

    // ---- 篡改甲：只改 body，不重算 id（偷懒的篡改者）----
    // 这一条自己就"id 与 body 不符"，篡改点落在 entry 1。
    let mut lazy = entries.clone();
    for e in lazy.iter_mut() {
        if e.id == target_id {
            if let warrant::json::Value::Object(o) = &mut e.body {
                o.push(("tampered".into(), warrant::json::Value::Str("yes".into())));
            }
        }
    }
    let errs = ledger::verify_chain(&lazy);
    assert!(!errs.is_empty(), "篡改后居然没报错");
    assert!(
        errs[0].starts_with("entry 1: id does not match body"),
        "首个不一致应当是 entry 1 的 id 失配，得到: {errs:?}"
    );

    // ---- 篡改乙：改 body 并重算 id（用心的篡改者）----
    // 这时 entry 1 自己已经自洽，但它**原来的 id** 被后继条目的 chain.prev 引用着，
    // 于是首个不一致落到 entry 2 —— 正是向量里的 first_bad_index = 2。
    let mut clever = entries.clone();
    let mut new_id = String::new();
    for e in clever.iter_mut() {
        if e.id == target_id {
            if let warrant::json::Value::Object(o) = &mut e.body {
                o.push(("tampered".into(), warrant::json::Value::Str("yes".into())));
            }
            new_id = canon::event_id(&e.body).unwrap();
            e.id = new_id.clone();
        }
    }
    assert_ne!(new_id, target_id, "改了 body 之后 id 应当变");
    let errs = ledger::verify_chain(&clever);
    assert!(
        errs[0].starts_with("entry 2: chain.prev="),
        "首个不一致应当是 entry 2 的链位（与向量的 first_bad_index=2 一致），得到: {errs:?}"
    );
}
