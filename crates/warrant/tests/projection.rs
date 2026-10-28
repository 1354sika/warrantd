//! C6-C9：投影一致性（信使 SPEC.md 4 / 5 节）。
//!
//! 用 vectors/projection_cases.json 的 12 个场景验证：
//! C6 断言比对三态 C7 九档优先级 C8 读取分离 C9 grant 授权解析

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use warrant::json::{self, Value};
use warrant::ledger::{self, Entry};
use warrant::projection;

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

fn entries_from(v: &Value) -> Vec<Entry> {
    v.as_array()
        .expect("entries must be a list")
        .iter()
        .map(|x| ledger::entry_from_value(x).expect("envelope"))
        .collect()
}

#[test]
fn c6_to_c9_projection_vectors() {
    let text = fs::read_to_string(xinshi(&["vectors", "projection_cases.json"]))
        .expect("读 vectors/projection_cases.json");
    let doc = json::parse(&text).expect("vectors 必须是合法 JSON");
    let now = doc
        .get("now")
        .and_then(|x| x.as_str())
        .expect("顶层 now")
        .to_string();
    let scenarios = doc.get("scenarios").expect("scenarios").as_array().unwrap();

    let mut fails: Vec<String> = Vec::new();
    let mut states_checked = 0usize;

    for sc in scenarios {
        let name = sc.get("name").and_then(|x| x.as_str()).unwrap_or("?");
        // [GATE-DEFAULT-ON-2026-10-02] **跳过 `A/frozen`**：它是信使规范向量里"**未开门**"的场景
        // （期望 `WARRANTED` = 旧口径"有签名就算事实"）。用户裁决「**门槛默认打开**」⇒
        // 新语义下该场景应为 `DEMOTED`。向量文件在**外部仓**（信使系统/vectors/）⇒ **不改它**，
        // 改在这里跳过，并在 `freeze_gate_active_only_on_human_frozen_c1_ruling` 里钉死新语义。
        // 其余 11 个场景照旧逐字比对。
        // [GATE-DEFAULT-ON 补全 2026-10-12] 不再"跳过"：外部向量仍是旧口径（未开门 ⇒ WARRANTED），
        // 引擎新语义（门槛默认开）下该场景应 DEMOTED——**就地改写期望并逐条比对**（消测试盲区）。
        // 回滚：恢复 `if name == "A/frozen" { continue; }`。
        let expect_override: Option<(&str, &str)> = if name == "A/frozen" {
            Some(("WARRANTED", "DEMOTED"))
        } else {
            None
        };
        let entries = entries_from(sc.get("entries").expect("entries"));
        let st = projection::project(&entries, Some(&now));

        // ---- C6 / C7 / C9：主 claim 的状态，含九档优先级场景 ----
        for (k, want) in sc.get("expect").expect("expect").as_object().unwrap() {
            let mut want = want.as_str().unwrap();
            if let Some((from, to)) = expect_override {
                if want == from {
                    want = to;
                }
            }
            let have = st.iter().find(|(id, _)| id == k).map(|(_, s)| *s);
            if have != Some(want) {
                fails.push(format!(
                    "{name}: claim ..{} 期望 {want} 得到 {have:?}",
                    &k[7..15]
                ));
            }
            states_checked += 1;
        }

        // ---- C8：facts() 与向量给出的 facts_all 完全一致 ----
        let mut f_all = projection::facts(&entries, Some(&now));
        f_all.sort();
        let mut want_all: Vec<String> = sc
            .get("facts_all")
            .expect("facts_all")
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        // [GATE-DEFAULT-ON 补全 2026-10-12] 同场景 facts 期望随新语义改写（旧向量把该冻结声明记入 facts；
        // 门槛默认开后它不再是事实）。回滚：删本 if 块 + 恢复上方 continue。
        if name == "A/frozen" {
            const LEGACY_FACT: &str =
                "sha256:a829386cad4435a28259da30419e54fc311eaef887db9202086e5fde9c902d25";
            want_all.retain(|x| x != LEGACY_FACT);
        }
        if f_all != want_all {
            fails.push(format!(
                "{name}: facts_all 我方 {f_all:?} 向量 {want_all:?}"
            ));
        }

        // ---- C8：grant 本身是已认定事实，但不作为动作认定结果参与断言 ----
        let grant_ids: HashSet<String> = entries
            .iter()
            .filter(|e| e.body.get("type").and_then(|x| x.as_str()) == Some(projection::T_GRANT))
            .map(|e| e.id.clone())
            .collect();
        let f: Vec<String> = f_all
            .iter()
            .filter(|i| !grant_ids.contains(*i))
            .cloned()
            .collect();
        let mut want_f: Vec<String> = sc
            .get("facts")
            .expect("facts")
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        // [GATE-DEFAULT-ON 补全 2026-10-12] 同场景：去 grant 后新语义下无可认定事实。
        if name == "A/frozen" {
            want_f.clear();
        }
        if f != want_f {
            fails.push(format!(
                "{name}: facts(去 grant) 我方 {f:?} 期望 {want_f:?}"
            ));
        }

        // ---- C8：facts 与 hypotheses 必须互斥且完备（SPEC 5 节硬要求）----
        // [F1-2026-09-29] hypotheses() 现按 SPEC 5 节返回 (id, state, actor)；此处只取 id 做集合运算，
        // 并额外钉死「每条必须携带 state 与 actor」。
        let hp = projection::hypotheses(&entries, Some(&now));
        if hp.iter().any(|(_, s, a)| s.is_empty() || a.is_empty()) {
            fails.push(format!(
                "{name}: hypotheses 条目缺 state/actor（SPEC 5 节）"
            ));
        }
        let mut h: Vec<String> = hp.into_iter().map(|(k, _, _)| k).collect();
        h.sort();
        let mut keys: Vec<String> = st.iter().map(|(k, _)| k.clone()).collect();
        keys.sort();
        let mut union: Vec<String> = f_all.clone();
        union.extend(h.clone());
        union.sort();
        if union != keys {
            fails.push(format!(
                "{name}: facts U hypotheses 不完备\n    union {union:?}\n    keys  {keys:?}"
            ));
        }
        if f_all.iter().any(|x| h.contains(x)) {
            fails.push(format!("{name}: facts 与 hypotheses 不互斥"));
        }
    }

    assert!(
        fails.is_empty(),
        "投影向量不一致（{} 项）：\n{}",
        fails.len(),
        fails.join("\n")
    );
    assert!(
        states_checked >= 12,
        "必须覆盖全部 12 个场景的主 claim，实际 {states_checked}"
    );
}

/// [FUSE-2026-09-30] 「门槛激活」判定。
/// [GATE-DEFAULT-ON-2026-10-02] **语义已改**（用户裁决）：
/// 原设计（信使）：只有「`kind=="ruling"` + `ruling.judgement=="C1"` + **人类 freeze 签名**」
/// 才激活；未激活 ⇒ 走旧口径"有签名就算事实"。实测后果：AI 的 `declare` 自签也算签 ⇒
/// **AI 自己就能把声明定成事实** ⇒ "待你认定"恒为 0 条 ⇒ **人没有发言权**。
/// 现设计：**默认就是激活的**（k=2、need_non_jia=true）；人签的 ruling **仍有效**，用来**调整**参数。
#[test]
fn freeze_gate_active_only_on_human_frozen_c1_ruling() {
    // id 就是 64 位 hex（用 n 生成，避免手打）
    let id = |n: u32| format!("sha256:{:064x}", n);
    let one = |n: u32, body: &str, sigs: &str| {
        let text = format!(
            "[{{\"spec\":\"warrant/1\",\"id\":\"{}\",\"body\":{},\"signatures\":{}}}]",
            id(n),
            body,
            sigs
        );
        entries_from(&json::parse(&text).unwrap())
    };
    let frozen_human = r#"[{"role":"freeze","signer":{"kind":"human"}}]"#;
    let frozen_agent = r#"[{"role":"freeze","signer":{"kind":"agent"}}]"#;

    // ① 账本里没有 ruling ⇒ **默认激活**（严格口径 k=2、要求至少一条非甲）
    assert_eq!(
        projection::active_ruling(&one(1, r#"{"kind":"claim"}"#, "[]")),
        Some((2, true))
    );
    // ② 有 ruling 但**没有人类 freeze**（AI 自己签的不算）⇒ 仍是**默认严格**（自签不能放宽）
    assert_eq!(
        projection::active_ruling(&one(
            2,
            r#"{"kind":"ruling","ruling":{"judgement":"C1"}}"#,
            frozen_agent
        )),
        Some((2, true))
    );
    // ③ judgement 不是 C1 ⇒ 不被采纳为调节项 ⇒ 仍是默认严格
    assert_eq!(
        projection::active_ruling(&one(
            3,
            r#"{"kind":"ruling","ruling":{"judgement":"C2"}}"#,
            frozen_human
        )),
        Some((2, true))
    );
    // ④ 三条件齐备 ⇒ 激活；缺省 k=2、need_non_jia=true（与信使 `r.get("k") or 2` 同口径）
    assert_eq!(
        projection::active_ruling(&one(
            4,
            r#"{"kind":"ruling","ruling":{"judgement":"C1"}}"#,
            frozen_human
        )),
        Some((2, true))
    );
    // ⑤ ruling 里显式给了 k / need_non_jia ⇒ 以 ruling 为准
    assert_eq!(
        projection::active_ruling(&one(
            5,
            r#"{"kind":"ruling","ruling":{"judgement":"C1","k":1,"need_non_jia":false}}"#,
            frozen_human
        )),
        Some((1, false))
    );
    // ⑥ 取**最后一条**（最新决定覆盖旧的）——与信使 `for e in entries: found = ...` 同语义
    let six = entries_from(
        &json::parse(&format!(
            "[{{\"spec\":\"warrant/1\",\"id\":\"{}\",\"body\":{{\"kind\":\"ruling\",\"ruling\":{{\"judgement\":\"C1\",\"k\":2}}}},\"signatures\":{}}},\
              {{\"spec\":\"warrant/1\",\"id\":\"{}\",\"body\":{{\"kind\":\"ruling\",\"ruling\":{{\"judgement\":\"C1\",\"k\":3}}}},\"signatures\":{}}}]",
            id(6), frozen_human, id(7), frozen_human
        ))
        .unwrap(),
    );
    assert_eq!(projection::active_ruling(&six), Some((3, true)));
}
