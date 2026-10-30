//! 投影：状态是条目集合的纯函数（SPEC.md 4 / 5 节）。
//!
//! 规则只来自规范：4.1 断言比对三态 / 4.2 九档优先级 / 5 facts 与 hypotheses 分离。

use crate::json::Value;
use crate::ledger::{self, Entry};
// [FUSE-2026-09-30] 冻结要过 T1/T2 ⇒ 需要 rank::judge（四轴判定）与 FREEZE_K。
use crate::rank;
use std::collections::{HashMap, HashSet};

pub const T_GRANT: &str = "warrant://types/warrant.authority.grant@1";
pub const T_OBS: &str = "warrant://types/warrant.observation@1";
pub const T_TESTIMONY: &str = "warrant://types/warrant.testimony@1";
/// 能支撑冻结的观测档位（SPEC.md 5.1）
pub const C1_PLUS: [&str; 3] = ["C1", "C2", "C3"];

/// [FUSE-2026-09-30] 门槛是否已被**人类激活**
/// （对齐信使 `信使系统/tools/projection.py:54-70` 的 `_seek_ruling`）：
/// 取**最后一条**满足全部条件的条目——
/// ① `body.kind == "ruling"`；② `body.ruling.judgement == "C1"`；
/// ③ 它被**人类** `freeze` 过（`signatures` 里有 `role=="freeze"` 且 `signer.kind=="human"`）。
/// 返回 `Some((k, need_non_jia))`；**未激活 ⇒ `None`**（冻结只看签名，与信使逐字节一致）。
///
/// 为什么必须有这一步（实测证据）：无条件把 T1/T2 开着会**违反信使的规范向量**
/// —— `信使系统/vectors/projection_cases.json` 的 `A/frozen` 期望 `WARRANTED`，开门后得到 `DEMOTED`。
/// 信使的语义是「**人类先把这道门打开**，此后认定才需要够证据」⇒ 引擎必须同口径。
pub fn active_ruling(entries: &[Entry]) -> Option<(usize, bool)> {
    let mut found = None;
    for e in entries {
        let b = &e.body;
        if b.get("kind").and_then(|x| x.as_str()) != Some("ruling") {
            continue;
        }
        let Some(r) = b.get("ruling") else { continue };
        if r.get("judgement").and_then(|x| x.as_str()) != Some("C1") {
            continue;
        }
        let human_frozen = e.signatures.iter().any(|s| {
            s.get("role").and_then(|x| x.as_str()) == Some("freeze")
                && s.get("signer").and_then(|x| x.get("kind")).and_then(|x| x.as_str())
                    == Some("human")
        });
        if human_frozen {
            let k = r.get("k").and_then(|x| x.as_int()).unwrap_or(2).max(0) as usize;
            // 缺省 = true（与信使 `r.get("need_non_jia", True)` 同口径）
            let nn = matches!(r.get("need_non_jia"), None | Some(Value::Bool(true)));
            found = Some((k, nn));
        }
    }
    // [GATE-DEFAULT-ON-2026-10-02] **默认就是开着的**（用户裁决）。
    //
    // 原设计（信使语义）："**人类先把这道门打开**，此后认定才需要够证据" ⇒ 没人签 ruling ⇒
    // 走旧口径"**有签名就算事实**"。而 AI 的 `declare` 自签也算签 ⇒ **AI 自己就能把声明定成事实**
    // ⇒ 账本里"待你认定"**永远是 0 条** ⇒ 人根本没有发言权（真机实测：7 条账目、0 条待签）。
    //
    // 现在：**找不到人签的 C1 ruling ⇒ 默认按严格口径判**（k=2、且至少一条非甲）。
    // 人签的 ruling **仍然有效**：用来**调整** k / need_non_jia（例如显式放宽），而不是"许可证"。
    // 代价（明确记下）：丢掉"改判定规则要人签一条"的审计痕迹 —— 这是用户明确要的方向：
    // **不要仪式，默认就严；人只在真需要决定时出场**。
    found.or(Some((2, true)))
}

fn kind_of(e: &Entry) -> Option<&str> {
    e.body.get("kind").and_then(|x| x.as_str())
}

fn type_of(e: &Entry) -> Option<&str> {
    e.body.get("type").and_then(|x| x.as_str())
}

fn has_role(e: &Entry, role: &str) -> bool {
    e.signatures
        .iter()
        .any(|s| s.get("role").and_then(|x| x.as_str()) == Some(role))
}

/// 4.1 断言比对：contradicted / consistent / unknown
pub fn compare(expect: &Value, result: &Value) -> &'static str {
    let (eo, ro) = match (expect.as_object(), result.as_object()) {
        (Some(a), Some(b)) => (a, b),
        _ => return "unknown",
    };
    if eo.is_empty() || ro.is_empty() {
        return "unknown";
    }
    let mut matched = 0usize;
    for (k, v) in eo {
        if let Some((_, rv)) = ro.iter().find(|(rk, _)| rk == k) {
            if rv != v {
                return "contradicted";
            }
            matched += 1;
        }
    }
    if matched == eo.len() {
        "consistent"
    } else {
        "unknown"
    }
}

fn verdicts(claim: &Entry, obs: &[&Entry]) -> Vec<(&'static str, String)> {
    let expect = claim.body.get("expect").cloned().unwrap_or(Value::Null);
    obs.iter()
        .map(|o| {
            let ob = o.body.get("observation");
            let result = ob
                .and_then(|x| x.get("result"))
                .cloned()
                .unwrap_or(Value::Null);
            let tier = ob
                .and_then(|x| x.get("tier"))
                .and_then(|x| x.as_str())
                .unwrap_or("C0")
                .to_string();
            (compare(&expect, &result), tier)
        })
        .collect()
}

/// 4.2 九档状态，**升序判定、先命中者胜**。
///
/// [FUSE-2026-09-30] 增 `all`：让冻结能**过 T1/T2**（见下）。
/// 为什么必要（用户裁决，原话）：「**四轴 + 线代 + 智能体**……**是否完美融合，这个必须做好**，
/// 否则完美的智能体没有意义，跟普通的写代码产品没有区别」。
/// 此前引擎侧 `d_eff` 只是"展示/注记层"（状态卡、仪表盘），**不 gate 冻结** ⇒ 四轴只是提示词。
pub fn state(
    all: &[Entry],
    gate: Option<(usize, bool)>,
    entry: &Entry,
    obs: &[&Entry],
    superseded: &HashSet<String>,
    grants: Option<&HashSet<String>>,
    now: Option<&str>,
) -> &'static str {
    // [PERF-2026-10-05] 公开签名**保持不动**（外部与测试逐字节同形）：单次调用 = 建一次 O(n) 索引，
    // 与旧实现同代价。**批量判定请走 project** —— 它在全量上只建一次索引。
    state_indexed(&rank::JudgeIndex::build(all), gate, entry, obs, superseded, grants, now)
}

/// [PERF-2026-10-05] state 的**预建索引**版：唯一差别是把「每次现建的全账本索引」换成调用方共享的一份。
///
/// 为什么必要（真机事故 2026-10-05，有定量证据）：all 在原实现里**只被用在一处** —— rank::judge(all, id)，
/// 而它的定义就是 JudgeIndex::build(entries).judge(id) ⇒ **每条冻结 claim 都重建一次全账本索引**。
/// 实测（账本 4067 条 / 1561 claim / 318 条冻结）：project 单次 **789ms**、facts 744ms、hypotheses 933ms；
/// warrant/facts（facts+hypotheses）≈1.7s、warrant/pending≈0.8s，被认定面板每 3s 轮询
/// ⇒ 2.5s/3s ≈ 单核 83%（与进程实测 83.5% 吻合）；而 main.rs 的 dispatch(...).await 是**串行**的
/// ⇒ 整个引擎（含 turn/start）被堵死，表现为「卡住 / 干不了活 / 日志静默」。
///
/// **判定结果逐字节不变**：rank::judge(entries, id) 的定义就是 JudgeIndex::build(entries).judge(id)。
/// 回滚：把 project 里的 state_indexed(&jidx, …) 改回 state(&merged, …)，并删本函数。
fn state_indexed(
    index: &rank::JudgeIndex<'_>,
    gate: Option<(usize, bool)>,
    entry: &Entry,
    obs: &[&Entry],
    superseded: &HashSet<String>,
    grants: Option<&HashSet<String>>,
    now: Option<&str>,
) -> &'static str {
    if superseded.contains(&entry.id) {
        return "SUPERSEDED";
    }
    if has_role(entry, "reject") {
        return "REJECTED";
    }
    if type_of(entry) == Some(T_GRANT) {
        // grant 自举：有效性只由人类的 freeze 签名决定
        return if has_role(entry, "freeze") { "WARRANTED" } else { "PROPOSED" };
    }
    let v = verdicts(entry, obs);
    if v.iter().any(|(x, _)| *x == "contradicted") {
        return "CONTRADICTED";
    }
    let consistent_c1 = v
        .iter()
        .any(|(x, t)| *x == "consistent" && C1_PLUS.contains(&t.as_str()));
    if consistent_c1 && has_role(entry, "freeze") {
        // [FUSE-2026-09-30] **激活后**：冻结不再只看"有人签了字"，还要看"证据够不够"。
        // 对齐信使 `tools/projection.py:197-201` 的协议 §4.5 P2：
        // T1：`d_eff >= k`（ruling 里给，缺省 2） T2：至少一轴**不是「丁」**（AI 自报）
        // 不过者 ⇒ `DEMOTED`：仍被记录，但**不得当事实用**（`facts()` 只取 WARRANTED ⇒ 自动排除）。
        // 拿不出判定（judge 返回 None）时**保守降级**（宁可不当事实，不可凭空当事实）。
        // 回滚：删本段即回到"只看签名"（四轴退回提示词层，用户已明确否决）。
        let Some((k, need_non_ai)) = gate else {
            return "WARRANTED"; // 门槛未激活 ⇒ 与信使逐字节一致（历史行为）
        };
        return match index.judge(&entry.id) {
            Some(v) if v.d_eff >= k && (v.has_non_ai || !need_non_ai) => "WARRANTED",
            _ => "DEMOTED",
        };
    }
    if let Some(g) = grants {
        let gid = entry
            .body
            .get("authority")
            .and_then(|a| a.get("grant_id"))
            .and_then(|x| x.as_str());
        if gid.map(|x| !g.contains(x)).unwrap_or(true) {
            return "UNAUTHORIZED";
        }
    }
    if consistent_c1 {
        return "CONSISTENT";
    }
    if !obs.is_empty() {
        return "UNKNOWN";
    }
    let exp = entry
        .body
        .get("horizon")
        .and_then(|h| h.get("expires_at"))
        .and_then(|x| x.as_str());
    if let (Some(e), Some(n)) = (exp, now) {
        if e < n {
            return "EXPIRED";
        }
    }
    "PROPOSED"
}

/// 返回 (claim id, state)。观测条目不参与 —— 它们是投影的基元。
pub fn project(entries: &[Entry], now: Option<&str>) -> Vec<(String, &'static str)> {
    let merged = ledger::dedup(entries);
    // [FUSE-2026-09-30] 门槛激活态（人类签过 C1 ruling）**只算一次**，避免每条 claim 都重扫账本。
    let gate = active_ruling(&merged);

    let mut superseded: HashSet<String> = HashSet::new();
    for e in &merged {
        if let Some(arr) = e.body.get("supersedes").and_then(|x| x.as_array()) {
            for t in arr {
                if let Some(s) = t.as_str() {
                    superseded.insert(s.to_string());
                }
            }
        }
    }

    let mut obs: HashMap<String, Vec<&Entry>> = HashMap::new();
    for e in &merged {
        if kind_of(e) == Some("observation") {
            if let Some(sid) = e
                .body
                .get("subject")
                .and_then(|s| s.get("id"))
                .and_then(|x| x.as_str())
            {
                obs.entry(sid.to_string()).or_default().push(e);
            }
        }
    }

    let claims: Vec<&Entry> = merged
        .iter()
        .filter(|e| kind_of(e) == Some("claim"))
        .collect();

    // [PERF-2026-10-05] **判定索引只建一次**，下面两个循环共用（原实现每条冻结 claim 各建一次 O(n)）。
    let jidx = rank::JudgeIndex::build(&merged);
    let mut grants: HashSet<String> = HashSet::new();
    for e in &claims {
        if type_of(e) == Some(T_GRANT) {
            let o: &[&Entry] = obs.get(&e.id).map(|v| v.as_slice()).unwrap_or(&[]);
            if state_indexed(&jidx, gate, e, o, &superseded, None, now) == "WARRANTED" {
                grants.insert(e.id.clone());
            }
        }
    }

    claims
        .iter()
        .map(|e| {
            let o: &[&Entry] = obs.get(&e.id).map(|v| v.as_slice()).unwrap_or(&[]);
            (e.id.clone(), state_indexed(&jidx, gate, e, o, &superseded, Some(&grants), now))
        })
        .collect()
}

/// 5 节 facts()：仅 WARRANTED。**禁止提供"读一切"的合并接口。**
pub fn facts(entries: &[Entry], now: Option<&str>) -> Vec<String> {
    project(entries, now)
        .into_iter()
        .filter(|(_, s)| *s == "WARRANTED")
        .map(|(k, _)| k)
        .collect()
}

/// 5 节 hypotheses()：其余全部。**每条必须携带 state 与 actor**（SPEC.md 5 节；
/// [F1-2026-09-29] 旧实现只回 id 列表，与本条规范不符）。
pub fn hypotheses(entries: &[Entry], now: Option<&str>) -> Vec<(String, &'static str, String)> {
    let merged = ledger::dedup(entries);
    let actor_of: HashMap<&str, String> = merged
        .iter()
        .map(|e| {
            let a = e
                .body
                .get("actor")
                .and_then(|x| x.get("id"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            (e.id.as_str(), a)
        })
        .collect();
    project(entries, now)
        .into_iter()
        .filter(|(_, s)| *s != "WARRANTED")
        .map(|(k, s)| {
            let a = actor_of.get(k.as_str()).cloned().unwrap_or_default();
            (k, s, a)
        })
        .collect()
}

/// 2.5 证言读取面：不进 facts()，不参与投影。
pub fn testimonies(entries: &[Entry]) -> Vec<(String, String, String, String)> {
    let mut out = Vec::new();
    for e in ledger::dedup(entries).iter() {
        if kind_of(e) != Some("testimony") {
            continue;
        }
        let sgs: Vec<&Value> = e
            .signatures
            .iter()
            .filter(|s| s.get("role").and_then(|x| x.as_str()) == Some("declare"))
            .collect();
        let signer = match sgs.first() {
            Some(s) => s.get("signer"),
            None => continue,
        };
        if signer.and_then(|s| s.get("kind")).and_then(|x| x.as_str()) != Some("human") {
            continue;
        }
        let tm = e.body.get("testimony");
        let g = |k: &str| {
            tm.and_then(|t| t.get(k))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string()
        };
        out.push((
            e.id.clone(),
            signer
                .and_then(|s| s.get("id"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            g("statement"),
            e.body
                .get("subject")
                .and_then(|s| s.get("id"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        ));
    }
    out
}