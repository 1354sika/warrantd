//! 秩内核（W2）：证据轴坐标 / d_eff / I3 快照绑定。
//!
//! 纯函数叶子模块：不依赖执行层，不进主协议流。
//! 设计依据：kb/W2-设计定型-2026-09-20.md §3；真实信使账本口径
//! （冻结门槛 k=2，"d_eff=2 可冻"、"甲乙独立成轴"）。
//!
//! 轴映射（引擎口径 · [AXIS4-2026-09-29] 已与信使仓 `protocol/c1.py` 对齐）：
//! - 甲 = 我方独立通道（proc_spawn_readback，C1：新进程重开读回 / 离线复算）—— 信使的「甲」；
//! - 乙 = 被控软件自报（mcp_verify_readback，C1：同 server 只读回读）；
//! - 丙 = 人类签名（freeze）；
//! - 丁 = AI 自报（tool_receipt，C0：同会话工具回执，最弱）。
//! 认定口径：须 `d_eff ≥ FREEZE_K` 且**至少一轴非 AI 自报**（I2）。
//! 未知通道 → 不产轴（堵「编个名字就白得一根轴」的洞，对齐信使 c1.py 的域判定）。
//!
//! 不变量：
//! - I1：无非甲证据 → 结论停 TENTATIVE；
//! - I2：FREEZEABLE 需 d_eff ≥ FREEZE_K 且含非甲轴（同轴多条不增秩）；
//! - I3：一切判定输出绑定快照 sha256（含判据与合并规则版本号 RULESET_VERSION）。

use crate::canon;
use crate::json::Value;
use crate::ledger::Entry;
use crate::projection;

/// 判据与合并规则版本号：判据任何变更必须升号（I3 快照随之改变）。
/// [AXIS4-2026-09-29] revd.rank/1 → /2：轴三扩四。
/// [AXIS4R-2026-09-30 **撤回**] 回到 **/3**：
/// 我曾一度改成「甲=AI 自称 / 乙=我方独立 / 丙=软件自报 / 丁=人」—— 其依据是我**自己整理的
/// 中间产物**（一张我标注过"按你口述的模型分析"的表），**不是用户原话**。用户指出：
/// **一开始就定了「按信使来，并在信使基础上加丁=AI 自报」**（`AGENTS.md:134` 拍板原话：
/// 四轴 = **人 / AI 自报 / 系统日志 / 软件自报**）⇒ 正确编号为
/// 甲 = **系统日志**（我方独立：新进程读回/离线复算）· 乙 = 软件自报 · 丙 = 人 · 丁 = AI 自报。
/// 回到 /3 而不是继续升号：语义与 /3 完全一致（/4 只存活数小时且**从未发布**）。
/// 不改"已发送字节"（状态卡在尾部）⇒ 不伤前缀缓存。
pub const RULESET_VERSION: &str = "revd.rank/3";
/// 冻结门槛（真实信使账本口径：d_eff=2 可冻）。
pub const FREEZE_K: usize = 2;

/// [FREEZE-GATE-2026-10-02] 认定标签常量 —— **判据与消费者共用同一个名字**，
/// 避免两边各写一遍字面量而漂移（改一处、另一处静默失配）。
pub const LABEL_FREEZEABLE: &str = "FREEZEABLE";

/// 证据轴（甲乙丙丁）—— **与信使同编号 + 补一根丁**（用户定的口径，`AGENTS.md:134`）。
/// 甲 = **系统日志**（我方独立：新进程读回 / 离线复算）· 乙 = 软件自报 · 丙 = 人 · 丁 = AI 自报
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Axis {
    /// 甲：**系统日志** —— 我方独立拿到的（新进程读回 / 离线复算，C1）。= 信使的「甲」（`c_offline*`）。
    /// 为什么不叫"AI 说的"：它**不经过 AI 的嘴**（是引擎/系统侧的记录）；
    /// 但它由 AI 的动作**触发** ⇒ 所以它只算"系统日志"级别，**不等于**"人或第三方软件独立验证"。
    Jia,
    /// 乙：**软件自报** —— 被控软件自己报的（同 server 只读回读，C1）。= 信使的「乙」（`c_target_*`）。
    Yi,
    /// 丙：**人** —— 人类签名（观测 declare / 认定 freeze）。= 信使的「丙」。
    Bing,
    /// 丁：**AI 自报**（同会话工具回执，C0；最弱）—— **信使没有这一轴**，是 ZeroPage 补的。
    Ding,
}

impl Axis {
    pub fn name(self) -> &'static str {
        match self {
            Axis::Jia => "甲",
            Axis::Yi => "乙",
            Axis::Bing => "丙",
            Axis::Ding => "丁",
        }
    }

    /// 是否「非甲」（信使门槛 `NEED_NON_JIA` 口径）：甲 = 系统日志 ⇒ 判「≠甲」
    /// = "至少一条证据**不是我们自己算的**" ⇒ 必须有一条**外部见证**。
    /// **只为认定门槛（`judge` 的 FREEZEABLE）而设**；不要拿它当出口门用（见 `is_non_ai`）。
    pub fn is_non_jia(self) -> bool {
        self != Axis::Jia
    }

    /// 是否「**不是只有 AI 自报**」：丁 = AI 自报 ⇒ 判「≠丁」。
    /// 供**出口门 / 状态卡**用（"AI 到底有没有真的动过手、有没有被核验"）。
    /// [LOCK-2026-09-30] 两个判据**不同**且都必要：
    /// · `is_non_jia`（认定门槛）：排掉"只有我方系统日志"⇒ 要有外部见证；
    /// · `is_non_ai`（出口门）：排掉"只有 AI 自己说"。
    /// 曾有一次把两者合成一个字段，导致认定门槛与出口门互相掣肘（4 个测试同时红）。
    pub fn is_non_ai(self) -> bool {
        self != Axis::Ding
    }
}

/// 一条支撑证据：来源条目 + 所属轴 + 是否与 expect 一致（不一致不增秩）。
#[derive(Debug, Clone)]
pub struct Evidence {
    pub entry_id: String,
    pub axis: Axis,
    pub consistent: bool,
    /// [RULE-C-2026-09-29] 观测自报的 `observation.evidence`（该观测所依据的证据 id 列表）。
    /// 为空 ⇒ 本条**独立成轴**（与蓝本 `_fp()` 的 `("noev", id)` 同义）。
    pub evidence: Vec<String>,
}

/// 判定输出（I3：绑定快照 sha256）。
#[derive(Debug, Clone)]
pub struct RankVerdict {
    pub claim_id: String,
    pub d_eff: usize,
    /// 是否含「**非甲**」轴（[AXIS4] 原名 `has_non_jia`）—— **认定门槛专用**（信使口径）。
    /// 与 `has_non_ai`（出口门专用，判「≠丁」）**不是一回事**，两者都要。
    pub non_jia: bool,
    /// 是否含「**不是只有 AI 自报**」的轴（判「≠丁」）—— **出口门 / 状态卡专用**。
    pub has_non_ai: bool,
    /// [§4.6 F2-2026-09-29] 该 claim 挂的那条 grant 的**直接扇出是否合规**（≤ `D_MAX`）。
    /// 「万能章」（宽授权）下产生的动作**可以执行、但不能被认定** —— 这是用户裁决：
    /// 「万能公章是需要的…当信使生效的时候、或需要生效的时候就不能使用」。
    pub grant_fanout_ok: bool,
    pub axes: Vec<Axis>,
    pub label: &'static str,
    pub snapshot_sha256: String,
}

/// 观测通道 → 轴（[AXIS4-2026-09-29] 表驱动，按「主体」匹配）：
/// - `proc_spawn_readback` → 甲（我方独立：新进程读回）
/// - `mcp_verify_readback` → 乙（被控软件自报：同 server 只读回读）
/// - `tool_receipt` → 丁（AI 自报：同会话工具回执）
/// - 其余未知通道 → `None`（**不产轴**）。旧实现把未知通道一律归乙 ⇒ 等于「编个名字就白得一根轴」。
pub fn axis_of_channel(channel: &str) -> Option<Axis> {
    match channel {
        // 甲 = **系统日志**（我方独立：新进程读回 / 离线复算）
        "proc_spawn_readback" => Some(Axis::Jia),
        // 乙 = **软件自报**（被控软件自己报）
        "mcp_verify_readback" => Some(Axis::Yi),
        // 丁 = **AI 自报**（同会话工具回执，最弱；信使没有这一轴）
        "tool_receipt" => Some(Axis::Ding),
        // 丙 = **人**：人类签名（declare 观测 / freeze 认定）——目前由 `evidence_for_claim`
        // 扫人类 freeze 签名产出，**不**走通道名。未知通道一律 None（不产轴，不编造名字）。
        _ => None,
    }
}

/// 收集支撑某 claim 的证据：观测（甲/乙，标注一致性）+ 人类 freeze 签名（丙）。
/// [PERF-2026-10-03] **判定索引**：一次 O(n) 遍历预建三张表（id→条目、subject→观测、grant→扇出计数），
/// 供 `status_card` / `pending_freeze_items` 这类"对每条 claim 各判一次"的调用点复用，
/// 把 O(claims × entries) 降到 O(n)。
///
/// 为什么必要（用户裁决 2026-10-03）：状态卡**每轮**对每条 claim 调一次判定，
/// 而判定要各扫一遍全账本 ⇒ 大账本时每轮 O(n²)（封存上界 8000 时最坏到秒级）。
/// **不改变任何判定结果**（同一份 evidence、同一个扇出计数；`by_id` 取首个同 id 条目，与原 `find` 一致）。
pub struct JudgeIndex<'a> {
    by_id: std::collections::HashMap<&'a str, &'a Entry>,
    obs_by_subject: std::collections::HashMap<&'a str, Vec<&'a Entry>>,
    grant_fanout: std::collections::HashMap<&'a str, usize>,
}

impl<'a> JudgeIndex<'a> {
    pub fn build(entries: &'a [Entry]) -> Self {
        let mut by_id: std::collections::HashMap<&str, &Entry> = std::collections::HashMap::new();
        let mut obs_by_subject: std::collections::HashMap<&str, Vec<&Entry>> =
            std::collections::HashMap::new();
        let mut grant_fanout: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for e in entries {
            by_id.entry(e.id.as_str()).or_insert(e);
            match e.body.get("kind").and_then(|x| x.as_str()) {
                Some("observation") => {
                    if let Some(sid) = e
                        .body
                        .get("subject")
                        .and_then(|s| s.get("id"))
                        .and_then(|x| x.as_str())
                    {
                        obs_by_subject.entry(sid).or_default().push(e);
                    }
                }
                Some("claim") => {
                    if e.body.get("type").and_then(|x| x.as_str()) != Some(projection::T_GRANT) {
                        if let Some(g) = e
                            .body
                            .get("authority")
                            .and_then(|a| a.get("grant_id"))
                            .and_then(|x| x.as_str())
                        {
                            if !g.is_empty() {
                                *grant_fanout.entry(g).or_insert(0) += 1;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Self { by_id, obs_by_subject, grant_fanout }
    }

    /// [PERF-2026-10-05] 该 subject 名下的**全部观测条目**（走索引，O(该 subject 的观测数)）。
    /// 供「待签扫描」这类原本对每条 claim 各扫一遍全账本的调用点复用（复用同一张
    /// `obs_by_subject` 表 = 不另造轮子）。返回空切片 = 该 subject 无观测（与原全表扫同义）。
    pub fn observations_for(&self, subject_id: &str) -> &[&'a Entry] {
        self.obs_by_subject
            .get(subject_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// 同 `evidence_for_claim`，但走索引（O(该 claim 的观测数)）。
    pub fn evidence_for_claim(&self, claim_id: &str) -> Option<Vec<Evidence>> {
        let claim = *self.by_id.get(claim_id)?;
        if claim.body.get("kind").and_then(|x| x.as_str()) != Some("claim") {
            return None;
        }
        let expect = claim.body.get("expect").cloned().unwrap_or(Value::Null);
        let mut evs = Vec::new();
        if let Some(obs) = self.obs_by_subject.get(claim_id) {
            for e in obs {
                let ob = e.body.get("observation").cloned().unwrap_or(Value::Null);
                let result = ob.get("result").cloned().unwrap_or(Value::Null);
                let channel = ob.get("channel").and_then(|x| x.as_str()).unwrap_or("");
                let evidence: Vec<String> = ob
                    .get("evidence")
                    .and_then(|x| x.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if let Some(axis) = axis_of_channel(channel) {
                    evs.push(Evidence {
                        entry_id: e.id.clone(),
                        axis,
                        consistent: projection::compare(&expect, &result) == "consistent",
                        evidence,
                    });
                }
            }
        }
        // 丙轴：人类 freeze 签名（结构判定；密码学校验归 ledger/projection）
        for sig in &claim.signatures {
            let is_freeze = sig.get("role").and_then(|x| x.as_str()) == Some("freeze");
            let is_human = sig
                .get("signer")
                .and_then(|s| s.get("kind"))
                .and_then(|x| x.as_str())
                == Some("human");
            if is_freeze && is_human {
                evs.push(Evidence {
                    entry_id: format!("{claim_id}#freeze"),
                    axis: Axis::Bing,
                    consistent: true,
                    evidence: Vec::new(),
                });
            }
        }
        Some(evs)
    }

    /// [§4.6 F2] 该 claim 挂的 grant 的**直接扇出**是否合规（≤ `D_MAX`）—— 走索引。
    fn grant_fanout_ok(&self, claim_id: &str) -> bool {
        let gid = self
            .by_id
            .get(claim_id)
            .and_then(|e| e.body.get("authority"))
            .and_then(|a| a.get("grant_id"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if gid.is_empty() {
            // 无授权信息可核（如 grant 自举自身）⇒ 本闸不拦，交给别的规则
            return true;
        }
        self.grant_fanout.get(gid).copied().unwrap_or(0) <= crate::graph::D_MAX
    }

    /// 同 `judge`，但走索引。
    pub fn judge(&self, claim_id: &str) -> Option<RankVerdict> {
        let evs = self.evidence_for_claim(claim_id)?;
        // [RULE-C-2026-09-29] 轴集合 = 按轴归并 + 协议 §2.2 的证据合并（只降不升）
        let axes: Vec<Axis> = merge_by_evidence(&evs);
        let d = axes.len();
        // [§4.6 F2-2026-09-29] **认定门**：宽授权（万能章）下的动作可执行、不可认定
        let non_jia = axes.iter().any(|a| a.is_non_jia());
        let has_non_ai = axes.iter().any(|a| a.is_non_ai());
        let fanout_ok = self.grant_fanout_ok(claim_id);
        let label = if d == 0 {
            "UNOBSERVED"
        } else if d >= FREEZE_K && non_jia && fanout_ok {
            LABEL_FREEZEABLE
        } else {
            "TENTATIVE"
        };
        let snapshot = snapshot_sha256(claim_id, &evs, d, label);
        Some(RankVerdict {
            claim_id: claim_id.to_string(),
            d_eff: d,
            non_jia,
            has_non_ai,
            grant_fanout_ok: fanout_ok,
            axes,
            label,
            snapshot_sha256: snapshot,
        })
    }
}

/// claim 不存在 → None。
///
/// [PERF-2026-10-03] 便捷包装（内部建索引再取，单次 O(n)）。**批量**判定请用 `JudgeIndex`。
pub fn evidence_for_claim(entries: &[Entry], claim_id: &str) -> Option<Vec<Evidence>> {
    JudgeIndex::build(entries).evidence_for_claim(claim_id)
}

/// [协议 §3.1] **证据重叠率 `J`**：`|A ∩ B| / |A ∪ B|`（A、B 为两条观测的 `evidence` 集合）。
///
/// 用途仅止于**筛查**（`J = 1` ⇒ 直接判为同一来源）；**最终一律以 `d_eff` 为准**。
/// 两侧都空 ⇒ 返回 `0.0` 而**不是** `1.0`：空集之间没有"重叠"可言，不编造。
pub fn jaccard_evidence(a: &[String], b: &[String]) -> f64 {
    let sa: std::collections::HashSet<&String> = a.iter().collect();
    let sb: std::collections::HashSet<&String> = b.iter().collect();
    let uni = sa.union(&sb).count();
    if uni == 0 {
        return 0.0;
    }
    sa.intersection(&sb).count() as f64 / uni as f64
}

fn is_subset_of(a: &[String], b: &[String]) -> bool {
    a.iter().all(|x| b.contains(x))
}

/// 最大**互不包含族**（antichain）的大小。
/// 规模小时**精确**（暴力枚举，n ≤ 12）；更大时退化为按大小贪心并**如实标注为下界**。
fn antichain_max(sets: &[Vec<String>]) -> usize {
    let n = sets.len();
    if n == 0 {
        return 0;
    }
    if n <= 12 {
        let mut best = 0usize;
        for mask in 1u32..(1u32 << n) {
            let mut ok = true;
            let mut c = 0usize;
            for i in 0..n {
                if mask & (1 << i) == 0 {
                    continue;
                }
                c += 1;
                for j in (i + 1)..n {
                    if mask & (1 << j) == 0 {
                        continue;
                    }
                    if is_subset_of(&sets[i], &sets[j]) || is_subset_of(&sets[j], &sets[i]) {
                        ok = false;
                        break;
                    }
                }
                if !ok {
                    break;
                }
            }
            if ok {
                best = best.max(c);
            }
        }
        return best;
    }
    // 规模化降级：按集合大小升序贪心取互不包含者（**下界**，非精确最大值）
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| sets[i].len());
    let mut picked: Vec<&Vec<String>> = Vec::new();
    for i in order {
        if picked
            .iter()
            .all(|p| !is_subset_of(p, &sets[i]) && !is_subset_of(&sets[i], p))
        {
            picked.push(&sets[i]);
        }
    }
    picked.len()
}

/// [协议 §3.3] **横截性 `τ`**：各失效域（轴）内「极大互不包含族」的最大大小。
///
/// 直观含义：**同一个域里有几份互不包含的来源** —— 互相包含的那些其实是同一份。
/// `evidence` 全空时每域各算一份 ⇒ `τ = 1`（诚实：每个域只有一份来源）。
pub fn tau(entries: &[Entry], claim_id: &str) -> usize {
    let Some(evs) = evidence_for_claim(entries, claim_id) else {
        return 0;
    };
    let mut by_axis: std::collections::HashMap<Axis, Vec<Vec<String>>> =
        std::collections::HashMap::new();
    for e in evs.iter().filter(|e| e.consistent) {
        let mut ev = e.evidence.clone();
        ev.sort();
        ev.dedup();
        by_axis.entry(e.axis).or_default().push(ev);
    }
    by_axis.values().map(|sets| antichain_max(sets)).max().unwrap_or(0)
}



/// 轴强弱（越大越"强"）：**人 > 系统日志 > 软件自报 > AI 自报**。
/// [RULE-C] 合并时取**更弱**者 —— 更保守（弱轴更不容易满足「含非甲轴」）。
fn axis_strength(a: Axis) -> u8 {
    match a {
        Axis::Bing => 3, // 丙 = 人
        Axis::Jia => 2,  // 甲 = 系统日志（我方独立）
        Axis::Yi => 1,   // 乙 = 软件自报
        Axis::Ding => 0, // 丁 = AI 自报
    }
}

fn is_subset(a: &[String], b: &[String]) -> bool {
    a.iter().all(|x| b.contains(x))
}

/// [RULE-C-2026-09-29] 协议《线性代数 v1.0》§2.2 **规则 C 的「证据合并」**：
/// 两条观测若 `evidence` **非空**且**相等或互为子集**（串联判据）⇒ 视为**同一份证据**
/// ⇒ 合并为一根轴，轴取**更弱**者。
/// 性质：`d_eff` **只降不升** ⇒ 只可能**更难**被认定（安全方向）；`evidence` 为空时
/// **每条独立成组**（与蓝本 `_fp()` 的 `("noev", id)` 同义），故对现有账本**零影响**。
fn merge_by_evidence(evs: &[Evidence]) -> Vec<Axis> {
    let mut groups: Vec<(Vec<String>, Axis)> = Vec::new();
    for e in evs.iter().filter(|e| e.consistent) {
        if e.evidence.is_empty() {
            groups.push((Vec::new(), e.axis));
            continue;
        }
        let mut ev: Vec<String> = e.evidence.clone();
        ev.sort();
        ev.dedup();
        let hit = groups
            .iter_mut()
            .find(|(g, _)| !g.is_empty() && (is_subset(&ev, g) || is_subset(g, &ev)));
        match hit {
            Some((g, ax)) => {
                for x in &ev {
                    if !g.contains(x) {
                        g.push(x.clone());
                    }
                }
                if axis_strength(e.axis) < axis_strength(*ax) {
                    *ax = e.axis;
                }
            }
            None => groups.push((ev, e.axis)),
        }
    }
    let mut axes: Vec<Axis> = groups.iter().map(|(_, a)| *a).collect();
    axes.sort();
    axes.dedup();
    axes
}

/// d_eff = 一致证据的独立轴计数（同轴多条不增秩，I2 防"一次观测记两条"；
/// [RULE-C] 另叠加协议 §2.2 的证据合并，见 `merge_by_evidence`）。
pub fn d_eff(evs: &[Evidence]) -> usize {
    merge_by_evidence(evs).len()
}

/// 判定：UNOBSERVED（无一致证据）/ TENTATIVE（I1/I2：秩不足或缺非甲）/ FREEZEABLE。
///
/// [PERF-2026-10-03] 便捷包装（内部建索引，单次 O(n)）。
/// **对多条 claim 批量判定**（如状态卡、待签列表）请改用 `JudgeIndex`，避免 O(n²)。
pub fn judge(entries: &[Entry], claim_id: &str) -> Option<RankVerdict> {
    JudgeIndex::build(entries).judge(claim_id)
}

/// I3 快照：sha256(规则版本号 ‖ claim ‖ 排序后证据清单 ‖ d_eff ‖ 判定标签)。
pub fn snapshot_sha256(claim_id: &str, evs: &[Evidence], d_eff: usize, label: &str) -> String {
    let mut items: Vec<String> = evs
        .iter()
        .map(|e| format!("{}:{}:{}", e.entry_id, e.axis.name(), e.consistent))
        .collect();
    items.sort();
    let text = format!("{RULESET_VERSION}|{claim_id}|{}|{d_eff}|{label}", items.join(","));
    format!("{}{}", canon::ID_PREFIX, canon::sha256_hex(&[text.as_bytes()]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;
    use crate::ledger::SPEC;

    fn entry(id: &str, body: &str, signatures: Vec<Value>) -> Entry {
        Entry {
            spec: SPEC.to_string(),
            id: id.to_string(),
            body: json::parse(body).unwrap(),
            signatures,
        }
    }

    fn claim(id: &str, expect_sha: &str, signatures: Vec<Value>) -> Entry {
        let body = format!(
            r#"{{"kind":"claim","type":"warrant://types/t.write@1","expect":{{"path":"p","content_sha256":"{expect_sha}"}}}}"#
        );
        entry(id, &body, signatures)
    }

    fn obs(id: &str, claim_id: &str, channel: &str, result_sha: &str) -> Entry {
        let body = format!(
            r#"{{"kind":"observation","subject":{{"id":"{claim_id}","kind":"warrant.entry"}},"observation":{{"channel":"{channel}","tier":"C1","method":"m","observed_at":"t","result":{{"path":"p","content_sha256":"{result_sha}"}}}}}}"#
        );
        entry(id, &body, vec![])
    }

    /// [RULE-C] 带 `evidence` 的观测（验证协议 §2.2 的证据合并）。
    fn obs_ev(id: &str, claim_id: &str, channel: &str, result_sha: &str, ev: &[&str]) -> Entry {
        let evs = ev.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(",");
        let body = format!(
            r#"{{"kind":"observation","subject":{{"id":"{claim_id}","kind":"warrant.entry"}},"observation":{{"channel":"{channel}","tier":"C1","method":"m","observed_at":"t","evidence":[{evs}],"result":{{"path":"p","content_sha256":"{result_sha}"}}}}}}"#
        );
        entry(id, &body, vec![])
    }

    /// [RULE-C-2026-09-29] 协议 §2.2「证据合并」：两条观测 `evidence` 相同/包含 ⇒ 同一份证据
    /// ⇒ 合并为一根轴，且轴取**更弱**者（`d_eff` 只降不升 ⇒ 只会更难认定）。
    #[test]
    fn same_evidence_merges_into_one_axis() {
        let es = vec![
            claim("c1", "aaa", vec![]),
            obs_ev("o1", "c1", "proc_spawn_readback", "aaa", &["f1"]),
            obs_ev("o2", "c1", "tool_receipt", "aaa", &["f1"]),
        ];
        let v = judge(&es, "c1").unwrap();
        assert_eq!(v.d_eff, 1, "同一份证据（甲与丁）⇒ 合并为一轴: {v:?}");
        assert_eq!(v.axes, vec![Axis::Ding], "合并后取更弱者（丁 = AI 自报）: {v:?}");
        assert!(!v.has_non_ai, "合并后只剩丁 ⇒ 不满足『含非甲轴』");
        assert_eq!(v.label, "TENTATIVE");

        // 证据不同 ⇒ 不合并（仍两轴）
        let es2 = vec![
            claim("c1", "aaa", vec![]),
            obs_ev("o1", "c1", "proc_spawn_readback", "aaa", &["f1"]),
            obs_ev("o2", "c1", "tool_receipt", "aaa", &["f2"]),
        ];
        assert_eq!(judge(&es2, "c1").unwrap().d_eff, 2, "不同证据不得合并");

        // evidence 为空 ⇒ 各自独立成组（与现有账本行为一致、零回归）
        let es3 = vec![
            claim("c1", "aaa", vec![]),
            obs("o1", "c1", "proc_spawn_readback", "aaa"),
            obs("o2", "c1", "tool_receipt", "aaa"),
        ];
        assert_eq!(judge(&es3, "c1").unwrap().d_eff, 2, "空证据不得相互合并");
    }

    /// [协议 §3.1/§3.3] `J`（重叠率）与 `τ`（横截性）：
    /// 空 evidence ⇒ τ=1（每域一份来源）；同域两份互不包含 ⇒ 2；互相包含 ⇒ 1（其实是同一份）。
    #[test]
    fn jaccard_and_tau_behave() {
        let e = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        // J：两侧都空 ⇒ 0.0（**不编造 1.0**）
        assert!((jaccard_evidence(&e(&[]), &e(&[])) - 0.0).abs() < 1e-9);
        // 完全相同 ⇒ 1.0；完全不同 ⇒ 0.0；半重叠 ⇒ 1/3
        assert!((jaccard_evidence(&e(&["f1"]), &e(&["f1"])) - 1.0).abs() < 1e-9);
        assert!((jaccard_evidence(&e(&["f1"]), &e(&["f2"])) - 0.0).abs() < 1e-9);
        assert!((jaccard_evidence(&e(&["f1", "f2"]), &e(&["f1", "f3"])) - 1.0 / 3.0).abs() < 1e-9);

        // τ：evidence 全空 ⇒ 每域各一份 ⇒ 1
        let es = vec![
            claim("c1", "aaa", vec![]),
            obs("o1", "c1", "proc_spawn_readback", "aaa"),
            obs("o2", "c1", "tool_receipt", "aaa"),
        ];
        assert_eq!(tau(&es, "c1"), 1, "全空 evidence ⇒ 每域一份来源");

        // τ：**同一域**内两份互不包含 ⇒ 2
        let es2 = vec![
            claim("c1", "aaa", vec![]),
            obs_ev("o1", "c1", "proc_spawn_readback", "aaa", &["f1"]),
            obs_ev("o2", "c1", "proc_spawn_readback", "aaa", &["f2"]),
        ];
        assert_eq!(tau(&es2, "c1"), 2, "同域两份互不包含 ⇒ τ=2");

        // τ：同一域内**互相包含** ⇒ 1（其实是同一份来源）
        let es3 = vec![
            claim("c1", "aaa", vec![]),
            obs_ev("o1", "c1", "proc_spawn_readback", "aaa", &["f1"]),
            obs_ev("o2", "c1", "proc_spawn_readback", "aaa", &["f1", "f2"]),
        ];
        assert_eq!(tau(&es3, "c1"), 1, "互相包含 ⇒ 同一份 ⇒ τ=1");
    }

    /// 挂在某条 grant 下的 claim（用于验证 §4.6 F2 的“认定门”）。
    fn claim_under(id: &str, expect_sha: &str, grant: &str) -> Entry {
        entry(
            id,
            &format!(
                r#"{{"kind":"claim","type":"warrant://types/t.write@1","authority":{{"grant_id":"{grant}"}},"expect":{{"path":"p","content_sha256":"{expect_sha}"}}}}"#
            ),
            vec![],
        )
    }

    /// [§4.6 F2-2026-09-29] **认定门**：宽授权（grant 扇出 > `D_MAX`）下的 claim
    /// **可以执行、但不能被认定** —— 用户裁决：「万能章是需要的…当信使生效的时候就不能使用」。
    #[test]
    fn wide_authorization_blocks_recognition() {
        let mut es = vec![
            entry(
                "g1",
                r#"{"kind":"claim","type":"warrant://types/warrant.authority.grant@1","parents":[]}"#,
                vec![],
            ),
            claim_under("c1", "aaa", "g1"),
            obs("o1", "c1", "proc_spawn_readback", "aaa"),
            obs("o2", "c1", "tool_receipt", "aaa"),
        ];
        // 再挂 12 条到同一 grant ⇒ 扇出 13 > D_MAX(10)
        for i in 0..12 {
            es.push(claim_under(&format!("cx{i}"), "aaa", "g1"));
        }
        let v = judge(&es, "c1").unwrap();
        assert_eq!(v.d_eff, 2, "轴数照旧（门不影响 d_eff）");
        assert!(v.has_non_ai);
        assert!(!v.grant_fanout_ok, "扇出 13 > D_MAX ⇒ 授权不合规");
        assert_eq!(v.label, "TENTATIVE", "宽授权下不得认定为可冻");

        // 反向：扇出合规（只有 1 条）⇒ 仍可认定
        let small = vec![
            entry(
                "g1",
                r#"{"kind":"claim","type":"warrant://types/warrant.authority.grant@1","parents":[]}"#,
                vec![],
            ),
            claim_under("c1", "aaa", "g1"),
            obs("o1", "c1", "proc_spawn_readback", "aaa"),
            obs("o2", "c1", "tool_receipt", "aaa"),
        ];
        let v2 = judge(&small, "c1").unwrap();
        assert!(v2.grant_fanout_ok && v2.label == "FREEZEABLE", "窄授权下仍可认定");
    }

    fn human_freeze() -> Value {
        json::parse(r#"{"role":"freeze","signer":{"id":"user:op","kind":"human"}}"#).unwrap()
    }

    #[test]
    fn same_axis_multiple_observations_do_not_increase_rank() {
        let es = vec![
            claim("c1", "aaa", vec![]),
            obs("o1", "c1", "tool_receipt", "aaa"),
            obs("o2", "c1", "tool_receipt", "aaa"),
        ];
        let v = judge(&es, "c1").unwrap();
        assert_eq!(v.d_eff, 1, "同轴多条证据不增秩（I2）");
        // tool_receipt = **丁（AI 自报）**。
        assert_eq!(v.axes, vec![Axis::Ding]);
        assert!(!v.has_non_ai);
        assert_eq!(v.label, "TENTATIVE", "I1：无非甲证据停 TENTATIVE");
    }

    #[test]
    fn two_independent_axes_are_freezeable() {
        let es = vec![
            claim("c1", "aaa", vec![]),
            obs("o1", "c1", "tool_receipt", "aaa"),
            obs("o2", "c1", "proc_spawn_readback", "aaa"),
        ];
        let v = judge(&es, "c1").unwrap();
        assert_eq!(v.d_eff, 2, "甲（系统日志/我方独立）+ 丁（AI 自报）独立成轴");
        assert!(v.has_non_ai, "含甲轴 ⇒ 非「我们自己算的」⇒ 过门槛");
        assert_eq!(v.label, "FREEZEABLE", "d_eff=2 且含非 AI 轴 ⇒ 可冻");
    }

    #[test]
    fn contradicted_observation_does_not_increase_rank() {
        let es = vec![
            claim("c1", "aaa", vec![]),
            obs("o1", "c1", "tool_receipt", "aaa"),
            obs("o2", "c1", "proc_spawn_readback", "WRONG"),
        ];
        let v = judge(&es, "c1").unwrap();
        assert_eq!(v.d_eff, 1, "相悖观测不支撑结论、不增秩");
        assert_eq!(v.label, "TENTATIVE");
    }

    /// 人的轴 = **丙**（与信使同编号）。
    #[test]
    fn human_freeze_counts_as_bing_axis() {
        let es = vec![
            claim("c1", "aaa", vec![human_freeze()]),
            obs("o1", "c1", "tool_receipt", "aaa"),
        ];
        let v = judge(&es, "c1").unwrap();
        // enum 序 Jia(甲) < Yi(乙) < Bing(丙) < Ding(丁)；tool_receipt 现为丁。
        assert_eq!(v.axes, vec![Axis::Bing, Axis::Ding]);
        assert_eq!(v.d_eff, 2);
        assert_eq!(v.label, "FREEZEABLE");
    }

    #[test]
    fn ai_freeze_signature_is_not_bing_axis() {
        let ai_sig =
            json::parse(r#"{"role":"freeze","signer":{"id":"agent:x","kind":"ai"}}"#).unwrap();
        let es = vec![claim("c1", "aaa", vec![ai_sig]), obs("o1", "c1", "tool_receipt", "aaa")];
        let v = judge(&es, "c1").unwrap();
        assert_eq!(v.d_eff, 1, "非人类 freeze 不计丙轴");
    }

    #[test]
    fn unobserved_claim_is_unobserved() {
        let es = vec![claim("c1", "aaa", vec![])];
        let v = judge(&es, "c1").unwrap();
        assert_eq!(v.d_eff, 0);
        assert_eq!(v.label, "UNOBSERVED");
        assert!(v.snapshot_sha256.starts_with("sha256:"));
    }

    #[test]
    fn snapshot_binds_ruleset_evidence_and_verdict() {
        let es1 = vec![claim("c1", "aaa", vec![]), obs("o1", "c1", "proc_spawn_readback", "aaa")];
        let es2 = vec![claim("c1", "aaa", vec![]), obs("o2", "c1", "proc_spawn_readback", "aaa")];
        let v1 = judge(&es1, "c1").unwrap();
        let v2 = judge(&es1, "c1").unwrap();
        let v3 = judge(&es2, "c1").unwrap();
        assert_eq!(v1.snapshot_sha256, v2.snapshot_sha256, "同输入同快照（确定性）");
        assert_ne!(v1.snapshot_sha256, v3.snapshot_sha256, "证据变 ⇒ 快照变（I3 绑定）");
        assert!(v1.snapshot_sha256.starts_with(canon::ID_PREFIX));
    }

    #[test]
    fn unknown_claim_returns_none() {
        let es = vec![claim("c1", "aaa", vec![])];
        assert!(judge(&es, "nope").is_none());
    }
}