//! 证据图（W2）：扇出计数与无环检测（邻接矩阵幂零 A^N=0）。
//!
//! 纯函数叶子模块，不依赖执行层。边 = 依据 → 结论：
//! - 观测条目 → 其 subject 指向的 claim（观测支撑结论）；
//! - 非观测条目：parents / authority.grant_id → 本条目（依据在前）。
//! 观测条目的 parents 不建边——避免与 subject 边构成伪环
//! （引擎 W1 口径：观测的 parents = claim_id，语义是"关于"，不是"依据"）。
//! 设计依据：kb/W2-设计定型-2026-09-20.md §3.4。

use crate::json::Value;
use crate::ledger::Entry;
use std::collections::{HashMap, HashSet};

/// ④扇出上限（设计定型 §4）：单条依据支撑结论数超此值即记录违例（判定层，不阻塞）。
pub const D_MAX: usize = 10;

/// [协议 §3.4] 证据链**深度上限 `N_MAX`**。
/// 超限 ⇒ **拒绝入账**（ZeroPage 的默认裁决，见 `PROTOCOL.md` 顶部状态表；改这里等于改判据）。
///
/// [X-DEPTH-2026-10-02] 16 ⇒ **32**：真机事故暴露——闸的原意是拦「**推论叠推论**」，
/// 但**授权链（grant amend）也算进了深度**：历史上每次加一种副作用类型就 amend 一次、
/// 每次串链接，累计到 16 层后，**每个新动作 claim 的深度恒为 17 ⇒ 账本每轮全拒收**（瘫痪）。
/// 治本已做（amend 的 parents 留空，见 `amend_grant`）；这里抬到 32 是**兜底**
/// —— 万一还有别的链式累积，给足余量，不至于再次「一超限就全瘫」。
pub const N_MAX: usize = 32;

/// 证据图：节点 = 账本条目 id；边 = (from, to) 索引对（依据 → 结论）。
#[derive(Debug, Clone, Default)]
pub struct EvidenceGraph {
    pub nodes: Vec<String>,
    pub edges: Vec<(usize, usize)>,
}

/// 从账本条目建图。边去重；指向未知 id 的边忽略（诚实：不给幻影建边）。
pub fn build(entries: &[Entry]) -> EvidenceGraph {
    let mut nodes: Vec<String> = Vec::new();
    let mut idx: HashMap<String, usize> = HashMap::new();
    for e in entries {
        if !idx.contains_key(&e.id) {
            idx.insert(e.id.clone(), nodes.len());
            nodes.push(e.id.clone());
        }
    }
    let mut edge_set: HashSet<(usize, usize)> = HashSet::new();
    let add_edge = |from: &str, to: &str, edge_set: &mut HashSet<(usize, usize)>| {
        if let (Some(f), Some(t)) = (idx.get(from), idx.get(to)) {
            edge_set.insert((*f, *t));
        }
    };
    for e in entries {
        let kind = e.body.get("kind").and_then(|x| x.as_str()).unwrap_or("");
        if kind == "observation" {
            // 观测支撑结论：obs → subject claim
            if let Some(sid) = e
                .body
                .get("subject")
                .and_then(|s| s.get("id"))
                .and_then(|x| x.as_str())
            {
                add_edge(&e.id, sid, &mut edge_set);
            }
        } else {
            // 非观测条目：parents 是"依据"（依据在前 → 本条目）
            match e.body.get("parents") {
                Some(Value::Str(p)) => add_edge(p, &e.id, &mut edge_set),
                Some(Value::Array(ps)) => {
                    for p in ps {
                        if let Some(pid) = p.as_str() {
                            add_edge(pid, &e.id, &mut edge_set);
                        }
                    }
                }
                _ => {}
            }
            // grant 授权支撑 claim：grant → 本条目
            //
            // [X-DEPTH-FIX-2026-10-04] **授权不是推论依据**：`authority.grant_id` 表达的是
            // 「谁能做」（授权谱系），不是「凭什么成立」（推论依据）。若把 grant→grant 的
            // 换章链也当证据边，授权谱系会随账本单调累积——`rotate_grant_if_full` 每满
            // D_MAX=10 条 claim 就换发一枚新 grant 并以 `authority.grant_id` 指向旧章，
            // 累计到 N_MAX 层后，**每个新 claim 深度恒为 N_MAX+1 ⇒ 账本整体拒收**（瘫痪）。
            // 真机事故已复现两次：2026-10-02 depth 17、2026-10-04 depth 33（163 条 refused）。
            // 治法：当条目**自身是 grant** 时不建这条边，只断 grant→grant；claim→grant 边保留
            // ⇒ grant 深度恒 1、claim 恒 2（观测为源、恒 1），与授权链长度无关。
            // 语义核对：X-DEPTH 的原意是拦「推论叠推论」；观察/claim 的实质依据链不受影响。
            // 回滚方式：删除下面 `if !is_grant` 判断（恢复无条件建边）——但**回滚后现有账本
            // 会立即再次锁死**（grant 链仍在），故回滚须与「重签信任锚另起谱系」配套。
            let is_grant =
                e.body.get("type").and_then(|x| x.as_str()) == Some(crate::projection::T_GRANT);
            if !is_grant {
                if let Some(gid) = e
                    .body
                    .get("authority")
                    .and_then(|a| a.get("grant_id"))
                    .and_then(|x| x.as_str())
                {
                    if !gid.is_empty() {
                        add_edge(gid, &e.id, &mut edge_set);
                    }
                }
            }
        }
    }
    let mut edges: Vec<(usize, usize)> = edge_set.into_iter().collect();
    edges.sort();
    EvidenceGraph { nodes, edges }
}

impl EvidenceGraph {
    /// [协议 §3.4] 该节点的**深度 `N`**：沿「依据 → 结论」方向、从**根**到它的**最长链**长度
    /// （根 = 1）。未知节点 ⇒ `0`（不编造）。有环时按已访问剪断（真环由 `cyclic_nodes` 单独报）。
    pub fn depth_of(&self, node: &str) -> usize {
        match self.nodes.iter().position(|n| n == node) {
            None => 0,
            Some(i) => {
                let mut seen: HashSet<usize> = HashSet::new();
                self.depth_at(i, &mut seen)
            }
        }
    }

    fn depth_at(&self, i: usize, seen: &mut HashSet<usize>) -> usize {
        if !seen.insert(i) {
            return 0; // 环 ⇒ 剪断，不假装有深度
        }
        let mut best = 0usize;
        for (f, t) in &self.edges {
            if *t == i {
                best = best.max(self.depth_at(*f, seen));
            }
        }
        seen.remove(&i);
        1 + best
    }

    /// 全图最深节点的 `(node, depth)`（同深按 id 字典序破平）。空图 ⇒ `None`。
    pub fn max_depth(&self) -> Option<(String, usize)> {
        let mut best: Option<(String, usize)> = None;
        for n in &self.nodes {
            let d = self.depth_of(n);
            let better = match &best {
                None => true,
                Some((bn, bd)) => d > *bd || (d == *bd && n.as_str() < bn.as_str()),
            };
            if better {
                best = Some((n.clone(), d));
            }
        }
        best
    }

    /// 单条依据支撑的结论数（出度）。
    pub fn fanout(&self, node: &str) -> usize {
        match self.nodes.iter().position(|n| n == node) {
            None => 0,
            Some(i) => {
                let mut outs: Vec<usize> = self
                    .edges
                    .iter()
                    .filter(|(f, _)| *f == i)
                    .map(|(_, t)| *t)
                    .collect();
                outs.sort();
                outs.dedup();
                outs.len()
            }
        }
    }

    /// 出度最大的依据节点（出度相同按 id 字典序破平）。全零出度 → None。
    pub fn max_fanout(&self) -> Option<(String, usize)> {
        let mut best: Option<(String, usize)> = None;
        for n in &self.nodes {
            let f = self.fanout(n);
            if f == 0 {
                continue;
            }
            let better = match &best {
                None => true,
                Some((bn, bf)) => f > *bf || (f == *bf && n.as_str() < bn.as_str()),
            };
            if better {
                best = Some((n.clone(), f));
            }
        }
        best
    }

    /// 超限记录：出度 > d_max 的依据节点清单（判定层，只标注不阻塞）。
    pub fn over_limit(&self, d_max: usize) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = self
            .nodes
            .iter()
            .map(|n| (n.clone(), self.fanout(n)))
            .filter(|(_, f)| *f > d_max)
            .collect();
        out.sort();
        out
    }

    /// 无环判定 = 邻接矩阵幂零：A^N = 0（N = 节点数）⇔ 无环。
    /// 位并行布尔矩阵乘；稀疏图上早退（幂零指数 = 最长路径 + 1）。
    pub fn is_acyclic(&self) -> bool {
        let n = self.nodes.len();
        if n == 0 {
            return true;
        }
        let a = self.adjacency();
        let mut p = a.clone();
        for _ in 0..n {
            if p.iter().all(|x| *x == 0) {
                return true;
            }
            p = mat_mul(&p, &a, n);
        }
        p.iter().all(|x| *x == 0)
    }

    /// 检出成环节点：传递闭包 A+ 对角线为真 ⇔ 该节点处于某个环上。
    pub fn cyclic_nodes(&self) -> Vec<String> {
        let n = self.nodes.len();
        if n == 0 {
            return Vec::new();
        }
        let w = words(n);
        // Warshall 传递闭包（位并行），起点 = A（路径长度 ≥ 1）
        let mut reach = self.adjacency();
        for k in 0..n {
            for i in 0..n {
                if reach[i * w + k / 64] >> (k % 64) & 1 == 1 {
                    for x in 0..w {
                        reach[i * w + x] |= reach[k * w + x];
                    }
                }
            }
        }
        (0..n)
            .filter(|&i| reach[i * w + i / 64] >> (i % 64) & 1 == 1)
            .map(|i| self.nodes[i].clone())
            .collect()
    }

    /// 布尔邻接矩阵（位打包，行主序，行跨幅 words(n)）。
    fn adjacency(&self) -> Vec<u64> {
        let n = self.nodes.len();
        let w = words(n);
        let mut m = vec![0u64; n * w];
        for (f, t) in &self.edges {
            m[f * w + t / 64] |= 1u64 << (t % 64);
        }
        m
    }
}

fn words(n: usize) -> usize {
    n.div_ceil(64)
}

/// 布尔矩阵乘（位并行）：C[i] = OR over set bits k in P[i] of A[k]。
fn mat_mul(p: &[u64], a: &[u64], n: usize) -> Vec<u64> {
    let w = words(n);
    let mut c = vec![0u64; n * w];
    for i in 0..n {
        for k in 0..n {
            if p[i * w + k / 64] >> (k % 64) & 1 == 1 {
                for x in 0..w {
                    c[i * w + x] |= a[k * w + x];
                }
            }
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;
    use crate::ledger::SPEC;

    fn entry(id: &str, body: &str) -> Entry {
        Entry {
            spec: SPEC.to_string(),
            id: id.to_string(),
            body: json::parse(body).unwrap(),
            signatures: vec![],
        }
    }

    fn grant(id: &str) -> Entry {
        entry(
            id,
            &format!(
                r#"{{"kind":"claim","type":"warrant://types/warrant.authority.grant@1","parents":"nonce-{id}"}}"#
            ),
        )
    }

    fn claim(id: &str, grant_id: &str) -> Entry {
        entry(
            id,
            &format!(
                r#"{{"kind":"claim","type":"warrant://types/t.write@1","authority":{{"grant_id":"{grant_id}"}},"parents":"{grant_id}"}}"#
            ),
        )
    }

    fn obs(id: &str, claim_id: &str) -> Entry {
        entry(
            id,
            &format!(
                r#"{{"kind":"observation","subject":{{"id":"{claim_id}","kind":"warrant.entry"}},"observation":{{"channel":"proc_spawn_readback","tier":"C1"}},"parents":"{claim_id}"}}"#
            ),
        )
    }

    /// 换章 grant：`authority.grant_id = prev`（对齐 `amend_grant`：parents 留空）。
    fn amend_grant(id: &str, prev: &str) -> Entry {
        entry(
            id,
            &format!(
                r#"{{"kind":"claim","type":"warrant://types/warrant.authority.grant@1","authority":{{"grant_id":"{prev}"}},"parents":[]}}"#
            ),
        )
    }

    #[test]
    fn observation_edges_support_claim_and_skip_parents() {
        let es = vec![grant("g"), claim("c1", "g"), obs("o1", "c1")];
        let gph = build(&es);
        assert_eq!(gph.fanout("o1"), 1, "观测支撑其 claim");
        assert_eq!(
            gph.fanout("g"),
            1,
            "grant 支撑其 claim（parents/authority 去重）"
        );
        assert_eq!(gph.fanout("c1"), 0, "观测的 parents 不建反向边（防伪环）");
        assert!(gph.is_acyclic());
        assert!(gph.cyclic_nodes().is_empty());
    }

    /// [协议 §3.4] 深度 = 从根到该节点的**最长依据链**（根 = 1）；未知节点 ⇒ 0（不编造）。
    #[test]
    fn depth_is_longest_chain() {
        let es = vec![
            entry("a", r#"{"kind":"claim","parents":[]}"#),
            entry("b", r#"{"kind":"claim","parents":["a"]}"#),
            entry("c", r#"{"kind":"claim","parents":["b"]}"#),
            // 更短的旁支：d 只依赖 a ⇒ 深度 2（最长链仍是 a→b→c = 3）
            entry("d", r#"{"kind":"claim","parents":["a"]}"#),
        ];
        let g = build(&es);
        assert_eq!(g.depth_of("a"), 1);
        assert_eq!(g.depth_of("b"), 2);
        assert_eq!(g.depth_of("c"), 3);
        assert_eq!(g.depth_of("d"), 2);
        assert_eq!(g.depth_of("ghost"), 0, "未知节点 ⇒ 0（不编造）");
        assert_eq!(g.max_depth(), Some(("c".to_string(), 3)));
    }

    /// [X-DEPTH-FIX-2026-10-04] 回归钉子：**grant 换章链不得累积证据深度**。
    /// 真机事故：32 枚 grant 串链（每满 D_MAX 条 claim 换一枚）⇒ 新 claim 深度恒 33 > N_MAX
    /// ⇒ `record_effect` 全拒、账本冻结、认定面板恒空。钉子：即便租权链长到 2×N_MAX，
    /// grant 深度仍恒 1、claim 恒 2（观测为源、恒 1）；新 claim 的深度 ≤ N_MAX（可入账）。
    #[test]
    fn grant_amend_chain_does_not_accumulate_depth() {
        let chain_len = N_MAX * 2;
        let mut es = vec![grant("g1")];
        let mut prev = "g1".to_string();
        for i in 2..=chain_len {
            let id = format!("g{i}");
            es.push(amend_grant(&id, &prev));
            prev = id;
        }
        let last_grant = prev.clone();
        es.push(claim("c", &last_grant));
        es.push(obs("o", "c"));
        let g = build(&es);
        assert_eq!(g.depth_of("g1"), 1, "bootstrap grant 恒深 1");
        assert_eq!(
            g.depth_of(&last_grant),
            1,
            "第 {chain_len} 枚 grant 仍恒深 1（授权不是依据）"
        );
        assert_eq!(
            g.depth_of("c"),
            2,
            "claim 深度 = grant + 1 = 2，与授权链长度无关"
        );
        // 深度方向：边 = 依据 → 结论；观测是**源**（obs → claim），故 obs 深 1。
        assert_eq!(g.depth_of("o"), 1, "观测为源（obs → claim），恒深 1");
        // 关键：新 claim 不再越限 ⇒ X-DEPTH 不再拦（这里就是 admission 的判据来源）。
        assert!(
            g.depth_of("c") <= N_MAX,
            "新 claim 深度必须 ≤ N_MAX，否则账本整体拒收"
        );
        assert!(g.is_acyclic());
        assert!(g.cyclic_nodes().is_empty());
    }

    #[test]
    fn fanout_counts_distinct_conclusions_and_over_limit_is_recorded() {
        let es = vec![
            grant("g"),
            claim("c1", "g"),
            claim("c2", "g"),
            claim("c3", "g"),
        ];
        let gph = build(&es);
        assert_eq!(gph.fanout("g"), 3);
        assert_eq!(gph.max_fanout(), Some(("g".to_string(), 3)));
        assert_eq!(
            gph.over_limit(2),
            vec![("g".to_string(), 3)],
            "超限必须被记录"
        );
        assert!(gph.over_limit(D_MAX).is_empty(), "未超 D_MAX 不记录");
    }

    #[test]
    fn dag_is_nilpotent_acyclic() {
        let es = vec![
            entry("a", r#"{"kind":"claim","parents":"ghost"}"#),
            entry("b", r#"{"kind":"claim","parents":"a"}"#),
            entry("c", r#"{"kind":"claim","parents":"b"}"#),
        ];
        let gph = build(&es);
        assert!(gph.is_acyclic(), "链式 DAG 的邻接矩阵必须幂零");
        assert!(gph.cyclic_nodes().is_empty());
    }

    #[test]
    fn nilpotency_detects_two_node_cycle() {
        let es = vec![
            entry("x", r#"{"kind":"claim","parents":"y"}"#),
            entry("y", r#"{"kind":"claim","parents":"x"}"#),
        ];
        let gph = build(&es);
        assert!(!gph.is_acyclic(), "x⇄y 互为依据 ⇒ A^N 非零");
        assert_eq!(gph.cyclic_nodes(), vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn self_loop_is_a_cycle() {
        let es = vec![entry("z", r#"{"kind":"claim","parents":"z"}"#)];
        let gph = build(&es);
        assert!(!gph.is_acyclic());
        assert_eq!(gph.cyclic_nodes(), vec!["z".to_string()]);
    }

    #[test]
    fn empty_graph_is_acyclic() {
        let gph = build(&[]);
        assert!(gph.is_acyclic());
        assert_eq!(gph.max_fanout(), None);
        assert!(gph.cyclic_nodes().is_empty());
    }
}
