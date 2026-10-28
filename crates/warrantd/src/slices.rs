//! 三种切片 —— 一条世界流，三种回答方式。
//!
//! ```text
//! W（世界流，daemon 持续产）
//!   ├─ ①  claim ∩ W        → CONSISTENT / CONTRADICTED   ← 抗黑盒 A
//!   ├─ ②  W ∖ claim        → 未申报变更（负事实）         ← 抗黑盒 B
//!   └─ ③  W(t) − W(offset) → 「你不在的时候变了这些」      ← 抗滞后
//! ```
//!
//! **② 和 ③ 是同一个集合的两种读法** —— 「变了但没人申报」对**未声明者**是滞后，
//! 对**已声明者**是矛盾。所以"同时抗黑盒与滞后"不是加两个机制，是把同一份记录按两种方式切。
//!
//! 本模块**只读账本、不改账本**（切片是查询，不是写入）。

use std::collections::{BTreeMap, BTreeSet};

use warrant::json::Value;
use warrant::ledger::Entry;

use crate::snapshot::{Change, ChangeKind};
use crate::store::{T_AGENT_CLAIM, T_WORLD_CHANGE};

/// 切片①：一条 claim 的认定状态。
#[derive(Debug, Clone)]
pub struct ClaimVerdict {
    pub claim_id: String,
    /// 九档状态之一（`SPEC.md:233`）
    pub state: &'static str,
    /// `FREEZEABLE` / `TENTATIVE`（`rank.rs` 的判据标签）
    pub label: String,
    pub d_eff: usize,
    /// 轴名（甲/乙/丙/丁）
    pub axes: Vec<String>,
    /// 指向这条 claim 的观测条数
    pub observations: usize,
}

/// 切片①（抗黑盒 A）：**看与说的差**。
pub fn check_claim(entries: &[Entry], claim_id: &str) -> Option<ClaimVerdict> {
    let claim = entries.iter().find(|e| e.id == claim_id)?;
    let states: BTreeMap<String, &'static str> = warrant::projection::project(entries, None)
        .into_iter()
        .collect();
    let state = states.get(claim_id).copied().unwrap_or("UNKNOWN");
    let observations = entries
        .iter()
        .filter(|e| {
            e.body.get("kind").and_then(|x| x.as_str()) == Some("observation")
                && e.body
                    .get("subject")
                    .and_then(|x| x.get("id"))
                    .and_then(|x| x.as_str())
                    == Some(claim_id)
        })
        .count();
    let (label, d_eff, axes) = match warrant::rank::judge(entries, claim_id) {
        Some(v) => (
            v.label.to_string(),
            v.d_eff,
            v.axes.iter().map(|a| a.name().to_string()).collect(),
        ),
        None => ("UNJUDGED".to_string(), 0, vec![]),
    };
    let _ = claim;
    Some(ClaimVerdict {
        claim_id: claim_id.to_string(),
        state,
        label,
        d_eff,
        axes,
        observations,
    })
}

/// `special:` 前缀 = **观测面自身的配置**（如 `.warrant/ignore`）。
///
/// 它们的改动**必须进账本**（放宽观测面这个动作要可见），
/// 但**不该报成「agent 的未申报改动」**——那是归因错误，会把真警报淹掉。
fn is_meta(path: &str) -> bool {
    path.starts_with("special:")
}

/// 从 body 里取出 `{路径: 哈希}` 形态的申报映射（agent claim 专用）。
pub fn declared_map(e: &Entry) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if e.body.get("type").and_then(|x| x.as_str()) != Some(T_AGENT_CLAIM) {
        return out;
    }
    if let Some(Value::Object(pairs)) = e.body.get("expect") {
        for (k, v) in pairs {
            if let Some(h) = v.as_str() {
                out.insert(k.clone(), h.to_string());
            }
        }
    }
    out
}

/// 账本里所有被「申报过」的路径（切片②的减数）。
pub fn declared_paths(entries: &[Entry]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for e in entries {
        out.extend(declared_map(e).into_keys());
    }
    out
}

fn parse_changes(v: Option<&Value>) -> Vec<Change> {
    let mut out = Vec::new();
    let Some(Value::Array(items)) = v else {
        return out;
    };
    for it in items {
        let path = it.get("path").and_then(|x| x.as_str()).unwrap_or("");
        if path.is_empty() {
            continue;
        }
        let kind = match it.get("kind").and_then(|x| x.as_str()) {
            Some("added") => ChangeKind::Added,
            Some("removed") => ChangeKind::Removed,
            // [TOUCH-2026-10-27] 漏了这一行 ⇒ 账本里写 touched、展示成 modified。
            // 单测没抓住是因为它直接比对 `Change`（不经 JSON 往返）；真机才暴露。
            Some("touched") => ChangeKind::Touched,
            _ => ChangeKind::Modified,
        };
        out.push(Change {
            path: path.to_string(),
            kind,
            from: it
                .get("from")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            to: it.get("to").and_then(|x| x.as_str()).map(|s| s.to_string()),
        });
    }
    out
}

/// 账本里所有的「世界变更」条目：`(claim_id, changes)`。
pub fn world_changes(entries: &[Entry]) -> Vec<(String, Vec<Change>)> {
    entries
        .iter()
        .filter(|e| e.body.get("type").and_then(|x| x.as_str()) == Some(T_WORLD_CHANGE))
        .map(|e| {
            let ch = parse_changes(
                e.body
                    .get("action")
                    .and_then(|a| a.get("args"))
                    .and_then(|a| a.get("changes")),
            );
            (e.id.clone(), ch)
        })
        .filter(|(_, ch)| !ch.is_empty())
        .collect()
}

/// 切片②（抗黑盒 B）：**变了但没人申报** = 自动产生的负事实。
#[derive(Debug, Clone)]
pub struct Unreported {
    pub world_claim: String,
    pub changes: Vec<Change>,
}

pub fn unreported(entries: &[Entry]) -> Vec<Unreported> {
    let declared = declared_paths(entries);
    world_changes(entries)
        .into_iter()
        .map(|(id, changes)| Unreported {
            world_claim: id,
            changes: changes
                .into_iter()
                .filter(|c| !declared.contains(&c.path) && !is_meta(&c.path))
                .collect(),
        })
        .filter(|u| !u.changes.is_empty())
        .collect()
}

/// 切片③（抗滞后）：读者水位之后发生了什么。
#[derive(Debug, Clone)]
pub struct SinceItem {
    pub seq: i64,
    pub id: String,
    pub kind: String,
    pub type_: String,
    pub actor: String,
}

#[derive(Debug, Clone)]
pub struct SinceReport {
    pub from: usize,
    pub to: usize,
    pub items: Vec<SinceItem>,
    /// 水位之后的世界变更（可直接给 agent 当「你不在时变了这些」）
    pub world: Vec<(String, Vec<Change>)>,
    /// 其中**没有任何 agent 申报过**的部分（真正的滞后，不是被跟进的变更）
    pub unreported: Vec<Change>,
}

/// 切片③。`from` = 上次读到的条数（水位）。
pub fn since(entries: &[Entry], from: usize) -> SinceReport {
    let from = from.min(entries.len());
    let tail = &entries[from..];
    let items: Vec<SinceItem> = tail
        .iter()
        .map(|e| SinceItem {
            seq: e
                .body
                .get("chain")
                .and_then(|c| c.get("seq"))
                .and_then(|x| x.as_int())
                .unwrap_or(-1),
            id: e.id.clone(),
            kind: e
                .body
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            type_: e
                .body
                .get("type")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            actor: e
                .body
                .get("actor")
                .and_then(|a| a.get("id"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
        .collect();
    let world: Vec<(String, Vec<Change>)> = tail
        .iter()
        .filter(|e| e.body.get("type").and_then(|x| x.as_str()) == Some(T_WORLD_CHANGE))
        .map(|e| {
            (
                e.id.clone(),
                parse_changes(
                    e.body
                        .get("action")
                        .and_then(|a| a.get("args"))
                        .and_then(|a| a.get("changes")),
                ),
            )
        })
        .filter(|(_, c)| !c.is_empty())
        .collect();
    // 未申报判定要用**全账本**的申报集（水位之前申报过的，不该在水位之后被误报成「未申报」）
    let declared = declared_paths(entries);
    let unreported = world
        .iter()
        .flat_map(|(_, cs)| cs.iter().cloned())
        .filter(|c| !declared.contains(&c.path) && !is_meta(&c.path))
        .collect();
    SinceReport {
        from,
        to: entries.len(),
        items,
        world,
        unreported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(p: &str) -> Change {
        Change {
            path: p.into(),
            kind: ChangeKind::Modified,
            from: Some("sha256:a".into()),
            to: Some("sha256:b".into()),
        }
    }

    #[test]
    fn since_before_offset_is_empty() {
        let r = since(&[], 0);
        assert!(r.items.is_empty() && r.world.is_empty() && r.unreported.is_empty());
        // 水位越过末尾 ⇒ 钳到末尾，不 panic
        let r = since(&[], 99);
        assert_eq!(r.from, 0);
    }

    #[test]
    fn unreported_is_complement_of_declared() {
        // 纯函数级：declared_paths 只认 T_AGENT_CLAIM 的 expect 键
        let mut e = Entry {
            spec: "warrant/1".into(),
            id: "sha256:x".into(),
            body: crate::util::obj(vec![
                ("type", crate::util::s(T_AGENT_CLAIM)),
                (
                    "expect",
                    crate::util::obj(vec![("src/a.rs", crate::util::s("sha256:1"))]),
                ),
            ]),
            signatures: vec![],
        };
        assert_eq!(declared_paths(std::slice::from_ref(&e)).len(), 1);
        // 换类型 ⇒ 不再算申报
        e.body = crate::util::obj(vec![("type", crate::util::s("other"))]);
        assert!(declared_paths(std::slice::from_ref(&e)).is_empty());
    }

    #[test]
    fn world_changes_parse_roundtrip() {
        let json = crate::snapshot::changes_json(&[change("a.rs"), change("b.rs")]);
        let parsed = parse_changes(Some(&json));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, "a.rs");
        assert_eq!(parsed[0].kind, ChangeKind::Modified);
    }

    /// **[TOUCH-2026-10-27] 这条钉子是因为真机上一处静默失真才补的**：
    /// `ChangeKind::Touched` 加进了枚举、也写进了账本，但 JSON 反序列化忘了加分支，
    /// 于是 `unreported` 把 touched 显示成 modified —— 单测没抓住（它不经 JSON 往返）。
    /// 所以：**每一种 ChangeKind 都必须是 JSON 往返不变的**。
    #[test]
    fn every_change_kind_survives_json_roundtrip() {
        for kind in [
            ChangeKind::Added,
            ChangeKind::Modified,
            ChangeKind::Removed,
            ChangeKind::Touched,
        ] {
            let c = Change {
                path: "x".into(),
                kind,
                from: Some("sha256:a".into()),
                to: Some("sha256:b".into()),
            };
            let json = crate::snapshot::changes_json(std::slice::from_ref(&c));
            let back = parse_changes(Some(&json));
            assert_eq!(back.len(), 1);
            assert_eq!(
                back[0].kind, kind,
                "{:?} 没能在 JSON 往返中保留（这正是真机那次 touched→modified 失真的原因）",
                kind
            );
        }
    }
}
