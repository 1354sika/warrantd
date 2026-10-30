//! 世界快照与差分 —— 「抗滞后」的原材料。
//!
//! 快照只存**内容哈希**，不存内容：daemon 不需要读得懂你的代码，它只需要记得
//! 「上次看到时这个文件是这个样子的」。
//!
//! **为什么快照要和账本分开存**：账本是 append-only 的证据链（每条签名、算 id、占链位），
//! 快照是**可覆盖的最新视图**。把快照塞进账本会让每次巡边都写几百条、把认定账本淹掉。
//! 两者职责不同：账本回答「发生过什么」，快照回答「现在是什么」。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use warrant::json::Value;

use crate::util::{now_rfc3339, obj, s};

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub at: String,
    /// 相对路径 → `sha256:<hex>`
    pub files: BTreeMap<String, String>,
    /// 相对路径 → mtime（纳秒）。
    ///
    /// [TOUCH-2026-10-27] **为什么要多记这一个数**：「改了又改回来」这种抖动，
    /// **内容哈希看不出来**（改回去了），但 **mtime 一定变了**。
    /// 多记一个 mtime，「一次扫描」就能发现它 —— 不需要事件级 watcher、不需要新依赖。
    /// 只记文件，不记目录（目录的结构指纹里已含 newest）。
    pub mtimes: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Modified,
    Removed,
    /// 被碰过，但**内容没变**（改了又改回来）。
    ///
    /// 这是 mtime 才看得见的一类事实：内容哈希会显示"什么都没变"，
    /// 而实际有进程动过这个文件。危害通常小于 Modified，但它是**真信息**，
    /// 而且正好补上「30 秒采样窗口内改了又改回来」这个洞。
    Touched,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Added => "added",
            ChangeKind::Modified => "modified",
            ChangeKind::Removed => "removed",
            ChangeKind::Touched => "touched",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub path: String,
    pub kind: ChangeKind,
    pub from: Option<String>,
    pub to: Option<String>,
}

pub fn snapshot_path(repo: &Path) -> PathBuf {
    repo.join(crate::LEDGER_DIR).join("snapshot.json")
}

pub fn load(repo: &Path) -> Option<Snapshot> {
    let text = std::fs::read_to_string(snapshot_path(repo)).ok()?;
    let v = warrant::json::parse(&text).ok()?;
    let at = v
        .get("at")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let mut files = BTreeMap::new();
    if let Some(Value::Object(pairs)) = v.get("files") {
        for (k, vv) in pairs {
            if let Some(h) = vv.as_str() {
                files.insert(k.clone(), h.to_string());
            }
        }
    }
    let mut mtimes = BTreeMap::new();
    if let Some(Value::Object(pairs)) = v.get("mtimes") {
        for (k, vv) in pairs {
            if let Some(n) = vv.as_int() {
                mtimes.insert(k.clone(), n);
            }
        }
    }
    Some(Snapshot { at, files, mtimes })
}

pub fn save(repo: &Path, snap: &Snapshot) -> Result<(), String> {
    let dir = repo.join(crate::LEDGER_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let mtimes = Value::Object(
        snap.mtimes
            .iter()
            .map(|(k, v)| (k.clone(), Value::Int(*v)))
            .collect(),
    );
    let v = obj(vec![
        ("at", s(&snap.at)),
        ("files", crate::probe::hash_map_json(&snap.files)),
        ("mtimes", mtimes),
    ]);
    let line = crate::util::to_line(&v);
    std::fs::write(snapshot_path(repo), line)
        .map_err(|e| format!("write {}: {e}", snapshot_path(repo).display()))
}

pub fn scan(repo: &Path, rels: &[String]) -> Result<Snapshot, String> {
    // [WINDOW-2026-10-28] `at` 取在**扫描完成之后**，不是开始之前。
    //
    // 为什么：`at` 现在是「这条快照覆盖到哪一刻」的右端点。若取开始时刻，
    // 下一次巡边的 window_from（= 本次 at）会早于本次的 window_to ⇒ **窗口重叠**，
    // 于是「这段时间里变了几次」这类问题会被重复计数。
    // 放在最后求值，保证窗口首尾相接：[T0, T1] [T1, T2] …
    let files = crate::probe::scan_hashes(repo, rels)?;
    let mtimes = crate::probe::mtimes_of(repo, rels);
    Ok(Snapshot {
        files,
        mtimes,
        at: now_rfc3339(),
    })
}

/// 差分。`old = None` ⇒ 首扫建基线，**不产生变更**（否则第一次巡边会把整个仓库报成 added）。
pub fn diff(old: Option<&Snapshot>, new: &Snapshot) -> Vec<Change> {
    // 首扫没有「之前」可比 —— 报 added 是把「我现在才看见」误当成「世界刚变了」。
    // 这是抗滞后里最容易犯的错：把观测的起点当成了事件的发生。
    let Some(old) = old else {
        return Vec::new();
    };
    let before = &old.files;
    let mut out: Vec<Change> = Vec::new();
    for (k, v) in &new.files {
        match before.get(k) {
            None => out.push(Change {
                path: k.clone(),
                kind: ChangeKind::Added,
                from: None,
                to: Some(v.clone()),
            }),
            Some(old_h) if old_h != v => out.push(Change {
                path: k.clone(),
                kind: ChangeKind::Modified,
                from: Some(old_h.clone()),
                to: Some(v.clone()),
            }),
            Some(_) => {
                // 内容没变 —— 但 mtime 变了就说明**有进程碰过它**（改了又改回来）。
                // 这是内容哈希看不见的事实，也是补「采样窗口内抖动」这个洞的落点。
                let om = old.mtimes.get(k);
                let nm = new.mtimes.get(k);
                if let (Some(a), Some(b)) = (om, nm) {
                    if a != b {
                        out.push(Change {
                            path: k.clone(),
                            kind: ChangeKind::Touched,
                            from: Some(v.clone()),
                            to: Some(v.clone()),
                        });
                    }
                }
            }
        }
    }
    for (k, v) in before {
        if !new.files.contains_key(k) {
            out.push(Change {
                path: k.clone(),
                kind: ChangeKind::Removed,
                from: Some(v.clone()),
                to: None,
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

pub fn changes_json(changes: &[Change]) -> Value {
    Value::Array(
        changes
            .iter()
            .map(|c| {
                let mut pairs = vec![
                    ("path".to_string(), s(&c.path)),
                    ("kind".to_string(), s(c.kind.as_str())),
                ];
                if let Some(f) = &c.from {
                    pairs.push(("from".to_string(), s(f)));
                }
                if let Some(t) = &c.to {
                    pairs.push(("to".to_string(), s(t)));
                }
                Value::Object(pairs)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(pairs: &[(&str, &str)]) -> Snapshot {
        Snapshot {
            at: "t".into(),
            files: pairs
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            mtimes: BTreeMap::new(),
        }
    }

    /// [TOUCH-2026-10-27] 洞③的核心钉子：**内容没变但 mtime 变了 ⇒ touched**。
    ///
    /// 这条测试对应一个真实失效：agent 改了文件又改回来（或编译工具重写同内容），
    /// 内容哈希会显示"什么都没变" —— 于是账本一片空白，而这恰恰是观测该说话的时候。
    #[test]
    fn mtime_change_with_same_content_is_touched_not_silent() {
        let mut old = snap(&[("a.txt", "sha256:same")]);
        old.mtimes.insert("a.txt".into(), 100);
        let mut new = snap(&[("a.txt", "sha256:same")]);
        new.mtimes.insert("a.txt".into(), 200);
        let d = diff(Some(&old), &new);
        assert_eq!(d.len(), 1, "改了又改回来必须产生一条记录：{d:?}");
        assert_eq!(d[0].kind, ChangeKind::Touched);
        assert_eq!(d[0].kind.as_str(), "touched");
    }

    /// 对照：内容变了 + mtime 变了 ⇒ 报 modified（不是 touched），不要重复报两条
    #[test]
    fn content_change_wins_over_touch() {
        let mut old = snap(&[("a.txt", "sha256:1")]);
        old.mtimes.insert("a.txt".into(), 100);
        let mut new = snap(&[("a.txt", "sha256:2")]);
        new.mtimes.insert("a.txt".into(), 200);
        let d = diff(Some(&old), &new);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].kind, ChangeKind::Modified);
    }

    /// 内容与 mtime 都没变 ⇒ 一条都不报（不能因为"多了个字段"就开始误报）
    #[test]
    fn nothing_changed_reports_nothing() {
        let mut a = snap(&[("x", "sha256:1")]);
        a.mtimes.insert("x".into(), 7);
        assert!(diff(Some(&a), &a.clone()).is_empty());
    }

    /// mtime 缺失（旧快照没有这个字段）⇒ 保守不报 touched，而不是瞎报
    #[test]
    fn missing_mtime_does_not_fabricate_touch() {
        let old = snap(&[("a.txt", "sha256:same")]); // mtimes 空
        let mut new = snap(&[("a.txt", "sha256:same")]);
        new.mtimes.insert("a.txt".into(), 200);
        assert!(
            diff(Some(&old), &new).is_empty(),
            "旧快照没有 mtime 基线时不能凭空报 touched"
        );
    }

    #[test]
    fn first_scan_is_baseline_not_flood() {
        let new = snap(&[("a.rs", "sha256:1"), ("b.rs", "sha256:2")]);
        assert!(
            diff(None, &new).is_empty(),
            "首扫必须只建基线，不能把整个仓库报成 added"
        );
    }

    #[test]
    fn diff_reports_added_modified_removed() {
        let old = snap(&[("a.rs", "sha256:1"), ("b.rs", "sha256:2")]);
        let new = snap(&[("a.rs", "sha256:9"), ("c.rs", "sha256:3")]);
        let d = diff(Some(&old), &new);
        assert_eq!(d.len(), 3, "{d:?}");
        assert_eq!(
            d.iter().find(|c| c.path == "a.rs").unwrap().kind,
            ChangeKind::Modified
        );
        assert_eq!(
            d.iter().find(|c| c.path == "b.rs").unwrap().kind,
            ChangeKind::Removed
        );
        assert_eq!(
            d.iter().find(|c| c.path == "c.rs").unwrap().kind,
            ChangeKind::Added
        );
    }

    #[test]
    fn no_change_means_empty() {
        let a = snap(&[("x", "sha256:1")]);
        assert!(diff(Some(&a), &a.clone()).is_empty());
    }
}
