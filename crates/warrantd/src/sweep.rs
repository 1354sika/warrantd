//! 巡边（sweep）：**单源**。
//!
//! 这段逻辑原来只在 `main.rs` 里（`warrantd once` / `daemon` 用）。
//! `[MCP-FRESH-2026-10-27]` 之后 `mcp.rs` 也要用它（补扫），所以搬到 lib ——
//! **两份 sweep 一定会漂移**，而漂移的后果是"两个入口看到的观测面不一样"，
//! 那正是信使要反对的东西。
//!
//! # 职责边界
//!
//! - **只读世界 + 写账**：不注入任何对话消息；
//! - **世界没变就零条目**：账本不是心跳日志；
//! - **首扫只建基线**：不把「我现在才看见」误当成「世界刚变了」（见 `snapshot::diff`）。

use std::path::Path;

use warrant::json::Value;

use crate::probe::Observed;
use crate::store::{self, T_WORLD_CHANGE};
use crate::{snapshot, util};

/// 一次巡边的结果。
#[derive(Debug, Clone)]
pub struct SweepOutcome {
    pub scanned: usize,
    pub changes: usize,
    pub claim: String,
    pub offset: usize,
    pub snapshot_at: String,
}

impl SweepOutcome {
    /// 单行 JSON（与 CLI 输出同形 —— 人和脚本看的是同一串字节）。
    pub fn to_line(&self) -> String {
        util::to_line(&util::obj(vec![
            ("scanned", Value::Int(self.scanned as i64)),
            ("changes", Value::Int(self.changes as i64)),
            ("claim", util::s(&self.claim)),
            ("offset", Value::Int(self.offset as i64)),
            ("mode", util::s("fs.hash（内容级，不是 size/mtime）")),
            ("snapshot_at", util::s(&self.snapshot_at)),
        ]))
    }
}

/// 巡边一次。
pub fn sweep(repo: &Path, watch: &[String]) -> Result<SweepOutcome, String> {
    let mut st = store::Store::open(repo)?;
    let old = snapshot::load(repo);
    let new = snapshot::scan(repo, watch)?;
    let changes = snapshot::diff(old.as_ref(), &new);
    let claim = if changes.is_empty() {
        String::new()
    } else {
        let cid = st.append_world_change(&changes, watch.len())?;
        // 观测条目指向这条 claim：result 与 claim.expect 同形 ⇒ 切片① 直接判 consistent。
        // 语义诚实：这条观测**确实看到了**它自己声明的那批变更（同一次 scan 的产物）。
        let ob = Observed {
            method: "fs.hash".into(),
            tier: crate::DECLARED_TIER.into(),
            tier_hint: "C2".into(),
            channel: crate::CHANNEL.into(),
            observed_at: util::now_rfc3339(),
            result: util::obj(vec![
                ("count", Value::Int(changes.len() as i64)),
                ("scanned", Value::Int(watch.len() as i64)),
            ]),
            evidence: changes
                .iter()
                .map(|c| {
                    format!(
                        "{} {} -> {}",
                        c.path,
                        c.from.clone().unwrap_or_default(),
                        c.to.clone().unwrap_or_default()
                    )
                })
                .collect(),
            self_side_effects: vec![],
        };
        st.append_observation(&ob, &cid)?;
        cid
    };
    snapshot::save(repo, &new)?;
    Ok(SweepOutcome {
        scanned: watch.len(),
        changes: changes.len(),
        claim,
        offset: st.offset(),
        snapshot_at: new.at,
    })
}

/// 账本有多久没更新（秒）。`None` = 从没扫过。
///
/// 用 **snapshot.json 的文件 mtime** 而不是解析里面的时间串：
/// 少一次解析、少一种格式依赖，且"文件什么时候被写的"就是我们要问的那个事实。
pub fn snapshot_age_secs(repo: &Path) -> Option<u64> {
    let p = snapshot::snapshot_path(repo);
    let md = std::fs::metadata(p).ok()?;
    let m = md.modified().ok()?;
    m.elapsed().ok().map(|d| d.as_secs())
}

/// **观测面（单源）**：`.warrant/watch.list` 优先，否则 `git ls-files`（限 500）。
///
/// `[WATCH-SINGLE-2026-10-28]` 这个解析原来在 `mcp.rs` / `ui.rs` / `main.rs` 各写了一遍 ——
/// **三份一漂移，两个入口看到的观测面就不一样了**，那正是信使要反对的东西。
/// 现在只有这一份。
pub fn watch_surface(repo: &Path) -> (Vec<String>, &'static str) {
    let p = repo.join(crate::LEDGER_DIR).join("watch.list");
    if let Ok(text) = std::fs::read_to_string(&p) {
        let v: Vec<String> = text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        return (v, "项目的 .warrant/watch.list");
    }
    let mut c = std::process::Command::new("git");
    c.args(["ls-files"]).current_dir(repo);
    crate::util::hide_console(&mut c);
    match c.output() {
        Ok(o) if o.status.success() => (
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .take(500)
                .map(|x| x.to_string())
                .collect(),
            "git ls-files（仅已跟踪文件）",
        ),
        _ => (Vec::new(), "空（无 watch.list 且不是 git 仓库）"),
    }
}

/// 观测面有几项（admit 用）。
pub fn watch_surface_count(repo: &Path) -> usize {
    watch_surface(repo).0.len()
}

/// 把秒数说成人话（`18034 秒` 没人读得出来是 5 小时）。
pub fn human_age(secs: u64) -> String {
    if secs < 90 {
        format!("{secs} 秒")
    } else if secs < 5400 {
        format!("{} 分钟", secs / 60)
    } else if secs < 172_800 {
        format!("{} 小时", secs / 3600)
    } else {
        format!("{} 天", secs / 86400)
    }
}

/// 账本过期阈值：超过它就该补扫。
pub const STALE_SECS: u64 = 300;

/// **被问到时自检新鲜度**（`[MCP-FRESH-2026-10-27]`）。
///
/// 场景：agent 通过 `warrantd mcp` 问，但**没有常驻 daemon 在跑**。
/// 如果不处理，它看到的永远是空账本 —— 那会表现成"信使什么都没记"，
/// 而真相是"没人看着"。这两件事必须能被区分。
///
/// 做法：过期就**当场补扫一次**，并如实告诉调用方「我补扫了，常驻似乎没在跑」。
/// 这是自洽的：观测面自己会说"我没在持续看"。
pub fn ensure_fresh(repo: &Path, watch: &[String]) -> Option<String> {
    let age = snapshot_age_secs(repo);
    let stale = match age {
        None => true,
        Some(s) => s > STALE_SECS,
    };
    if !stale || watch.is_empty() {
        return None;
    }
    match sweep(repo, watch) {
        // ⚠️ 这里**不许写 markdown 标记**：这段字会被 MCP 的 text 与面板的 textContent
        // 直接显示（两处都不解析 markdown）。真机上就因为写了 `**…**`，面板里原样显示了两个星号。
        Ok(o) => Some(format!(
            "（账本已 {} 没更新 ⇒ 我补扫了一次：{} 项，{} 处变化。常驻 daemon 似乎没在跑，所以这之前的变化我看不见）",
            match age {
                Some(s) => human_age(s),
                None => "从未".to_string(),
            },
            o.scanned,
            o.changes
        )),
        Err(e) => Some(format!("（账本过期，补扫失败：{e}）")),
    }
}

/// 这个仓库里已有的世界变更条目数（供自检与诊断）。
pub fn world_change_count(entries: &[warrant::ledger::Entry]) -> usize {
    entries
        .iter()
        .filter(|e| e.body.get("type").and_then(|x| x.as_str()) == Some(T_WORLD_CHANGE))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("warrantd-sweep-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".git")).unwrap();
        d
    }

    #[test]
    fn first_sweep_is_baseline_and_writes_no_change() {
        let d = tmp("base");
        std::fs::write(d.join("a.txt"), b"1").unwrap();
        let o = sweep(&d, &["a.txt".to_string()]).unwrap();
        assert_eq!(o.changes, 0, "首扫只建基线");
        assert_eq!(o.offset, 1, "只有 bootstrap grant");
        assert!(snapshot_age_secs(&d).is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn second_sweep_after_edit_reports_change_and_grows_ledger() {
        let d = tmp("grow");
        std::fs::write(d.join("a.txt"), b"1").unwrap();
        let _ = sweep(&d, &["a.txt".to_string()]).unwrap();
        std::fs::write(d.join("a.txt"), b"22").unwrap();
        let o = sweep(&d, &["a.txt".to_string()]).unwrap();
        assert_eq!(o.changes, 1);
        assert!(o.claim.starts_with("sha256:"));
        assert_eq!(o.offset, 3, "grant + claim + observation");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// MCP 单独跑时的关键保障：账本从没扫过 ⇒ **必须补扫**，而不是回一个空账本。
    #[test]
    fn ensure_fresh_sweeps_when_never_scanned() {
        let d = tmp("fresh");
        std::fs::write(d.join("a.txt"), b"hi").unwrap();
        let note = ensure_fresh(&d, &["a.txt".to_string()]);
        assert!(note.is_some(), "从没扫过时必须补扫并说明");
        assert!(note.as_ref().unwrap().contains("补扫"), "{note:?}");
        let st = crate::store::Store::open(&d).unwrap();
        assert!(st.offset() >= 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 人读时长：`18034 秒` 没人读得出是 5 小时。
    #[test]
    fn human_age_reads_like_chinese() {
        assert_eq!(human_age(5), "5 秒");
        assert_eq!(human_age(300), "5 分钟");
        assert_eq!(human_age(18034), "5 小时");
        assert_eq!(human_age(200_000), "2 天");
    }

    #[test]
    fn ensure_fresh_is_silent_when_no_watch_surface() {
        let d = tmp("nowatch");
        assert!(ensure_fresh(&d, &[]).is_none(), "没观测面就不该瞎扫");
        let _ = std::fs::remove_dir_all(&d);
    }
}
