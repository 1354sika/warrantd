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
    sweep_with_events(repo, watch, &Default::default())
}

/// 带事件计数的巡边（`[JITTER-2026-10-29]`）。
///
/// `event_counts` 来自 watcher：本窗口内每个路径被碰了几次。
/// **它不影响「记几条」** —— 每轮仍然最多一条世界变更，计数只是随附信息。
pub fn sweep_with_events(
    repo: &Path,
    watch: &[String],
    event_counts: &std::collections::HashMap<String, usize>,
) -> Result<SweepOutcome, String> {
    let mut st = store::Store::open(repo)?;
    let old = snapshot::load(repo);
    // 窗口左端 = 上次快照覆盖到的那一刻；首扫为空（无基线）
    let window_from = old.as_ref().map(|s| s.at.clone()).unwrap_or_default();
    let new = snapshot::scan(repo, watch)?;
    // 窗口右端 = 本次扫描完成的时刻（与 Snapshot.at 同源，保证首尾相接）
    let window_to = new.at.clone();
    let changes = snapshot::diff(old.as_ref(), &new);
    let claim = if changes.is_empty() {
        String::new()
    } else {
        let cid = st.append_world_change(
            &changes,
            watch.len(),
            &window_from,
            &window_to,
            event_counts,
        )?;
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
    // [SEAL-2026-10-29] 自动封卷：当前卷超过阈值就挪走，让「当前卷」保持小。
    // 失败**不阻断**巡边（封卷是维护动作，不该让观测停摆）—— 但状态里会照实报条数。
    if st.entries().len() >= crate::SEAL_AFTER {
        let _ = st.seal();
    }
    Ok(SweepOutcome {
        scanned: watch.len(),
        changes: changes.len(),
        claim,
        offset: st.logical_offset(),
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

    /// **[JITTER-2026-10-29] 事件次数必须进账本。**
    ///
    /// 这条钉子守的是「快照差分之外的那点信息」：快照只知道最后长什么样，
    /// 改了又改回来就只剩 `touched`；而 watcher 数出来的次数能把
    /// 「改了一次」和「改了 17 次」分开 —— 后者通常意味着在反复试错。
    ///
    /// 注意：**次数不影响写几条**。这条世界变更仍然只有一条，计数是随附信息。
    #[test]
    fn jitter_counts_are_recorded_in_world_change() {
        let d = tmp("jitter");
        std::fs::write(d.join("a.txt"), b"1").unwrap();
        let _ = sweep(&d, &["a.txt".to_string()]).unwrap(); // 基线
        std::fs::write(d.join("a.txt"), b"22").unwrap();

        let mut counts = std::collections::HashMap::new();
        counts.insert("a.txt".to_string(), 7usize);
        let _ = sweep_with_events(&d, &["a.txt".to_string()], &counts).unwrap();

        let st = crate::store::Store::open(&d).unwrap();
        let entry = st
            .entries()
            .iter()
            .rev()
            .find(|e| {
                e.body.get("type").and_then(|x| x.as_str()) == Some(crate::store::T_WORLD_CHANGE)
            })
            .expect("应有一条世界变更");
        let got = entry
            .body
            .get("action")
            .and_then(|a| a.get("args"))
            .and_then(|a| a.get("event_counts"))
            .and_then(|c| c.get("a.txt"))
            .and_then(|v| v.as_int());
        assert_eq!(got, Some(7), "事件次数必须写进 action.args.event_counts");
        let _ = std::fs::remove_dir_all(&d);
    }

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

    /// **[WINDOW-2026-10-28] 窗口必须首尾相接，不能重叠。**
    ///
    /// 这条钉子的价值：如果 `Snapshot.at` 取在扫描**之前**，那么第 N+1 次的 window_from
    /// 会早于第 N 次的 window_to ⇒ 窗口重叠 ⇒ 「这段时间变了几次」被重复计数。
    /// 真机上我们正是把 at 挪到扫描**完成之后**才修好的。
    #[test]
    fn windows_are_adjacent_and_never_overlap() {
        let d = tmp("window");
        std::fs::write(d.join("a.txt"), b"1").unwrap();
        let _ = sweep(&d, &["a.txt".to_string()]).unwrap(); // 首扫建基线，无变更
        std::fs::write(d.join("a.txt"), b"22").unwrap();
        let _ = sweep(&d, &["a.txt".to_string()]).unwrap();
        std::fs::write(d.join("a.txt"), b"333").unwrap();
        let _ = sweep(&d, &["a.txt".to_string()]).unwrap();

        let st = crate::store::Store::open(&d).unwrap();
        let ws = crate::slices::world_changes(st.entries());
        assert_eq!(ws.len(), 2, "两次变化应各写一条世界变更");

        // 第 1 条：from = 上一次快照的时刻（首扫虽有快照但没有变更、不写条目 ⇒ from 不为空）
        assert!(
            !ws[0].1.is_empty(),
            "第一次有变化的巡边，window_from 应是上一次快照的时刻"
        );
        assert!(!ws[0].2.is_empty(), "window_to 必须有值");

        // 第 2 条：from 必须**恰好等于**上一条的 to（首尾相接）
        assert_eq!(
            ws[1].1, ws[0].2,
            "窗口重叠了：下一次的 from 应等于上一次的 to"
        );
        // RFC3339 的字典序 == 时间序
        assert!(ws[1].2 >= ws[1].1, "window_to 不得早于 window_from");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ensure_fresh_is_silent_when_no_watch_surface() {
        let d = tmp("nowatch");
        assert!(ensure_fresh(&d, &[]).is_none(), "没观测面就不该瞎扫");
        let _ = std::fs::remove_dir_all(&d);
    }
}
