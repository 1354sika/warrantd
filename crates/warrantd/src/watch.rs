//! 文件事件 watcher（洞⑤）：让「有变化」这件事**立刻**知道，而不是等下一轮定时巡边。
//!
//! **[WATCH-2026-10-29] 关键设计：watcher 只决定「什么时候扫」，不改变「记账粒度」。**
//!
//! 事件流进来只做一件事 —— 把等待中的巡边**提前唤醒**；扫仍然是快照差分，
//! 每轮仍然最多写一条世界变更。所以账本**不会**因为「上了 watcher」而变多。
//!
//! 为什么必须这样设计：如果每个事件都记一条，`cargo build` 一次就能产生几千条，
//! `npm install` 是几万条 —— 账本会立刻失控。**事件的价值是降低延迟，不是提高记账频率。**
//!
//! 盯不上的路径**不报错**：定时兜底扫描仍然在，所以「少盯一个」不会变成盲区，
//! 只是那一条的延迟回到采样级别。这一点必须诚实 —— 宁可慢，不可假。

use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::Duration;

// `watch()` 是 trait 方法，必须把 trait 带进作用域（否则只能看到 `unwatch` 之类）
use notify::Watcher as _;

/// 一个活着的文件 watcher。**drop 掉它监听就停**（内部句柄随之释放）。
pub struct Watcher {
    /// 账本所在的仓库根：事件路径要转成**相对路径**才能和快照的键对上
    repo: PathBuf,
    rx: Receiver<notify::Result<notify::Event>>,
    /// 必须持有：`notify` 的监听随句柄存活，drop 即停止
    _inner: notify::RecommendedWatcher,
    /// 真正盯上的路径（可能少于请求的 —— 路径不存在时盯不上，不报错）
    watched: Vec<PathBuf>,
    /// **[JITTER-2026-10-29] 本窗口内每个路径发生了几次变化。**
    ///
    /// 为什么记次数：快照差分只告诉我们「最后长什么样」，改了又改回来就只剩 `touched`。
    /// 次数不能还原过程，但至少能把「改了一次」和「改了 17 次」分开 ——
    /// 这两件事的意义完全不同（后者通常意味着 AI 在反复试错）。
    counts: std::collections::HashMap<String, usize>,
}

impl Watcher {
    /// 开始盯 `rels`（相对 `repo` 的路径，可以是文件也可以是目录）。
    pub fn start(repo: &Path, rels: &[String]) -> Result<Self, String> {
        let (tx, rx) = channel();
        let mut inner = notify::recommended_watcher(move |res| {
            // 发不出去（接收端已 drop）就算了：我们不能因为没人听就 panic
            let _ = tx.send(res);
        })
        .map_err(|e| format!("创建文件 watcher 失败：{e}"))?;

        let mut watched = Vec::new();
        for r in rels {
            let p = repo.join(r);
            // **[WATCH-2026-10-29] 盯父目录，不盯单文件。**
            // 实测：`notify` 6 在 Windows 上对「单个文件路径」做 Recursive 监听收不到事件
            // （`watch.dir_exists`/句柄族的差异），而 `warrantd open` 因为盯的是项目目录所以正常。
            // 代价是多收一点邻居事件 —— 但扫仍是快照差分，多余事件只会触发一次没变化的扫描。
            let target = if p.is_dir() {
                p.clone()
            } else {
                p.parent()
                    .map(|x| x.to_path_buf())
                    .unwrap_or_else(|| p.clone())
            };
            // 判「盯上了」看**目标本身是否存在** —— 盯父目录只是为了拿到事件，
            // 不代表那个文件真的在（否则不存在的路径也会被算成已盯上，虚报覆盖率）。
            if p.exists()
                && inner
                    .watch(&target, notify::RecursiveMode::Recursive)
                    .is_ok()
            {
                watched.push(p);
            }
        }
        Ok(Self {
            repo: repo.to_path_buf(),
            rx,
            _inner: inner,
            watched,
            counts: std::collections::HashMap::new(),
        })
    }

    /// 等到「有事件」或「超时」。
    ///
    /// - 返回 `true`：有事件发生 —— 该扫了（队列已尽量排空，一波事件只触发一次扫描）；
    /// - 返回 `false`：超时或 channel 断了 —— 走定时兜底，照常扫。
    ///
    /// **排空是必要的**：一次编译会连发几千条事件，逐条响应等于把 CPU 烧光；
    /// 而扫一次就能把所有变化都算出来。
    pub fn wait(&mut self, timeout: Duration) -> bool {
        let first = match self.rx.recv_timeout(timeout) {
            Ok(ev) => ev,
            Err(RecvTimeoutError::Timeout) => return false,
            // 监听断了：不再有事件，但定时兜底仍然有效 —— 不 panic、不静默退出
            Err(RecvTimeoutError::Disconnected) => return false,
        };
        self.absorb(first);
        while let Ok(ev) = self.rx.try_recv() {
            self.absorb(ev);
        }
        true
    }

    /// 把一条事件记进计数（按 repo 相对路径归一化，和快照的键一致）。
    fn absorb(&mut self, ev: notify::Result<notify::Event>) {
        let Ok(ev) = ev else {
            eprintln!("[watch-diag] event error: {ev:?}");
            return;
        };
        eprintln!("[watch-diag] paths={:?}", ev.paths);
        for p in ev.paths {
            // 只记**文件级**路径；目录事件交给快照差分去判（目录本身不进 counts）
            if p.is_dir() {
                continue;
            }
            // 转成 repo 相对路径（和快照/账本的键一致）：`src/a.rs`，不是 `C:/x/src/a.rs`
            let key = p
                .strip_prefix(&self.repo)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            // **[JITTER-2026-10-29] 跳过观测者自己的文件**（`.warrant/` 下的锁与快照）。
            // 真机实测：不过滤时 `event_counts` 里会混进 `.warrant/entries.lock: 2`、
            // `.warrant/snapshot.json: 2` —— 那是它在记自己的呼吸，纯噪音。
            if key.starts_with(&format!("{}/", crate::LEDGER_DIR)) {
                continue;
            }
            *self.counts.entry(key).or_insert(0) += 1;
        }
    }

    /// 取走本窗口的计数（取走即清空 —— 每个窗口只结算一次）。
    /// **看一眼**本窗口累计的次数（**不清空**）。
    ///
    /// `[JITTER-2026-10-29]` 为什么不在这里清空：真机踩到过 ——
    /// 事件先到、写入后到，这一轮扫出来 `changes=0`（还没写完），如果把计数取走就白丢了。
    /// 所以改成「先看，扫完确认真的结算了才清」。
    pub fn counts_snapshot(&self) -> std::collections::HashMap<String, usize> {
        self.counts.clone()
    }

    /// 结算完成后清空（只在**确实写了一条世界变更**时调用）。
    pub fn clear_counts(&mut self) {
        self.counts.clear();
    }

    /// 实际盯上的路径（诊断用：`status` 可以据此说明「真盯上了几个」）。
    pub fn watched(&self) -> &[PathBuf] {
        &self.watched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watcher_reports_change_quickly() {
        let d = std::env::temp_dir().join(format!("warrantd-watch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.txt"), b"1").unwrap();

        let mut w = Watcher::start(&d, &["a.txt".to_string()]).unwrap();
        assert_eq!(w.watched().len(), 1, "应当盯上那一个文件");

        // 注册句柄需要一点时间：立刻写文件有概率错过（测试里给 200ms，真机上人不可能这么快）
        std::thread::sleep(Duration::from_millis(200));
        std::fs::write(d.join("a.txt"), b"22").unwrap();
        // Windows 的文件事件通常 <100ms；给 5 秒宽松余量，避免慢机抖动
        assert!(w.wait(Duration::from_secs(5)), "写文件后必须收到事件");

        // 安静时应当超时返回 false（不能卡死）
        assert!(!w.wait(Duration::from_millis(300)), "没有变化时应超时返回");

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_path_is_skipped_not_fatal() {
        let d = std::env::temp_dir().join(format!("warrantd-watch-miss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // 一个存在、一个不存在：不许整只 watcher 起不来
        std::fs::write(d.join("real.txt"), b"x").unwrap();
        let w = Watcher::start(&d, &["real.txt".to_string(), "nope.txt".to_string()]).unwrap();
        assert_eq!(w.watched().len(), 1, "盯不上的路径应被跳过，只盯上的才算数");
        let _ = std::fs::remove_dir_all(&d);
    }
}
