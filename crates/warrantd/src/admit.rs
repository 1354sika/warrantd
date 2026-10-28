//! 准入自检 —— **「你现在到底有多可观测」**（`[ADMIT-2026-10-28]`）。
//!
//! # 为什么需要这个
//!
//! 用户定调：「让信使成为一个新的器官。其他智能体选择使用，那就要**按照信使的规矩来进入可观测世界**。」
//!
//! 「器官」的含义不是"拦得住"（MCP 拦不住宿主，这是结构性的），
//! 而是——**绕过去这件事本身必须立刻可见**。
//!
//! 那么"规矩"就不能是口号，得是**可检查、可分级**的东西。本模块就是那把尺子。
//!
//! # 四个等级
//!
//! | 级 | 名字 | 含义 |
//! |---|---|---|
//! | L0 | 盲 | 没有账本或没有观测面 —— 对这个项目一无所知 |
//! | L1 | 事后 | 有账本有观测面，但没有常驻 —— 被问时才扫 |
//! | L2 | 持续 | 有东西在持续看（快照新鲜） |
//! | L3 | 全经 | L2 + MCP 调用也经过代理 —— 连外部调用都看得见 |
//!
//! # 一条铁律：**自检不许改变被检对象**
//!
//! `assess` **绝不触发补扫**。否则它会把自己的"被问到"当成"有 daemon 在跑"，
//! 把 L1 自欺成 L2 —— 那就是假的乙轴，本项目作废过一个版本（v0.1.121）就是因为这个。
//! 所以这里**只读**，不写账本、不扫文件。

use std::path::Path;

use crate::store::{self, T_MCP_CALL};

/// 一项准入条件的检查结果。
#[derive(Debug, Clone)]
pub struct Check {
    pub what: &'static str,
    pub ok: bool,
    pub detail: String,
    /// 不满足时怎么办（**必须给**，否则等于说"做不到"）
    pub fix: Option<&'static str>,
}

/// 准入评估结果。
#[derive(Debug, Clone)]
pub struct Admission {
    /// 0..=3
    pub level: u8,
    pub name: &'static str,
    /// 一句话说清这一级的实际含义
    pub meaning: &'static str,
    pub checks: Vec<Check>,
}

impl Admission {
    /// 离下一级还差什么（已到 L3 则 `None`）。
    pub fn next_step(&self) -> Option<&'static str> {
        match self.level {
            0 => Some("先建观测面：在 .warrant/watch.list 里写要盯的路径/目录（一行一个）"),
            1 => Some("升到 L2：跑 `warrantd open`（或 daemon）让它持续看 —— 只被问时扫是「事后」不是「持续」"),
            2 => Some("升到 L3：把 MCP server 命令改成 `warrantd proxy -- <原命令>`，连外部调用也纳进来"),
            _ => None,
        }
    }

    /// 人读文本（CLI 与 MCP 共用同一份）。
    pub fn render(&self) -> String {
        let mut t = String::new();
        t.push_str(&format!(
            "可观测等级：L{} · {}\n{}\n\n",
            self.level, self.name, self.meaning
        ));
        t.push_str("逐项：\n");
        for c in &self.checks {
            t.push_str(&format!(
                "{} {} —— {}\n",
                if c.ok { "[x]" } else { "[ ]" },
                c.what,
                c.detail
            ));
            if !c.ok {
                if let Some(f) = c.fix {
                    t.push_str(&format!("      怎么补：{f}\n"));
                }
            }
        }
        if let Some(n) = self.next_step() {
            t.push_str(&format!("\n下一步：{n}\n"));
        } else {
            t.push_str("\n已在最高级。剩下的盲区见 warrant_status 的分组清单。\n");
        }
        t
    }
}

/// **只读**评估。不扫文件、不写账本（见模块头「自检不许改变被检对象」）。
pub fn assess(repo: &Path) -> Admission {
    let mut checks: Vec<Check> = Vec::new();

    // ① 账本可用
    let st = store::Store::open(repo);
    let (offset, entries_ok, has_mcp_call) = match &st {
        Ok(s) => (
            s.offset(),
            true,
            s.entries()
                .iter()
                .any(|e| e.body.get("type").and_then(|x| x.as_str()) == Some(T_MCP_CALL)),
        ),
        Err(_) => (0, false, false),
    };
    checks.push(Check {
        what: "账本可用",
        // [ADMIT-FIX-2026-10-28] 判据是「**能不能打开**」，不是「有没有内容」。
        // 首扫只写 grant（offset=1）—— 那是正常状态，原来拿 `offset > 1` 当"有内容"，
        // 结果刚建完基线的健康项目被判成 L0「盲」。真机上就是这么暴露的。
        ok: entries_ok,
        detail: if entries_ok {
            format!("offset={offset}")
        } else {
            "打不开（链断/权限/首次未初始化）".to_string()
        },
        fix: Some("跑一次 `warrantd once` 让它建账本"),
    });

    // ② 观测面非空
    let watch = crate::sweep::watch_surface_count(repo);
    checks.push(Check {
        what: "观测面非空",
        ok: watch > 0,
        detail: format!("{watch} 项（文件或目录）"),
        fix: Some("在 .warrant/watch.list 写路径，一行一个；或在命令行用 --watch a,b"),
    });

    // ③ 持续观测（快照新鲜）
    let age = crate::sweep::snapshot_age_secs(repo);
    let fresh = matches!(age, Some(s) if s <= crate::sweep::STALE_SECS);
    checks.push(Check {
        what: "有东西在持续看",
        ok: fresh,
        detail: match age {
            Some(s) => format!("上次观测 {}", crate::sweep::human_age(s)),
            None => "从未扫过".to_string(),
        },
        fix: Some("跑 `warrantd open`（手动打开，关窗口即停）；被问时才扫只算「事后」"),
    });

    // ④ MCP 经过代理（用账本自证，不读客户端配置）
    checks.push(Check {
        what: "MCP 调用经过代理",
        ok: has_mcp_call,
        detail: if has_mcp_call {
            "账本里有 mcp.call 条目 ⇒ 代理在工作".to_string()
        } else {
            "账本里没有任何 mcp.call ⇒ 外部工具调用全在观测面外".to_string()
        },
        fix: Some("把 MCP server 命令改成 `warrantd proxy --name <名> -- <原命令>`"),
    });

    // ⑤ 未申报变更（不判等级，但要说清"现在有多少东西没主人"）
    let unreported = match &st {
        Ok(s) => crate::slices::unreported(s.entries())
            .iter()
            .map(|u| u.changes.len())
            .sum::<usize>(),
        Err(_) => 0,
    };
    checks.push(Check {
        what: "没有未申报变更",
        ok: unreported == 0,
        detail: if unreported == 0 {
            "干净".to_string()
        } else {
            format!("{unreported} 处变了但没人申报（这是负事实，不是错误）")
        },
        fix: Some("看一眼 `warrantd unreported`；确认是预期副作用就写进 .warrant/ignore"),
    });

    let level = if !entries_ok || watch == 0 {
        0
    } else if !fresh {
        1
    } else if !has_mcp_call {
        2
    } else {
        3
    };
    let (name, meaning) = match level {
        0 => (
            "盲",
            "我对这个项目一无所知：没有账本或没有观测面。此时「没发生」这句话没有意义。",
        ),
        1 => (
            "事后",
            "有账本、有观测面，但只在被问到的时候才扫。两次被问之间的变化，我只能靠和上次快照比。",
        ),
        2 => (
            "持续",
            "有东西在持续看。文件层面的变化基本都在观测面内，但外部工具调用还看不见。",
        ),
        _ => (
            "全经",
            "持续观测 + 外部调用都经过代理。此时观测面覆盖了本地文件与 MCP 调用两条主要通路。",
        ),
    };

    Admission {
        level,
        name,
        meaning,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("warrantd-admit-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".git")).unwrap();
        d
    }

    /// 什么都不做 ⇒ L0（盲）。**这是最重要的等级**：它必须能被准确认出来，
    /// 否则用户会以为自己"在观测中"。
    #[test]
    fn empty_project_is_blind() {
        let d = tmp("blind");
        let a = assess(&d);
        assert_eq!(a.level, 0, "空项目必须是 L0：{}", a.render());
        assert!(
            a.checks.iter().any(|c| !c.ok && c.fix.is_some()),
            "不满足的项必须带补法"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **自检不许改变被检对象**：评两次，账本 offset 不能涨（否则会把 L1 自欺成 L2）。
    #[test]
    fn assess_is_read_only() {
        let d = tmp("ro");
        std::fs::write(d.join("a.txt"), b"hi").unwrap();
        std::fs::create_dir_all(d.join(".warrant")).unwrap();
        std::fs::write(d.join(".warrant/watch.list"), "a.txt\n").unwrap();
        let _ = crate::sweep::sweep(&d, &["a.txt".to_string()]);
        let before = store::Store::open(&d).unwrap().offset();
        let _ = assess(&d);
        let _ = assess(&d);
        let after = store::Store::open(&d).unwrap().offset();
        assert_eq!(before, after, "assess 绝不许写账本");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 有观测面 + 刚扫过 ⇒ 至少 L1，且**不会因为被问就跳成 L2**。
    #[test]
    fn fresh_snapshot_but_no_mcp_gives_level_2() {
        let d = tmp("l2");
        std::fs::write(d.join("a.txt"), b"hi").unwrap();
        std::fs::create_dir_all(d.join(".warrant")).unwrap();
        std::fs::write(d.join(".warrant/watch.list"), "a.txt\n").unwrap();
        let _ = crate::sweep::sweep(&d, &["a.txt".to_string()]);
        let a = assess(&d);
        assert_eq!(a.level, 2, "刚扫过但没 MCP 代理 ⇒ L2：{}", a.render());
        assert!(a.next_step().unwrap().contains("proxy"), "下一步要指向 L3");
        let _ = std::fs::remove_dir_all(&d);
    }
}
