//! 项目根解析 —— **防御式：宁可报错，也不写到错的地方**。
//!
//! # 为什么需要这个模块
//!
//! 别人的真机发现（`sentinel-verify` 的原话）：*some MCP clients launch servers from an
//! unexpected working directory (even `/`)*。这不是极端情况，是 MCP 生态的常态 ——
//! 客户端拉起 server 时给什么 cwd 完全由客户端决定。
//!
//! 对我们的后果特别严重：账本落在 `<repo>/.warrant/`，
//! **如果 cwd 解析错了，账本会安静地写到别的地方，而不会有任何报错** ——
//! 用户以为在记这个项目，其实记在 `C:\.warrant\` 或者别的项目里。
//! 这种失效是**静默的、事后才发现、且不可合并**（两本账链位不同，拼不回去）。
//!
//! # 解析顺序（从强到弱）
//!
//! 1. `--repo` 显式参数 —— 用户说了算
//! 2. `WARRANTD_REPO` 环境变量 —— 启动器说了算
//! 3. MCP `roots` capability —— **尚未实现**（还没有 MCP 层，见 `lib.rs` 的待办）
//! 4. 当前工作目录 —— **但必须校验**（前三条都没有时才走这条）
//!
//! # 两道闸
//!
//! - **硬拒绝**（任何来源都拒）：磁盘根 / 用户主目录 / 系统目录 —— 在这些地方建 `.warrant/`
//!   就是污染机器，没有正当用途。
//! - **软校验**（只有 cwd 来源才要求）：必须有 `.git` 或已存在 `.warrant/`。
//!   理由：cwd 是我们唯一"猜"的来源，猜就得有证据。
//!   显式 `--repo` 不要求 —— 用户可能就是想在一个还没 git init 的目录里用。

use std::path::{Path, PathBuf};

/// 解析结果：**把"怎么定下来的"一起带出去**。
///
/// 为什么必须带 `source`：观测者的第一条诚实义务是"说清我在看哪里"。
/// `status` 会把它原样报出来 —— 用户看一眼就知道账本记在哪个项目。
#[derive(Debug, Clone)]
pub struct Resolution {
    pub root: PathBuf,
    pub source: &'static str,
}

/// 解析项目根。失败时返回**可操作**的错误（说清为什么拒、怎么修）。
pub fn resolve(explicit: Option<&str>) -> Result<Resolution, String> {
    // ① 显式参数
    if let Some(p) = explicit {
        let root = absolutize(Path::new(p))?;
        reject_dangerous(&root, "--repo")?;
        return Ok(Resolution {
            root,
            source: "--repo（显式指定）",
        });
    }

    // ② 环境变量
    if let Ok(v) = std::env::var("WARRANTD_REPO") {
        let v = v.trim();
        if !v.is_empty() {
            let root = absolutize(Path::new(v))?;
            reject_dangerous(&root, "WARRANTD_REPO")?;
            return Ok(Resolution {
                root,
                source: "WARRANTD_REPO 环境变量",
            });
        }
    }

    // ③（MCP roots —— 未实现，留位）

    // ④ 当前工作目录：最后一个来源，也是唯一"猜"出来的 ⇒ 必须校验
    let cwd = std::env::current_dir().map_err(|e| format!("取当前目录失败：{e}"))?;
    reject_dangerous(&cwd, "当前工作目录")?;
    if !looks_like_project(&cwd) {
        return Err(format!(
            "拒绝把账本建在 `{}`：这里既没有 .git，也没有已存在的 .warrant/。\n\
             为什么会这样：MCP 客户端拉起 server 时给的工作目录由客户端决定，\n\
             常见情况是从 `C:\\` 或某个无关目录启动 —— 这样账本会安静地记错地方，且事后无法合并。\n\
             怎么修（三选一）：\n\
             · 启动时加 `--repo <你的项目>`\n\
             · 设环境变量 `WARRANTD_REPO=<你的项目>`\n\
             · 或者先进到项目目录再启动\n\
             （如果你确实想在一个还没 git init 的目录里用：显式加 `--repo`，那代表你说了算。）",
            cwd.display()
        ));
    }
    Ok(Resolution {
        root: cwd,
        source: "当前工作目录（已校验：有 .git 或 .warrant）",
    })
}

fn absolutize(p: &Path) -> Result<PathBuf, String> {
    if p.is_absolute() {
        Ok(normalize(p))
    } else {
        let cwd = std::env::current_dir().map_err(|e| format!("取当前目录失败：{e}"))?;
        Ok(normalize(&cwd.join(p)))
    }
}

/// 去掉 `.` 与多余的 `..`（不碰符号链接 —— 那需要 IO，且会掩盖用户的真实意图）。
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("USERPROFILE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
        })
        .map(|p| normalize(&p))
}

fn system_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if cfg!(windows) {
        if let Ok(w) = std::env::var("SystemRoot") {
            v.push(normalize(Path::new(&w)));
        }
        v.push(PathBuf::from("C:\\Windows"));
        v.push(PathBuf::from("C:\\Program Files"));
        v.push(PathBuf::from("C:\\Program Files (x86)"));
    } else {
        for d in ["/usr", "/etc", "/bin", "/sbin", "/var", "/boot", "/dev", "/proc", "/sys"] {
            v.push(PathBuf::from(d));
        }
    }
    v
}

/// **硬拒绝**：在这些地方建账本没有任何正当用途，只会污染机器。
fn reject_dangerous(p: &Path, from: &str) -> Result<(), String> {
    if p.parent().is_none() {
        return Err(format!(
            "拒绝把账本建在磁盘根 `{}`（来源：{from}）—— 那会污染整块盘。\n\
             请指定一个具体的项目目录。",
            p.display()
        ));
    }
    if let Some(h) = home_dir() {
        if *p == h {
            return Err(format!(
                "拒绝把账本建在用户主目录本身 `{}`（来源：{from}）—— 那会把所有不相干的改动\n\
                 都记进同一本账，等于没有观测面。请指定具体的项目目录。",
                p.display()
            ));
        }
    }
    for d in system_dirs() {
        let inside = p == d || p.starts_with(&d);
        if inside {
            return Err(format!(
                "拒绝把账本建在系统目录 `{}`（来源：{from}）—— 那里不属于任何项目。",
                p.display()
            ));
        }
    }
    Ok(())
}

/// 这个目录像不像一个"项目"（cwd 来源专用）。
fn looks_like_project(p: &Path) -> bool {
    p.join(".git").exists() || p.join(crate::LEDGER_DIR).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_removes_curdir_and_resolves_parent() {
        assert_eq!(normalize(Path::new("a/./b")), PathBuf::from("a/b"));
        assert_eq!(normalize(Path::new("a/b/../c")), PathBuf::from("a/c"));
    }

    #[test]
    fn explicit_repo_wins_over_cwd() {
        // 显式参数即使指向"不像项目"的目录也必须接受 —— 用户说了算
        let tmp = std::env::temp_dir();
        let r = resolve(Some(&tmp.display().to_string())).unwrap();
        assert!(r.source.contains("--repo"));
    }

    #[test]
    fn disk_root_is_refused() {
        let root = if cfg!(windows) { "C:\\" } else { "/" };
        let e = resolve(Some(root)).unwrap_err();
        assert!(e.contains("磁盘根"), "{e}");
    }

    #[test]
    fn home_dir_is_refused() {
        let h = home_dir().expect("测试机应有 USERPROFILE/HOME");
        let e = resolve(Some(&h.display().to_string())).unwrap_err();
        assert!(e.contains("主目录"), "{e}");
    }

    #[test]
    fn relative_repo_is_absolutized() {
        let r = resolve(Some("sub/dir")).unwrap();
        assert!(r.root.is_absolute(), "相对路径必须绝对化：{}", r.root.display());
        assert!(r.root.ends_with("sub/dir") || r.root.ends_with("sub\\dir"));
    }

    /// cwd 是**唯一"猜"出来的来源** ⇒ 必须校验；有证据才接受。
    ///
    /// 两个断言都要改**进程级全局 cwd** ⇒ 必须放在同一个测试里顺序执行。
    /// 拆成两个 `#[test]` 会被并行执行互相踩（真机在 2026-10-27 当场踩到：
    /// 一个测试把 cwd 改走、另一个测试恢复时目标已被删 ⇒ NotFound）。
    /// `CwdGuard` 保证即使 panic 也会还原 cwd，不污染其他测试。
    #[test]
    fn cwd_is_validated_before_being_trusted() {
        struct CwdGuard(PathBuf);
        impl Drop for CwdGuard {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(&self.0);
            }
        }

        let old = std::env::current_dir().unwrap();
        let _guard = CwdGuard(old);
        let base = std::env::temp_dir().join(format!("warrantd-root-{}", std::process::id()));
        let bare = base.join("bare");
        let proj = base.join("proj");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&bare).unwrap();
        std::fs::create_dir_all(proj.join(".git")).unwrap();

        // case 1：既无 .git 也无 .warrant ⇒ 拒绝，且错误里必须给出修法
        std::env::set_current_dir(&bare).unwrap();
        let e = match resolve(None) {
            Ok(r) => panic!("不该接受一个既无 .git 也无 .warrant 的 cwd：{}", r.root.display()),
            Err(e) => e,
        };
        assert!(
            e.contains("WARRANTD_REPO") && e.contains("--repo"),
            "错误里必须给出修法：{e}"
        );

        // case 2：有 .git ⇒ 接受，且如实标「已校验」
        std::env::set_current_dir(&proj).unwrap();
        let r = resolve(None).unwrap();
        assert!(r.source.contains("已校验"), "来源要如实报：{}", r.source);

        let _ = std::fs::remove_dir_all(&base);
    }
}
