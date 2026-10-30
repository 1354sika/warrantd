//! 观测白名单 —— warrantd 唯一被允许的「看世界」方式。
//!
//! # 为什么是白名单，而不是任意 shell
//!
//! 这不是安全偏好，是**自洽性**要求：
//!
//! > 一个监督世界变化的进程，如果自己能用任意命令改变世界，它的账本立刻失去意义 ——
//! > 它分不清「世界变了」和「我自己弄的」。
//!
//! 而且会立刻陷入无限回退：它跑的命令本身需要被认定，那谁来认定？
//! （同源红线：`crates/warrant/SPEC.md` §1「不进入实时控制回路」。）
//!
//! 最根本的理由是 `ADAPTER.md:23`：**适配器不被信任——它和被控软件一样会撒谎**。
//! ⇒ **daemon 自己也是被控对象**，它不能豁免于自己的规则。
//!
//! # 三条性质（缺一不可）
//!
//! 1. **封闭**：不在 [`WHITELIST`] 里的观测，warrantd **结构上做不到**（不是「不推荐」）。
//! 2. **随二进制发布**：表是编译期常量，AI 改不了，也不接受运行时注册。
//! 3. **每条自带档位与副作用申报**：向自己的账本申报，**像适配器一样**。
//!
//! # 唯一会写盘的一条
//!
//! [`run_build_test`] 会写构建产物目录。因此它必须 `--allow-side-effects` 显式开启，
//! 而且它造成的变化**必须标记为「daemon 自产」**，不能算进「未申报变更」——
//! 否则 daemon 会污染自己的账本。这一条正好把「未申报变更＝负事实」逼出自洽性：
//! **观测者必须能为自己的副作用负责。**

use std::path::{Path, PathBuf};

use warrant::json::Value;

use crate::util::{arr, now_rfc3339, obj, s};

/// 一条观测原语的**声明**（白名单条目）。
#[derive(Debug, Clone, Copy)]
pub struct ProbeDecl {
    /// 原语 id（CLI 与账本里都用它）
    pub id: &'static str,
    /// **保守申报档**：写进 observation.tier，必须等于 capability 的申报值（P5）。
    pub tier: &'static str,
    /// **真实上限档**（元数据 `tier_hint`，不参与判定）。理由见 doc 注。
    pub tier_hint: &'static str,
    /// 只读？false = 需要 `--allow-side-effects`。
    pub read_only: bool,
    /// 它会写什么（空 = 不写）。
    pub writes: &'static str,
    /// 人读说明：这条观测回答什么问题。
    pub desc: &'static str,
}

/// ★ 观测白名单（**封闭表**）。
///
/// 排序按「能回答什么」而不是按字母；新增条目必须同时升 [`crate::PROBE_SPEC_VERSION`]。
pub const WHITELIST: &[ProbeDecl] = &[
    ProbeDecl {
        id: "fs.hash",
        tier: "C1",
        tier_hint: "C2",
        read_only: true,
        writes: "",
        desc: "指定路径的内容 sha256（真实文件，不是任何进程写的副本）",
    },
    ProbeDecl {
        id: "fs.meta",
        tier: "C1",
        tier_hint: "C0",
        read_only: true,
        writes: "",
        desc: "指定路径的 size/mtime（便宜，但 size/mtime 未变视为未变 ⇒ 会漏）",
    },
    ProbeDecl {
        id: "vcs.state",
        tier: "C1",
        tier_hint: "C2",
        read_only: true,
        writes: "",
        desc: "git HEAD / 分支 / 脏文件数（第三方软件自产的量，不是我们算的）",
    },
    ProbeDecl {
        id: "proc.table",
        tier: "C1",
        tier_hint: "C2",
        read_only: true,
        writes: "",
        desc: "指定进程名是否存在（操作系统自产）",
    },
    ProbeDecl {
        id: "port.table",
        tier: "C1",
        tier_hint: "C1",
        read_only: true,
        writes: "",
        desc: "连接表条数（只读、粗粒度；解析不了就如实返回 unsupported）",
    },
    ProbeDecl {
        id: "build.test",
        tier: "C1",
        tier_hint: "C1",
        read_only: false,
        writes: "构建产物目录（如 target/、node_modules/.cache）",
        desc: "跑一条构建/测试命令，只取退出码（编译器/测试框架自己的判定，不经过 AI 的嘴）",
    },
    ProbeDecl {
        id: "net.conns",
        tier: "C1",
        tier_hint: "C1",
        read_only: true,
        writes: "",
        desc: "外部网络连接的对端集合（排除本机回环）—— 新增一个陌生对端就值得看一眼",
    },
    ProbeDecl {
        id: "vcs.remote",
        tier: "C1",
        tier_hint: "C0",
        read_only: true,
        writes: "",
        desc: "和上游分支的差距（领先/落后几个提交）。**只读本地已知的远端 ref，不 fetch**",
    },
    ProbeDecl {
        id: "dir.fingerprint",
        tier: "C1",
        tier_hint: "C0",
        read_only: true,
        writes: "",
        desc: "目录结构指纹（条目数/总字节/最新 mtime/结构哈希）—— 只 stat，不读内容",
    },
];

pub fn decl(id: &str) -> Option<&'static ProbeDecl> {
    WHITELIST.iter().find(|d| d.id == id)
}

pub fn is_whitelisted(id: &str) -> bool {
    decl(id).is_some()
}

/// 观测结果：**只放断言集，不返回 verdict**（`ADAPTER.md:83`「适配器无权宣布一致」）。
///
/// `result` 是 `{键: 值}` 形式，键与值都能被 `warrant::projection::compare` 直接比对 ——
/// 这样「agent 说 X = H」与「daemon 看到 X = H」用的是同一套比较语义。
#[derive(Debug, Clone)]
pub struct Observed {
    pub method: String,
    pub tier: String,
    pub tier_hint: String,
    pub channel: String,
    pub observed_at: String,
    pub result: Value,
    /// 证据：真实路径 + 哈希（第三方据此**自己复算**，不必信这句话）
    pub evidence: Vec<String>,
    /// **本次观测自身**造成的变化（不算世界的变更）。空 = 只读观测。
    pub self_side_effects: Vec<String>,
}

impl Observed {
    fn new(method: &str, result: Value) -> Self {
        let d = decl(method);
        Self {
            method: method.to_string(),
            tier: d.map(|x| x.tier).unwrap_or(crate::DECLARED_TIER).to_string(),
            tier_hint: d.map(|x| x.tier_hint).unwrap_or("C1").to_string(),
            channel: crate::CHANNEL.to_string(),
            observed_at: now_rfc3339(),
            result,
            evidence: Vec::new(),
            self_side_effects: Vec::new(),
        }
    }
}

/// 解析路径列表：逗号 / 分号分隔，或 `**`（= 扫描 root 下受管文件，由调用方限制）。
pub fn parse_paths(raw: &str) -> Vec<String> {
    raw.split([',', ';'])
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn abs(root: &Path, rel: &str) -> PathBuf {
    let p = Path::new(rel);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

/// `fs.hash` —— 内容哈希。**C2 能力**（任何人能自己复算），申报 C1（保守）。
pub fn run_fs_hash(root: &Path, rels: &[String]) -> Result<Observed, String> {
    use sha2::{Digest, Sha256};
    let mut pairs: Vec<(String, Value)> = Vec::new();
    let mut evidence: Vec<String> = Vec::new();
    for rel in rels {
        let p = abs(root, rel);
        let bytes = std::fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
        let digest = Sha256::digest(&bytes);
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        pairs.push((rel.clone(), s(&format!("sha256:{hex}"))));
        evidence.push(format!("{} sha256:{hex}", p.display()));
    }
    let mut ob = Observed::new("fs.hash", Value::Object(pairs));
    ob.evidence = evidence;
    Ok(ob)
}

/// `fs.meta` —— size/mtime。**C0 能力**，如实标在 `tier_hint`（申报仍走 C1 的通道）。
pub fn run_fs_meta(root: &Path, rels: &[String]) -> Result<Observed, String> {
    let mut pairs: Vec<(String, Value)> = Vec::new();
    let mut evidence: Vec<String> = Vec::new();
    for rel in rels {
        let p = abs(root, rel);
        let md = std::fs::metadata(&p).map_err(|e| format!("stat {}: {e}", p.display()))?;
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        pairs.push((format!("{rel}.size"), Value::Int(md.len() as i64)));
        pairs.push((format!("{rel}.mtime"), Value::Int(mtime)));
        evidence.push(format!("{} size={} mtime={mtime}", p.display(), md.len()));
    }
    let mut ob = Observed::new("fs.meta", Value::Object(pairs));
    ob.evidence = evidence;
    Ok(ob)
}

fn run_cmd(cwd: &Path, prog: &str, args: &[&str]) -> Result<String, String> {
    let mut cmd = std::process::Command::new(prog);
    cmd.args(args).current_dir(cwd);
    crate::util::hide_console(&mut cmd);
    let out = cmd.output().map_err(|e| format!("spawn {prog}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{prog} exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// 判一个 `ip:port` 是不是"外部对端"。
///
/// 排除：回环、通配、IPv6 未指定、以及本机自己 —— 剩下的才是"东西可能出门"。
///
/// ⚠️ **只能用前缀判定，绝不能用 `contains`**：真机上就踩过 ——
/// `2606:2800:220:1::1:443` 是公网 IPv6，但 `contains("::1")` 会把它误判成回环。
/// 那等于**把所有 IPv6 外网连接藏起来**，而这恰恰是本原语要防的东西（数据外传）。
fn is_external_peer(addr: &str) -> bool {
    let a = addr.trim();
    if a.is_empty() {
        return false;
    }
    let low = a.to_ascii_lowercase();
    for p in [
        "127.",          // IPv4 回环
        "0.0.0.0",       // IPv4 通配
        "[::1]",         // IPv6 回环（带方括号）
        "[::]",          // IPv6 通配（带方括号）
        "::1",           // IPv6 回环（裸）
        "::",            // IPv6 通配（裸）
        "localhost",
        "*:",            // ss 输出的通配
    ] {
        if low.starts_with(p) {
            return false;
        }
    }
    true
}

/// `net.conns` —— **外部**对端集合（洞②：网络）。
///
/// # 为什么它值钱
///
/// 其他观测都在看"本地文件被改了"；只有这一条能回答「**有没有东西出门**」。
/// 数据一旦外传就收不回来 —— 所以"多了一个陌生对端"是这套系统里最该被立刻看见的事件。
///
/// # 它不知道什么
///
/// 只知道**对端地址**，不知道传了什么内容（那要抓包，属结构性做不到）。
/// 所以它证明的是「建立了连接」，不是「泄露了数据」—— 两者不能混。
pub fn run_net_conns(full: bool) -> Result<Observed, String> {
    let listing = if cfg!(windows) {
        run_cmd(Path::new("."), "netstat", &["-ano"])?
    } else {
        run_cmd(Path::new("."), "ss", &["-tun"]).or_else(|_| run_cmd(Path::new("."), "netstat", &["-tun"]))?
    };
    let mut peers: Vec<String> = Vec::new();
    let mut total = 0usize;
    for line in listing.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        // netstat -ano: TCP  <local>  <remote>  <state>  <pid>；ss: 协议 State Recv-Q Send-Q Local Peer
        let remote = if cfg!(windows) { cols.get(2) } else { cols.last() };
        if let Some(r) = remote {
            if r.contains(':') && !r.starts_with("Local") && !r.starts_with("Peer") {
                total += 1;
                if is_external_peer(r) && !peers.iter().any(|x| x == r) {
                    peers.push(r.to_string());
                }
            }
        }
    }
    peers.sort();
    let joined = peers.join(",");
    // [NET-SLIM-2026-10-28] **默认只给集合指纹 + 样本，不列全量**。
    //
    // 真机实测：这台机器 338 个连接 / 90 个外部对端，全长 4000+ 字 —— 那是"清单"，
    // 而观测面要的是"**变没变**"。清单既贵又没帮助（90 条里多一条，人根本看不出）。
    // 所以：哈希判断变化，样本供人扫一眼；要看全量显式加参数 `full`。
    let sha = {
        use sha2::{Digest, Sha256};
        format!(
            "sha256:{}",
            Sha256::digest(joined.as_bytes())
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    };
    let sample = peers.iter().take(8).cloned().collect::<Vec<_>>().join(",");
    let result = if full {
        obj(vec![
            ("net.peers_sha", s(&sha)),
            ("net.peers", s(&joined)),
            ("net.peer_count", Value::Int(peers.len() as i64)),
            ("net.conn_count", Value::Int(total as i64)),
        ])
    } else {
        obj(vec![
            ("net.peers_sha", s(&sha)),
            ("net.sample", s(&sample)),
            ("net.peer_count", Value::Int(peers.len() as i64)),
            ("net.conn_count", Value::Int(total as i64)),
        ])
    };
    let mut ob = Observed::new("net.conns", result);
    ob.evidence = vec![format!(
        "netstat/ss 的原始输出（操作系统自产）；{} 个连接 / {} 个外部对端，对端集合 sha={}（要看全量：probe net.conns full）",
        total,
        peers.len(),
        sha
    )];
    Ok(ob)
}

/// `vcs.remote` —— 和上游分支的差距。
///
/// **只读本地已知的远端 ref，不 `git fetch`**：fetch 是网络操作、还会改 `.git/refs`，
/// 属于"有副作用的观测"，不该混进只读面。所以这条数据的诚实边界是：
/// **它反映的是"上次 fetch 时"的远端状态，可能已经过期**（`tier_hint` 如实标 C0）。
pub fn run_vcs_remote(repo: &Path) -> Result<Observed, String> {
    let up = run_cmd(repo, "git", &["rev-parse", "--abbrev-ref", "@{u}"])
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    if up.is_empty() {
        let result = obj(vec![
            ("git.upstream", s("")),
            ("git.ahead", Value::Int(0)),
            ("git.behind", Value::Int(0)),
        ]);
        let mut ob = Observed::new("vcs.remote", result);
        ob.evidence = vec!["这个分支没有设置上游（没有可比的远端）".to_string()];
        return Ok(ob);
    }
    let counts = run_cmd(repo, "git", &["rev-list", "--left-right", "--count", "HEAD...@{u}"])
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    let (ahead, behind) = {
        let mut it = counts.split_whitespace();
        let a = it.next().and_then(|x| x.parse::<i64>().ok()).unwrap_or(0);
        let b = it.next().and_then(|x| x.parse::<i64>().ok()).unwrap_or(0);
        (a, b)
    };
    let result = obj(vec![
        ("git.upstream", s(&up)),
        ("git.ahead", Value::Int(ahead)),
        ("git.behind", Value::Int(behind)),
    ]);
    let mut ob = Observed::new("vcs.remote", result);
    ob.evidence = vec![format!(
        "git rev-list HEAD...{up} = 领先 {ahead} / 落后 {behind}（基于上次 fetch 的远端状态，可能过期）"
    )];
    Ok(ob)
}

/// 目录结构指纹的**全局条目上限**（所有目录共享这一个预算）。
///
/// 为什么要有：`node_modules` 动辄十万个文件。只 stat 也比全量读内容便宜得多，
/// 但仍然要有个上界 —— **daemon 卡死比漏报更糟**（卡死时它连"我卡了"都报不出来）。
pub const FINGERPRINT_MAX_ENTRIES: usize = 50_000;

/// 递归收集 `相对路径:大小`。预算耗尽即停（返回 `true` = 已截断）。
///
/// **不跟随符号链接**：既为了防环，也为了不把链接指向的外部目录算进来（那会污染观测面）。
fn walk_entries(base: &Path, budget: &mut usize, out: &mut Vec<String>) -> bool {
    let mut stack = vec![base.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            if *budget == 0 {
                // 预算耗尽：立刻返回「已截断」，调用方必须把它写进指纹（不许隐藏）
                return true;
            }
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                let rel = p
                    .strip_prefix(base)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(format!("{rel}:{size}"));
                *budget -= 1;
            }
        }
    }
    false
}

/// 对单个目录算**结构指纹**。
///
/// 返回 `(指纹串, 是否截断)`。指纹串形如
/// `entries=1234;bytes=567890;newest=1793059200;sha=sha256:…`。
///
/// **它证明"这个目录变了"，不证明"哪个文件变成了什么"** ——
/// 所以真实上限是 `C0`（`tier_hint` 如实标注）。要定论必须升级到 `fs.hash` 对具体文件。
pub fn fingerprint_of(dir: &Path, budget: &mut usize) -> (String, bool) {
    let mut entries: Vec<String> = Vec::new();
    let truncated = walk_entries(dir, budget, &mut entries);
    entries.sort();
    let total_digest = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for e in &entries {
            h.update(e.as_bytes());
            h.update(b"\n");
        }
        format!("sha256:{}", h.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>())
    };
    let bytes: u64 = entries
        .iter()
        .filter_map(|e| e.rsplit(':').next().and_then(|s| s.parse::<u64>().ok()))
        .sum();
    // 最新 mtime：额外 walk 一遍太贵 ⇒ 用目录自身 mtime 作粗代理（目录条目变化会更新它）
    let newest = std::fs::metadata(dir)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (
        format!(
            "entries={};bytes={};newest={};sha={}{}",
            entries.len(),
            bytes,
            newest,
            total_digest,
            if truncated { ";truncated" } else { "" }
        ),
        truncated,
    )
}

/// `dir.fingerprint` —— 目录结构指纹（**洞①：命令副作用**的主力）。
///
/// # 为什么需要它
///
/// agent 跑 `npm install` / `cargo build` / `git commit` 时，改的往往是
/// **不在 watch 列表里的大目录**（`node_modules` / `target`）。逐个读内容太贵，
/// 但只 stat 一遍很便宜 —— 这一步让"命令改了东西"从**看不见**变成**看得见**（哪怕看不清）。
pub fn run_dir_fingerprint(root: &Path, dirs: &[String]) -> Result<Observed, String> {
    let mut pairs: Vec<(String, Value)> = Vec::new();
    let mut evidence: Vec<String> = Vec::new();
    let mut budget = FINGERPRINT_MAX_ENTRIES;
    for rel in dirs {
        let p = abs(root, rel);
        if !p.is_dir() {
            return Err(format!("{} 不是目录（dir.fingerprint 只接受目录）", p.display()));
        }
        let (fp, truncated) = fingerprint_of(&p, &mut budget);
        pairs.push((rel.clone(), s(&fp)));
        let tail = if truncated { "（已截断：超出条目预算）" } else { "" };
        evidence.push(format!("{}{fp}{tail}", p.display()));
    }
    let mut ob = Observed::new("dir.fingerprint", Value::Object(pairs));
    ob.evidence = evidence;
    Ok(ob)
}

/// 预期副作用清单：`.warrant/ignore`，一行一个路径前缀，`#` 开头是注释。
///
/// # 为什么必须有它
///
/// 没有它，`target/` 每次编译、`node_modules` 每次安装都会被报成「未申报变更」——
/// **天天响的警报，用户第一件事就是把它关掉**。误报会杀死真警报。
///
/// # 为什么它自己也在观测面里（自洽性）
///
/// 放宽观测面的动作必须**可见**：否则 agent 只要往 ignore 里加一行，就能把自己的改动藏起来。
/// 所以 ignore 文件的哈希被自动纳入快照（键 `special:ignore`），它的任何改动都会进账本。
/// **观测者不许改自己的眼睛而不留痕。**
pub fn ignore_rules(repo: &Path) -> Vec<String> {
    let p = repo.join(crate::LEDGER_DIR).join("ignore");
    let Ok(text) = std::fs::read_to_string(&p) else {
        return Vec::new();
    };
    text.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// 路径是否被 ignore 规则覆盖（前缀匹配，`dir:` 前缀会先剥掉）。
pub fn is_ignored(path: &str, rules: &[String]) -> bool {
    let p = path.strip_prefix("dir:").unwrap_or(path);
    rules.iter().any(|r| {
        p == r || p.starts_with(&format!("{r}/")) || p.starts_with(&format!("{r}\\"))
    })
}

/// `vcs.state` —— git 自产的量。**这是第三方软件自己报的**，不是我们算的。
pub fn run_vcs_state(repo: &Path) -> Result<Observed, String> {
    let head = run_cmd(repo, "git", &["rev-parse", "HEAD"])?;
    let head = head.trim().to_string();
    let branch = run_cmd(repo, "git", &["rev-parse", "--abbrev-ref", "HEAD"])
        .map(|x| x.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let status = run_cmd(repo, "git", &["status", "--porcelain"]).unwrap_or_default();
    let dirty = status.lines().filter(|l| !l.trim().is_empty()).count() as i64;
    let result = obj(vec![
        ("git.head", s(&head)),
        ("git.branch", s(&branch)),
        ("git.dirty", Value::Int(dirty)),
    ]);
    let mut ob = Observed::new("vcs.state", result);
    ob.evidence = vec![format!(
        "{} git rev-parse HEAD = {head}（可由第三方在本地复算）",
        repo.display()
    )];
    Ok(ob)
}

/// `proc.table` —— 进程存在性。操作系统自产。
pub fn run_proc_table(names: &[String]) -> Result<Observed, String> {
    let listing = if cfg!(windows) {
        run_cmd(Path::new("."), "tasklist", &["/FO", "CSV", "/NH"])?
    } else {
        run_cmd(Path::new("."), "ps", &["-eo", "comm="])?
    };
    let lower = listing.to_lowercase();
    let mut pairs: Vec<(String, Value)> = Vec::new();
    for n in names {
        let hit = lower.contains(&n.to_lowercase());
        pairs.push((format!("proc.{n}"), Value::Bool(hit)));
    }
    let mut ob = Observed::new("proc.table", Value::Object(pairs));
    ob.evidence = vec!["tasklist / ps 的原始输出（操作系统自产）".to_string()];
    Ok(ob)
}

/// `port.table` —— 连接表条数。**解析不了就如实说 unsupported，不猜。**
pub fn run_port_table() -> Result<Observed, String> {
    let listing = if cfg!(windows) {
        run_cmd(Path::new("."), "netstat", &["-ano"])?
    } else {
        run_cmd(Path::new("."), "ss", &["-tun"])
            .or_else(|_| run_cmd(Path::new("."), "netstat", &["-tun"]))?
    };
    let n = listing
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with("Active") && !t.starts_with("Proto") && !t.starts_with("活动")
        })
        .count() as i64;
    let result = obj(vec![("net.connections", Value::Int(n))]);
    let mut ob = Observed::new("port.table", result);
    ob.evidence = vec!["netstat / ss 的原始输出（操作系统自产；粗粒度计数）".to_string()];
    Ok(ob)
}

/// `build.test` —— 跑一条构建/测试命令，**只取退出码**。
///
/// **唯一会写盘的原语**：必须 `allow_side_effects = true`，且它造成的变化记进
/// `self_side_effects`，**不算世界的变更**。
pub fn run_build_test(cwd: &Path, cmdline: &str, allow_side_effects: bool) -> Result<Observed, String> {
    let d = decl("build.test").expect("build.test 必须在白名单里");
    if !d.read_only && !allow_side_effects {
        return Err(format!(
            "{} 有副作用（会写：{}）—— 必须显式加 --allow-side-effects 才允许执行。\
             拒绝是默认，不是故障。",
            d.id, d.writes
        ));
    }
    let parts: Vec<String> = cmdline.split_whitespace().map(|x| x.to_string()).collect();
    let (prog, args) = parts
        .split_first()
        .ok_or_else(|| "build.test 需要一个命令（如 `cargo test -p warrant`）".to_string())?;
    let args: Vec<&str> = args.iter().map(|x| x.as_str()).collect();
    let mut cmd = std::process::Command::new(prog);
    cmd.args(&args).current_dir(cwd);
    crate::util::hide_console(&mut cmd);
    let out = cmd.output().map_err(|e| format!("spawn {prog}: {e}"))?;
    let code = out.status.code().unwrap_or(-1) as i64;
    let result = obj(vec![
        ("build.cmd", s(cmdline)),
        ("build.exit", Value::Int(code)),
        ("build.stdout_bytes", Value::Int(out.stdout.len() as i64)),
        ("build.stderr_bytes", Value::Int(out.stderr.len() as i64)),
    ]);
    let mut ob = Observed::new("build.test", result);
    ob.evidence = vec![format!(
        "在 {} 执行 `{cmdline}`，退出码 {code}（编译器/测试框架自产）",
        cwd.display()
    )];
    ob.self_side_effects = vec![d.writes.to_string()];
    Ok(ob)
}

/// 按 id 分发。**这是唯一入口** —— 绕过它就等于绕过了白名单。
pub fn run(id: &str, root: &Path, arg: &str, allow_side_effects: bool) -> Result<Observed, String> {
    let rels = parse_paths(arg);
    match id {
        "fs.hash" => run_fs_hash(root, &rels),
        "fs.meta" => run_fs_meta(root, &rels),
        "vcs.state" => run_vcs_state(root),
        "proc.table" => run_proc_table(&rels),
        "port.table" => run_port_table(),
        "build.test" => run_build_test(root, arg, allow_side_effects),
        "dir.fingerprint" => run_dir_fingerprint(root, &rels),
        "net.conns" => run_net_conns(arg.eq_ignore_ascii_case("full")),
        "vcs.remote" => run_vcs_remote(root),
        other => Err(format!(
            "「{other}」不在观测白名单里（{}）—— warrantd 结构上做不到任意命令观测。\
             这是自洽性要求，不是配置项。可用：{}",
            crate::PROBE_SPEC_VERSION,
            WHITELIST.iter().map(|d| d.id).collect::<Vec<_>>().join(", ")
        )),
    }
}

/// 白名单自报（给 `warrantd probes` 与账本条目用）。
pub fn whitelist_json() -> Value {
    Value::Array(
        WHITELIST
            .iter()
            .map(|d| {
                obj(vec![
                    ("id", s(d.id)),
                    ("tier", s(d.tier)),
                    ("tier_hint", s(d.tier_hint)),
                    ("read_only", Value::Bool(d.read_only)),
                    ("writes", s(d.writes)),
                    ("desc", s(d.desc)),
                ])
            })
            .collect::<Vec<_>>(),
    )
}

/// 一次「世界扫描」：按白名单取哈希集（供快照差分用）。
///
/// 与 [`run`] 的区别：这里只做 `fs.hash` 这一类**只读**观测，且结果直接是
/// `path -> sha256`，供 [`crate::snapshot::diff`] 使用。
pub fn scan_hashes(root: &Path, rels: &[String]) -> Result<std::collections::BTreeMap<String, String>, String> {
    use sha2::{Digest, Sha256};
    let mut out = std::collections::BTreeMap::new();
    let mut budget = FINGERPRINT_MAX_ENTRIES;
    for rel in rels {
        let p = abs(root, rel);
        // 目录 ⇒ 结构指纹（C0）。这一条是「洞①：命令副作用」的落点：
        // npm install / cargo build 改的往往是 node_modules / target，逐个读内容太贵，
        // 但只 stat 一遍很便宜 —— 于是「命令改了东西」从看不见变成看得见。
        if p.is_dir() {
            let (fp, _trunc) = fingerprint_of(&p, &mut budget);
            out.insert(format!("dir:{rel}"), fp);
            continue;
        }
        match std::fs::read(&p) {
            Ok(bytes) => {
                let hex: String = Sha256::digest(&bytes).iter().map(|b| format!("{:02x}", b)).collect();
                out.insert(rel.clone(), format!("sha256:{hex}"));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // 文件不存在 = 世界的真实状态，不是错误。差分据此判 removed。
            }
            Err(e) => return Err(format!("read {}: {e}", p.display())),
        }
    }
    // [SELF-OBSERVE-2026-10-27] 观测面**自己的配置**也在观测面里。
    // ignore 文件的哈希进快照 ⇒ 它一改就走正常的世界变更流程 ⇒ 自动进账本。
    // 这条是为了堵住「agent 往 ignore 里加一行就把自己的改动藏起来」这个洞。
    let ign = root.join(crate::LEDGER_DIR).join("ignore");
    if let Ok(bytes) = std::fs::read(&ign) {
        let hex: String = Sha256::digest(&bytes).iter().map(|b| format!("{:02x}", b)).collect();
        out.insert("special:ignore".to_string(), format!("sha256:{hex}"));
    }
    Ok(out)
}

/// 采集 mtime（纳秒）。**只对文件采集** —— 目录的结构指纹里已含 newest，不必重复。
///
/// [TOUCH-2026-10-27] 这一路数据专门用来发现「**改了又改回来**」：
/// 内容哈希会显示"什么都没变"，而 mtime 记得"有进程碰过它"。
pub fn mtimes_of(root: &Path, rels: &[String]) -> std::collections::BTreeMap<String, i64> {
    let mut out = std::collections::BTreeMap::new();
    for rel in rels {
        let p = abs(root, rel);
        if p.is_dir() {
            continue;
        }
        if let Some(ns) = mtime_ns(&p) {
            out.insert(rel.clone(), ns);
        }
    }
    out
}

fn mtime_ns(p: &Path) -> Option<i64> {
    let md = std::fs::metadata(p).ok()?;
    let t = md.modified().ok()?;
    let d = t.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(d.as_nanos() as i64)
}

/// 证据串里的哈希前缀校验（`sha256:<64 hex>`）。
pub fn is_hash(x: &str) -> bool {
    x.strip_prefix("sha256:")
        .map(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false)
}

/// 供快照落盘：`{path: hash}` → Value（键排序由 canon 保证）。
pub fn hash_map_json(m: &std::collections::BTreeMap<String, String>) -> Value {
    Value::Object(m.iter().map(|(k, v)| (k.clone(), s(v))).collect())
}

/// 证据清单 → Value 数组（canon 只认字符串）。
pub fn evidence_json(items: &[String]) -> Value {
    arr(items.iter().map(|x| s(x)).collect())
}

/// 计算文件内容哈希（供快照模块复用，避免两处 sha256 逻辑漂移）。
pub fn sha256_file(p: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(p).ok()?;
    Some(format!(
        "sha256:{}",
        Sha256::digest(&bytes).iter().map(|b| format!("{:02x}", b)).collect::<String>()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_is_closed_and_self_describing() {
        // 封闭性：不在表里 ⇒ run 必然拒绝
        let e = run("shell.exec", Path::new("."), "rm -rf /", false).unwrap_err();
        assert!(e.contains("不在观测白名单"), "{e}");
        // 每条都要有 id/tier/desc，且 tier 与申报一致（P5 要求逐字相等）
        for d in WHITELIST {
            assert!(!d.id.is_empty() && !d.desc.is_empty());
            assert_eq!(d.tier, crate::DECLARED_TIER, "{} 的申报档必须等于 capability 申报值", d.id);
        }
    }

    #[test]
    fn only_build_test_has_side_effects() {
        let writers: Vec<&str> = WHITELIST.iter().filter(|d| !d.read_only).map(|d| d.id).collect();
        assert_eq!(writers, vec!["build.test"], "只有 build.test 允许写盘；新增写盘原语必须改这条断言");
        assert!(!decl("build.test").unwrap().writes.is_empty(), "有副作用就必须申报写什么");
    }

    #[test]
    fn side_effect_probe_refuses_without_flag() {
        let e = run_build_test(Path::new("."), "cargo --version", false).unwrap_err();
        assert!(e.contains("--allow-side-effects"), "{e}");
    }

    #[test]
    fn unknown_probe_name_is_refused_not_guessed() {
        let e = run("fs.hash2", Path::new("."), "x", false).unwrap_err();
        assert!(e.contains("不在观测白名单"), "{e}");
    }

    // ---------- 洞①：命令副作用（目录指纹 + 预期副作用清单）----------

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("warrantd-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn dir_fingerprint_is_stable_and_detects_change() {
        let d = tmpdir("fp");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("a.txt"), b"1").unwrap();
        std::fs::write(d.join("sub/b.txt"), b"22").unwrap();

        let mut b1 = FINGERPRINT_MAX_ENTRIES;
        let (fp1, t1) = fingerprint_of(&d, &mut b1);
        let mut b2 = FINGERPRINT_MAX_ENTRIES;
        let (fp2, _) = fingerprint_of(&d, &mut b2);
        assert_eq!(fp1, fp2, "同一目录两次扫描必须得到同一指纹");
        assert!(!t1);
        assert!(fp1.contains("entries=2"), "{fp1}");

        // 新增一个文件 ⇒ 指纹必须变（这是「命令往目录里写了东西」的最小复现）
        std::fs::write(d.join("c.txt"), b"333").unwrap();
        let mut b3 = FINGERPRINT_MAX_ENTRIES;
        let (fp3, _) = fingerprint_of(&d, &mut b3);
        assert_ne!(fp1, fp3, "目录里多了文件，指纹必须变");
        assert!(fp3.contains("entries=3"), "{fp3}");

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dir_fingerprint_declares_truncation_instead_of_hiding_it() {
        let d = tmpdir("fp-trunc");
        for i in 0..5 {
            std::fs::write(d.join(format!("f{i}.txt")), b"x").unwrap();
        }
        let mut budget = 1usize; // 预算只够 1 条 ⇒ 必然截断
        let (fp, truncated) = fingerprint_of(&d, &mut budget);
        assert!(truncated, "预算不够时必须报告截断");
        assert!(fp.contains("truncated"), "截断必须写在指纹里，不能隐藏：{fp}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn scan_routes_directories_to_fingerprint_and_files_to_hash() {
        let d = tmpdir("scan");
        std::fs::create_dir_all(d.join("big")).unwrap();
        std::fs::write(d.join("big/x.bin"), b"12").unwrap();
        std::fs::write(d.join("a.txt"), b"hello").unwrap();
        let m = scan_hashes(&d, &["big".to_string(), "a.txt".to_string()]).unwrap();
        assert!(m.contains_key("dir:big"), "目录必须走指纹分支：{m:?}");
        assert!(m["dir:big"].contains("entries=1"), "{:?}", m["dir:big"]);
        assert!(m["a.txt"].starts_with("sha256:"), "文件必须走内容哈希");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// [NET-2026-10-28] 外部对端判定：**回环/通配必须排除，否则"有一条连接"永远报变化**。
    #[test]
    fn external_peer_filter_excludes_loopback_and_wildcards() {
        for local in ["127.0.0.1:5000", "0.0.0.0:0", "[::]:443", "[::1]:8080", "localhost:3000"] {
            assert!(!is_external_peer(local), "本机地址不该算外部对端：{local}");
        }
        for ext in ["93.184.216.34:443", "[2606:2800:220:1::1]:443", "140.82.121.4:22"] {
            assert!(is_external_peer(ext), "外部地址必须被算进来：{ext}");
        }
    }

    /// 两条新原语都必须在白名单里、都只读（`only_build_test_has_side_effects` 也依赖这点）。
    #[test]
    fn network_and_remote_probes_are_read_only() {
        for id in ["net.conns", "vcs.remote"] {
            let d = decl(id).unwrap_or_else(|| panic!("{id} 必须在白名单里"));
            assert!(d.read_only, "{id} 必须只读");
            assert!(d.writes.is_empty(), "{id} 不该申报写盘");
        }
    }

    #[test]
    fn ignore_matches_prefix_not_arbitrary_substring() {
        let rules = vec!["target".to_string(), "node_modules".to_string()];
        assert!(is_ignored("target/", &rules));
        assert!(is_ignored("target/debug/x", &rules));
        assert!(is_ignored("dir:target", &rules), "目录项（dir: 前缀）也要匹配");
        assert!(!is_ignored("targetfoo/a", &rules), "前缀不能当成子串匹配");
        assert!(!is_ignored("src/target.rs", &rules));
    }

    /// 自洽性钉子：**ignore 文件自己也在观测面里**。
    /// 没有这条，agent 只要往 ignore 里加一行就能把改动藏起来。
    #[test]
    fn ignore_file_is_itself_observed() {
        let d = tmpdir("self-obs");
        assert!(!scan_hashes(&d, &[]).unwrap().contains_key("special:ignore"));
        std::fs::create_dir_all(d.join(crate::LEDGER_DIR)).unwrap();
        std::fs::write(d.join(crate::LEDGER_DIR).join("ignore"), "target\n").unwrap();
        let m = scan_hashes(&d, &[]).unwrap();
        assert!(
            m.contains_key("special:ignore"),
            "ignore 文件必须自动纳入观测面：{m:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
