//! warrantd CLI —— 常驻观测者与账本。
//!
//! ```text
//! warrantd probes                       # 打印观测白名单（自报「我能怎么看世界」）
//! warrantd status [--repo P]            # 自报：观测面 / 账本位置 / 水位 / 哪些**看不见**
//! warrantd once   [--repo P] [--watch a,b] [--limit N]
//! warrantd daemon [--repo P] [--interval 30] [--max-iters N]
//! warrantd claim  [--repo P] --actor X --path P [--expect sha256:...]
//! warrantd check  <claim-id> [--repo P]
//! warrantd unreported [--repo P]        # 切片②：变了但没人申报
//! warrantd since  <offset> [--repo P]   # 切片③：你不在的时候变了这些
//! warrantd verify [--repo P]            # 链 + 签名自检（第三方可复算）
//! ```
//!
//! **`status` 是第一个该被调用的命令**：一个观测者如果不先说清自己「看不见什么」，
//! 它说的「没发生」就不可信 —— 这正是信使要反对的那种黑盒。

use std::path::Path;
use std::time::Duration;

use warrant::json::Value;

use warrantd::probe;
use warrantd::util::{arr, obj, s, to_line};
use warrantd::{
    admit, mcp, proxy, root, slices, snapshot, store, ui, LEDGER_DIR, PROBE_SPEC_VERSION,
};

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        usage();
        std::process::exit(2);
    }
    let cmd = argv[0].as_str();
    let rest = &argv[1..];
    let r = match cmd {
        "probes" => {
            println!("{}", to_line(&probe::whitelist_json()));
            Ok(())
        }
        "status" => cmd_status(rest),
        "once" => cmd_once(rest),
        "daemon" => cmd_daemon(rest),
        "claim" => cmd_claim(rest),
        "check" => cmd_check(rest),
        "unreported" => cmd_unreported(rest),
        "since" => cmd_since(rest),
        "verify" => cmd_verify(rest),
        "seal" => cmd_seal(rest),
        "proxy" => cmd_proxy(rest),
        "mcp" => cmd_mcp(rest),
        "open" => cmd_open(rest),
        "ui" => cmd_ui(rest),
        "shortcut" => cmd_shortcut(rest),
        "probe" => cmd_probe(rest),
        "admit" => cmd_admit(rest),
        "wrap" => cmd_wrap(rest),
        "-h" | "--help" | "help" => {
            usage();
            Ok(())
        }
        other => Err(format!("未知子命令 `{other}`（warrantd help 看用法）")),
    };
    if let Err(e) = r {
        eprintln!("warrantd: {e}");
        std::process::exit(1);
    }
}

fn usage() {
    eprintln!(
        "warrantd —— 常驻观测者与账本（独立于任何智能体）\n\
         \n\
         用法：\n\
         \x20 warrantd probes                  打印观测白名单\n\
         \x20 warrantd probe   <原语> [参数]   手工跑一条观测（如 probe net.conns）\n\
 \x20 warrantd admit   [--repo P]        准入自检：你现在有多可观测（L0~L3）\n\
 \x20 warrantd wrap    [--file 配置]    只打印：MCP 配置该改成什么样（不碰文件）\n\
         \x20 warrantd status  [--repo P]      自报观测面 / 账本位置 / 水位 / 盲区\n\
         \x20 warrantd once    [--repo P] [--watch a,b] [--limit N]\n\
         \x20 warrantd daemon  [--repo P] [--interval 30] [--max-iters N]\n\
         \x20 warrantd claim   [--repo P] --actor X --path P [--expect sha256:...]\n\
         \x20 warrantd check   <claim-id> [--repo P]\n\
         \x20 warrantd unreported [--repo P]   切片②：变了但没人申报\n\
         \x20 warrantd since   <offset> [--repo P]  切片③：你不在的时候变了这些\n\
         \x20 warrantd verify  [--repo P]      链 + 签名自检\n\
 \x20 warrantd open    [--repo P] [--interval 30]   手动打开：人读输出，关窗口即停\n\
 \x20 warrantd ui      [--repo P] [--port N]       黑色信封面板（仅本机）\n\
 \x20 warrantd shortcut [--repo P] [--out 目录]    生成双击就能打开的桌面快捷方式\n\
 \x20 warrantd proxy   [--repo P] [--name N] -- <server 命令>\n\
 \x20                                    在 host 与 MCP server 之间旁观并记账\n\
         \n\
         `--repo` 省略时用当前目录。账本固定落在 <repo>/{LEDGER_DIR}/entries.jsonl（项目内，不跟应用走）。"
    );
}

fn flag(rest: &[String], name: &str) -> Option<String> {
    rest.iter()
        .position(|a| a == name)
        .and_then(|i| rest.get(i + 1).cloned())
}

/// 项目根 —— **走防御式解析**（`root.rs`）：宁可报错，也不把账本写到错的地方。
fn repo_of(rest: &[String]) -> Result<root::Resolution, String> {
    // `--` 之后是「被代理的 server 命令」，里面可能也带 `--repo` ⇒ 只扫前半段
    let head: &[String] = match rest.iter().position(|a| a == "--") {
        Some(i) => &rest[..i],
        None => rest,
    };
    root::resolve(flag(head, "--repo").as_deref())
}

/// 观测面：`--watch` > `.warrant/watch.list` > `git ls-files`（限制 `--limit`，默认 500）。
///
/// **为什么给 git 兜底**：开箱即用。但必须如实说明——`git ls-files` 只看**已跟踪**文件，
/// 未跟踪/被忽略的文件不在观测面内（这就是一条必须写进 status 的盲区）。
fn watch_list(repo: &Path, rest: &[String]) -> (Vec<String>, &'static str) {
    if let Some(w) = flag(rest, "--watch") {
        return (probe::parse_paths(&w), "--watch");
    }
    let p = repo.join(LEDGER_DIR).join("watch.list");
    if let Ok(text) = std::fs::read_to_string(&p) {
        let v: Vec<String> = text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        return (v, "属于项目的 .warrant/watch.list");
    }
    let limit: usize = flag(rest, "--limit")
        .and_then(|x| x.parse().ok())
        .unwrap_or(500);
    let mut gitcmd = std::process::Command::new("git");
    gitcmd.args(["ls-files"]).current_dir(repo);
    warrantd::util::hide_console(&mut gitcmd);
    match gitcmd.output() {
        Ok(o) if o.status.success() => {
            let mut v: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .lines()
                .take(limit)
                .map(|x| x.to_string())
                .collect();
            v.sort();
            (v, "git ls-files（仅已跟踪文件）")
        }
        _ => (
            Vec::new(),
            "空（既无 --watch 也无 watch.list，且不是 git 仓库）",
        ),
    }
}

fn cmd_status(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let repo_source = res.source;
    let repo = res.root;
    let st = store::Store::open(&repo)?;
    let (watch, source) = watch_list(&repo, rest);
    let snap = snapshot::load(&repo);
    let entries = st.entries();
    let unreported = slices::unreported(entries);
    let v = obj(vec![
        ("daemon", s("warrantd")),
        // 「我在看哪个项目」必须排在最前 —— 观测者的第一条义务。
        // 来源也要报（--repo / 环境变量 / cwd），否则「记错地方」这件事查不出来。
        ("repo", s(&repo.display().to_string())),
        ("repo_source", s(repo_source)),
        ("probe_spec", s(PROBE_SPEC_VERSION)),
        ("channel", s(warrantd::CHANNEL)),
        ("declared_tier", s(warrantd::DECLARED_TIER)),
        ("signer", s(warrantd::SIGNER_ID)),
        (
            "ledger",
            s(&st.dir().join("entries.jsonl").display().to_string()),
        ),
        // offset 用**跨卷单调**的逻辑序号：封卷后不回退，since 才不会重复
        ("offset", Value::Int(st.logical_offset() as i64)),
        ("grant", s(st.grant_id())),
        ("chain_ok", Value::Bool(st.verify().is_empty())),
        // 「现在有别人在写吗」——多主体场景的第一条诊断线索
        ("lock_free", Value::Bool(store::lock_is_free(&repo))),
        // ---- 观测面（**能看见什么**）----
        ("watch_source", s(source)),
        ("watching", Value::Int(watch.len() as i64)),
        // 观测面**分层**：内容级（逐文件哈希）vs 结构级（目录指纹）。
        // 分开报，是因为它们的能力差一个档：目录指纹只证明「变了」，不证明「变成什么」。
        (
            "watching_files",
            Value::Int(
                watch
                    .iter()
                    .filter(|r| !repo.join(r.as_str()).is_dir())
                    .count() as i64,
            ),
        ),
        (
            "watching_dirs_struct_level",
            Value::Int(
                watch
                    .iter()
                    .filter(|r| repo.join(r.as_str()).is_dir())
                    .count() as i64,
            ),
        ),
        (
            "ignore_rules",
            Value::Int(probe::ignore_rules(&repo).len() as i64),
        ),
        (
            "snapshot_at",
            s(&snap.as_ref().map(|x| x.at.clone()).unwrap_or_default()),
        ),
        // ---- 盲区（**看不见什么 —— 这一栏比上一栏重要**）----
        (
            "blind_spots",
            arr(vec![
                s("网络行为（除了连接表条数）"),
                s("内存/寄存器/硬件状态"),
                s("远端仓库与他人机器"),
                s("未出现在观测面里的路径（含未跟踪/被忽略文件）"),
                s("两次巡边之间发生又复原的变化（快照是离散采样）"),
            ]),
        ),
        ("unreported_batches", Value::Int(unreported.len() as i64)),
        ("whitelist", probe::whitelist_json()),
    ]);
    println!("{}", to_line(&v));
    Ok(())
}

fn cmd_once(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let repo = res.root;
    let (watch, _src) = watch_list(&repo, rest);
    if watch.is_empty() {
        return Err("观测面为空：没有 --watch、没有 .warrant/watch.list，也不是 git 仓库".into());
    }
    println!("{}", warrantd::sweep::sweep(&repo, &watch)?.to_line());
    Ok(())
}

fn cmd_daemon(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let repo = res.root;
    let (watch, src) = watch_list(&repo, rest);
    if watch.is_empty() {
        return Err("观测面为空：没有 --watch、没有 .warrant/watch.list，也不是 git 仓库".into());
    }
    let interval: u64 = flag(rest, "--interval")
        .and_then(|x| x.parse().ok())
        .unwrap_or(30);
    let max_iters: Option<u64> = flag(rest, "--max-iters").and_then(|x| x.parse().ok());
    println!(
        "{}",
        to_line(&obj(vec![
            ("daemon", s("warrantd")),
            ("repo", s(&repo.display().to_string())),
            ("watching", Value::Int(watch.len() as i64)),
            ("watch_source", s(src)),
            ("interval_secs", Value::Int(interval as i64)),
            (
                "note",
                s("常驻是为了「观测在场」：宿主不调用也照看，滞后窗口 = interval")
            ),
        ]))
    );
    // [WATCH-2026-10-29] 有 watcher 就等事件（延迟从 interval 降到毫秒级）；
    // 起不来就退回纯定时 —— 宁可慢，不可假：少盯一个不会变盲区，只是延迟回到采样级。
    let mut w = warrantd::watch::Watcher::start(&repo, &watch).ok();
    let mut i = 0u64;
    let mut first = true;
    loop {
        // 首轮立刻扫；之后**先等事件**（把这一波累计起来）再扫 —— [JITTER-2026-10-29]
        if !first {
            match &mut w {
                Some(w) => {
                    w.wait(Duration::from_secs(interval));
                }
                None => std::thread::sleep(Duration::from_secs(interval)),
            }
        }
        first = false;
        // **[JITTER-2026-10-29] 事件先到、写入后到。**
        // 真机实测：收到事件后立刻扫，会扫到「还没写完」的旧内容 ⇒ changes=0，
        // 而计数已被这一轮 take 走 ⇒ 计数白丢。给 100ms 让写落盘。
        if w.is_some() {
            std::thread::sleep(Duration::from_millis(100));
        }
        let counts = w.as_ref().map(|x| x.counts_snapshot()).unwrap_or_default();
        match warrantd::sweep::sweep_with_events(&repo, &watch, &counts) {
            Ok(o) => {
                // 只有**真的写了一条世界变更**才清空计数 —— 否则留着等下一轮（避免白丢）
                if o.changes > 0 {
                    if let Some(w) = w.as_mut() {
                        w.clear_counts();
                    }
                }
                println!("{}", o.to_line());
            }
            Err(e) => eprintln!("warrantd: 本轮巡边失败（不影响下一轮）：{e}"),
        }
        i += 1;
        if let Some(m) = max_iters {
            if i >= m {
                break;
            }
        }
    }
    Ok(())
}

fn cmd_claim(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let repo = res.root;
    let actor = flag(rest, "--actor").ok_or("缺 --actor（谁在申报，如 agent:claude-code）")?;
    let path = flag(rest, "--path").ok_or("缺 --path（申报改动的相对路径）")?;
    let expect = match flag(rest, "--expect") {
        Some(h) => h,
        None => {
            // 便利：不给 expect 就取**当前**内容哈希。诚实提示：这不是"我改成了什么"，
            // 而是"现在是什么" —— 用它申报等于自己给自己降难度。
            probe::sha256_file(&repo.join(&path))
                .ok_or_else(|| format!("读不到 {path}，且未给 --expect"))?
        }
    };
    let mut st = store::Store::open(&repo)?;
    let id = st.append_agent_claim(&actor, &path, &expect)?;
    println!(
        "{}",
        to_line(&obj(vec![
            ("claim", s(&id)),
            ("actor", s(&actor)),
            ("path", s(&path)),
            ("expect", s(&expect)),
            ("offset", Value::Int(st.logical_offset() as i64)),
        ]))
    );
    Ok(())
}

fn cmd_check(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let repo = res.root;
    let id = rest
        .iter()
        .find(|a| !a.starts_with("--") && **a != repo.display().to_string())
        .ok_or("缺 <claim-id>")?;
    let st = store::Store::open(&repo)?;
    let v = slices::check_claim(st.entries(), id).ok_or_else(|| format!("账本里没有这条：{id}"))?;
    println!(
        "{}",
        to_line(&obj(vec![
            ("claim", s(&v.claim_id)),
            ("state", s(v.state)),
            ("label", s(&v.label)),
            ("d_eff", Value::Int(v.d_eff as i64)),
            ("axes", arr(v.axes.iter().map(|a| s(a)).collect())),
            ("observations", Value::Int(v.observations as i64)),
        ]))
    );
    Ok(())
}

/// 只读当前卷（`unreported --current` 用）。
fn st_entries_only(repo: &Path) -> Result<Vec<warrant::ledger::Entry>, String> {
    Ok(store::Store::open(repo)?.entries().to_vec())
}

fn cmd_unreported(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let repo = res.root;
    let st = store::Store::open(&repo)?;
    // 预期副作用（`target/` 每次编译都会变）：按 `.warrant/ignore` 过滤，
    // 但**必须报出被排除了多少条** —— 否则「过滤」就成了新的黑盒。
    let rules = probe::ignore_rules(&repo);
    // [SEAL-2026-10-29] **默认跨卷**。
    //
    // 为什么不是「只看当前卷」：未申报的变更不因为被封卷就变成已申报 ——
    // 只看当前卷会让历史未申报**静默消失**，那等于「封卷洗白历史」。
    // 代价：卷很多时要多读几遍文件；`--current` 可退回只看当前卷。
    let everything = if rest.iter().any(|a| a == "--current") {
        let _ = st;
        st_entries_only(&repo)?
    } else {
        store::all_entries(&repo)?
    };
    let items = slices::unreported(&everything);
    let mut rows = Vec::new();
    let mut excluded = 0i64;
    for u in &items {
        for c in &u.changes {
            if probe::is_ignored(&c.path, &rules) {
                excluded += 1;
                continue;
            }
            rows.push(obj(vec![
                ("world_claim", s(&u.world_claim)),
                ("window_from", s(&u.window_from)),
                ("window_to", s(&u.window_to)),
                ("path", s(&c.path)),
                ("kind", s(c.kind.as_str())),
            ]));
        }
    }
    println!(
        "{}",
        to_line(&obj(vec![
            ("unreported", Value::Int(rows.len() as i64)),
            ("excluded_by_ignore", Value::Int(excluded)),
            ("ignore_rules", Value::Int(rules.len() as i64)),
            (
                "note",
                s("变了但没有任何 agent 申报过 —— 这是负事实，不是错误")
            ),
            ("items", Value::Array(rows)),
        ]))
    );
    Ok(())
}

fn cmd_since(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let repo = res.root;
    let off: usize = rest
        .iter()
        .find(|a| a.parse::<usize>().is_ok())
        .ok_or("缺 <offset>（上次读到的条数；不知道就给 0）")?
        .parse()
        .map_err(|e| format!("offset: {e}"))?;
    // [SEAL-2026-10-29] `off` 是**跨卷逻辑序号**，所以必须用 all_entries 合并后再切 ——
    // 只看当前卷会切错（封卷后当前卷很短，off 却很大 ⇒ 直接越界返回空）。
    let all = store::all_entries(&repo)?;
    let total = all.len();
    let from = off.min(total);
    // 仅用于确认账本可打开/报告当前卷位置；切片本身走合并后的列表
    let _st = store::Store::open(&repo)?;
    let rep = slices::since(&all, from);
    let items: Vec<Value> = rep
        .items
        .iter()
        .map(|i| {
            obj(vec![
                ("seq", Value::Int(i.seq)),
                ("id", s(&i.id)),
                ("kind", s(&i.kind)),
                ("type", s(&i.type_)),
                ("actor", s(&i.actor)),
            ])
        })
        .collect();
    let unreported: Vec<Value> = rep
        .unreported
        .iter()
        .map(|c| obj(vec![("path", s(&c.path)), ("kind", s(c.kind.as_str()))]))
        .collect();
    println!(
        "{}",
        to_line(&obj(vec![
            ("from", Value::Int(rep.from as i64)),
            ("to", Value::Int(rep.to as i64)),
            ("new_entries", Value::Int(rep.items.len() as i64)),
            ("world_batches", Value::Int(rep.world.len() as i64)),
            ("unreported", Value::Array(unreported)),
            ("items", Value::Array(items)),
        ]))
    );
    Ok(())
}

fn cmd_verify(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let repo = res.root;
    // `--all`：连同 volumes/ 各卷一起验，并核对卷间谱系（封过卷就必须用它）
    if rest.iter().any(|a| a == "--all") {
        let (list, errs) = store::verify_all(&repo)?;
        println!(
            "{}",
            to_line(&obj(vec![
                (
                    "volumes",
                    arr(list
                        .iter()
                        .map(|(n, c)| obj(vec![
                            ("name", s(n)),
                            ("entries", Value::Int(*c as i64)),
                        ]))
                        .collect())
                ),
                ("ok", Value::Bool(errs.is_empty())),
                ("errors", arr(errs.iter().map(|e| s(e)).collect())),
                (
                    "note",
                    s("封卷后谱系靠 parents 连接：每卷独立可验，第三方可各自复算，也可顺着 parents 一路回溯")
                ),
            ]))
        );
        return if errs.is_empty() {
            Ok(())
        } else {
            Err("账本自检未通过（--all）".into())
        };
    }
    let st = store::Store::open(&repo)?;
    let errs = st.verify();
    println!(
        "{}",
        to_line(&obj(vec![
            (
                "ledger",
                s(&st.dir().join("entries.jsonl").display().to_string())
            ),
            ("entries", Value::Int(st.offset() as i64)),
            ("ok", Value::Bool(errs.is_empty())),
            ("errors", arr(errs.iter().map(|e| s(e)).collect())),
            (
                "note",
                s("第三方拿到 entries.jsonl 可用同一判据自行复算，不必信 warrantd 的话")
            ),
        ]))
    );
    if errs.is_empty() {
        Ok(())
    } else {
        Err("账本自检未通过".into())
    }
}

/// `warrantd seal` —— 封卷。
///
/// **[SEAL-2026-10-29]** 账本没有上界是已知缺口。封卷**不是截断**：
/// 旧卷原样保留（仍可独立验签），新卷首条 grant 的 `parents` 指向旧卷 head，谱系不断。
fn cmd_seal(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let repo = res.root;
    let mut st = store::Store::open(&repo)?;
    let before = st.offset();
    if before < 2 {
        return Err(format!("账本只有 {before} 条，不需要封卷"));
    }
    let id = st.seal()?;
    println!(
        "{}",
        to_line(&obj(vec![
            ("sealed_entries", Value::Int(before as i64)),
            ("seal_grant", s(&id)),
            ("new_offset", Value::Int(st.logical_offset() as i64)),
            (
                "volumes_dir",
                s(&repo.join(LEDGER_DIR).join(store::VOLUMES).display().to_string())
            ),
            (
                "note",
                s("旧卷原样保留、仍可独立验签；新卷首条 grant 的 parents 指向旧卷 head —— 谱系不断。用 warrantd verify --all 一次验完")
            ),
        ]))
    );
    Ok(())
}

/// `warrantd proxy` —— 站在 host 与真 MCP server 之间旁观并记账（洞②）。
///
/// ⚠️ **stdout 是 MCP 协议通道**：本函数除协议帧外**绝不能往 stdout 写任何东西**
/// （诊断一律走 stderr），否则 host 会收到无法解析的垃圾，表现为「工具突然坏了」。
fn cmd_proxy(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let repo = res.root;
    let name = flag(rest, "--name").unwrap_or_else(|| "mcp".to_string());
    let i = rest.iter().position(|a| a == "--").ok_or(
        "用法：warrantd proxy --repo <项目> [--name <server 名>] -- <server 命令> [args...]",
    )?;
    let cmd: Vec<String> = rest[i + 1..].to_vec();
    if cmd.is_empty() {
        return Err(
            "`--` 之后要给 MCP server 的启动命令（例如 `-- python kit/lceda/mcp_server.py`）"
                .into(),
        );
    }
    eprintln!(
        "warrantd proxy: 代理 `{}`（server 名 `{name}`）；账本 {}",
        cmd.join(" "),
        repo.join(LEDGER_DIR).display()
    );
    proxy::run(&cmd, &repo, &name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--` 之后是**被代理的 server 命令**，里面完全可能有它自己的 `--repo`。
    /// 我们不能把它误当成"给我自己的参数"，否则会去解析错的项目、甚至报"磁盘根"。
    #[test]
    fn repo_flag_after_double_dash_is_not_swallowed() {
        let rest: Vec<String> = [
            "--repo",
            "/tmp/proj",
            "--",
            "myserver",
            "--repo",
            "/somewhere/else",
        ]
        .iter()
        .map(|x| x.to_string())
        .collect();
        let head: &[String] = match rest.iter().position(|a| a == "--") {
            Some(i) => &rest[..i],
            None => &rest,
        };
        assert_eq!(
            flag(head, "--repo"),
            Some("/tmp/proj".to_string()),
            "只应认 `--` 之前那个 --repo"
        );
    }

    /// **[WRAP-IDEMPOTENT-2026-10-28] 幂等是真机抓出来的 bug**：
    /// 第一版判据是 `command == "warrantd"`，但我们写进去的是**完整路径**，
    /// 于是反复跑会套成 `warrantd proxy -- warrantd proxy -- …`。
    #[test]
    fn wrap_is_idempotent_and_keeps_original_command() {
        let mut v = serde_json::json!({
            "mcpServers": {
                "lceda": {"command": "python", "args": ["kit/lceda/mcp_server.py"]},
                "fs": {"command": "npx", "args": ["-y", "srv"]}
            }
        });
        assert_eq!(
            wrap_value(&mut v, "C:/x/warrantd.exe", "C:/proj"),
            2,
            "两个都该包"
        );
        let lceda = &v["mcpServers"]["lceda"];
        assert_eq!(lceda["args"][0], "proxy");
        assert!(
            lceda["args"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a == "python"),
            "原命令必须保留"
        );
        assert!(
            lceda["args"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a == "kit/lceda/mcp_server.py"),
            "原参数必须保留"
        );

        // 再跑一次 ⇒ 一个都不该改（幂等）
        assert_eq!(
            wrap_value(&mut v, "C:/x/warrantd.exe", "C:/proj"),
            0,
            "第二次必须 0 改动"
        );
    }

    /// command 被改成别名/纯名也算包过（双保险那条：args 首项 proxy）
    #[test]
    fn already_wrapped_recognizes_path_and_alias() {
        let mut m = serde_json::Map::new();
        m.insert("command".into(), serde_json::json!("C:/x/warrantd.exe"));
        assert!(already_wrapped(&m));
        let mut m2 = serde_json::Map::new();
        m2.insert("command".into(), serde_json::json!("mytool"));
        m2.insert("args".into(), serde_json::json!(["proxy", "--name", "x"]));
        assert!(already_wrapped(&m2), "args 首项是 proxy 也算包过");
        let mut m3 = serde_json::Map::new();
        m3.insert("command".into(), serde_json::json!("python"));
        assert!(!already_wrapped(&m3));
    }

    #[test]
    fn no_double_dash_scans_everything() {
        let rest: Vec<String> = ["--repo", "/tmp/proj"]
            .iter()
            .map(|x| x.to_string())
            .collect();
        assert_eq!(flag(&rest, "--repo"), Some("/tmp/proj".to_string()));
    }
}

/// 自动找常见的 MCP 配置文件（找不到就返回 `None`，**不猜**）。
fn autodetect_mcp_config() -> Option<std::path::PathBuf> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()?;
    let home = std::path::PathBuf::from(home);
    // [CLIPPY-2026-10-30] 用 `find` 代替「for + 提前 return」（clippy: manual_find），语义一致
    [
        home.join(".claude.json"),
        home.join(".cursor").join("mcp.json"),
    ]
    .into_iter()
    .find(|p| p.is_file())
}

/// `warrantd wrap` —— **只打印**「你的 MCP 配置该改成什么样」，不碰任何文件。
///
/// # 它做什么
///
/// 把每个 MCP server 的 `command`/`args` 包成 `warrantd proxy -- <原命令>`，
/// 使「AI 调用外部工具」这条路也经过信使 —— 也就是从 L2 升到 L3。
///
/// # 它为什么只打印
///
/// 改客户端配置是**侵入性**操作：改坏了那个 server 会直接连不上，而用户会以为是软件坏了。
/// 这件事**一次就够**，没必要为省 30 秒冒这个风险。所以只输出结果，用户自己粘。
///
/// 幂等：已经是 `warrantd` 的项会跳过，可以反复跑。
fn cmd_wrap(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let file = match flag(rest, "--file") {
        Some(f) => std::path::PathBuf::from(f),
        None => autodetect_mcp_config().ok_or(
            "没找到 MCP 配置文件（找过 ~/.claude.json 和 ~/.cursor/mcp.json）。用 --file <路径> 指定。",
        )?,
    };
    let text =
        std::fs::read_to_string(&file).map_err(|e| format!("读不了 {}：{e}", file.display()))?;
    let mut v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("{} 不是合法 JSON：{e}", file.display()))?;

    let exe = std::env::current_exe().map_err(|e| format!("取自身路径失败：{e}"))?;
    let exe = exe.display().to_string();
    let repo = res.root.display().to_string();

    let n = wrap_value(&mut v, &exe, &repo);

    println!(
        "// 下面是把「AI 调外部工具」也纳进观测面的改法（来自 {}）。",
        file.display()
    );
    println!("// 共 {n} 个 server 需要包一层；已经是 warrantd 的会跳过（可反复跑）。");
    println!("// 我只打印不写文件 —— 你自己复制替换，然后跑 `warrantd admit` 看是否到 L3。");
    println!();
    println!(
        "{}",
        serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
    );
    Ok(())
}

/// 已经包过 proxy 了吗？
///
/// ⚠️ **不能只判 `command == "warrantd"`**：我们写进去的是**完整路径**
/// （`C:\...\warrantd.exe`），所以真机上幂等当场失效 —— 反复跑会套成
/// `warrantd proxy -- warrantd proxy -- …`，越套越慢。这条是修那个 bug 的。
fn already_wrapped(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    if let Some(c) = obj.get("command").and_then(|c| c.as_str()) {
        let low = c.to_ascii_lowercase().replace('\\', "/");
        let name = low.rsplit('/').next().unwrap_or(&low);
        if name == "warrantd" || name == "warrantd.exe" {
            return true;
        }
    }
    // 双保险：args 第一个是 proxy 也算（哪怕 command 被用户改成了别名）
    matches!(
        obj.get("args")
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .and_then(|x| x.as_str()),
        Some("proxy")
    )
}

/// 把 `mcpServers` 里每一项包成 `warrantd proxy -- <原命令>`。返回改了几项。**幂等**。
fn wrap_value(v: &mut serde_json::Value, exe: &str, repo: &str) -> usize {
    let mut n = 0usize;
    let Some(servers) = v.get_mut("mcpServers").and_then(|s| s.as_object_mut()) else {
        return 0;
    };
    for (name, cfg) in servers.iter_mut() {
        let Some(obj) = cfg.as_object_mut() else {
            continue;
        };
        if already_wrapped(obj) {
            continue;
        }
        let cmd = obj
            .get("command")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        if cmd.is_empty() {
            continue;
        }
        let mut args: Vec<String> = obj
            .get("args")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let mut new_args = vec![
            "proxy".to_string(),
            "--repo".to_string(),
            repo.to_string(),
            "--name".to_string(),
            name.clone(),
            "--".to_string(),
            cmd,
        ];
        new_args.append(&mut args);
        obj.insert("command".into(), serde_json::json!(exe));
        obj.insert("args".into(), serde_json::json!(new_args));
        n += 1;
    }
    n
}

/// `warrantd admit` —— **准入自检**：你现在到底有多可观测。
///
/// 这是「按信使的规矩进入可观测世界」那把尺子：**不拦你**，只告诉你
/// 你现在的动作**能不能被看见**、离下一级差什么。
fn cmd_admit(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    println!("{}", admit::assess(&res.root).render());
    Ok(())
}

/// 抽出位置参数（跳过 `--flag` 与它的值）—— `probe` 需要"第一个位置参数是原语名"。
fn positional(rest: &[String]) -> Vec<String> {
    const WITH_VALUE: &[&str] = &[
        "--repo",
        "--name",
        "--port",
        "--interval",
        "--limit",
        "--watch",
        "--out",
        "--expect",
        "--actor",
        "--path",
        "--max-iters",
    ];
    let mut out = Vec::new();
    let mut skip = false;
    for a in rest {
        if skip {
            skip = false;
            continue;
        }
        if WITH_VALUE.contains(&a.as_str()) {
            skip = true;
            continue;
        }
        if a.starts_with("--") {
            continue;
        }
        out.push(a.clone());
    }
    out
}

/// `warrantd probe <原语> [参数]` —— 手工跑**一条**观测原语。
///
/// 为什么要这个入口：新原语如果没有命令能直接跑，就等于**加了没人用**
/// （本项目已被真机证过三次：`edit_file`、`subagent`、`engine_doctor`）。
/// 观测面里每多一条原语，都必须有一条能立刻验证它的路。
fn cmd_probe(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let pos = positional(rest);
    let id = pos
        .first()
        .ok_or("用法：warrantd probe <原语> [参数]（原语列表见 warrantd probes）")?;
    let arg = pos.get(1).map(|s| s.as_str()).unwrap_or("");
    let allow = rest.iter().any(|a| a == "--allow-side-effects");
    let ob = probe::run(id, &res.root, arg, allow)?;
    println!("原语：{}", ob.method);
    println!("档位：{}（真实上限 {}）", ob.tier, ob.tier_hint);
    println!("观测于：{}", ob.observed_at);
    println!("结果：{}", warrantd::util::to_line(&ob.result));
    println!("证据：");
    for e in &ob.evidence {
        println!("  · {e}");
    }
    if !ob.self_side_effects.is_empty() {
        println!("自身副作用（不计入世界变更）：{:?}", ob.self_side_effects);
    }
    Ok(())
}

/// `warrantd shortcut` —— 生成一个**双击就能打开**的 `.cmd`。
///
/// 为什么由程序自己生成，而不是让用户手写：**这是"别人也能用"的最后一道门槛**。
/// 双击桌面上的「信使」就打开面板，关掉窗口就停 —— 与 `[MANUAL-OPEN]` 的约定一致。
///
/// 默认放桌面（`%USERPROFILE%\Desktop`），`--out` 可改。
fn cmd_shortcut(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let out_dir = flag(rest, "--out")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(default_desktop);
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| format!("建不了目录 {}：{e}", out_dir.display()))?;
    let exe = std::env::current_exe().map_err(|e| format!("取自身路径失败：{e}"))?;

    // chcp 65001：否则中文项目路径在 cmd 里会变乱码
    let content = format!(
        "@echo off\r\nchcp 65001 >nul\r\n\"{}\" ui --repo \"{}\"\r\n",
        exe.display(),
        res.root.display()
    );
    let path = out_dir.join("信使.cmd");
    std::fs::write(&path, content).map_err(|e| format!("写 {} 失败：{e}", path.display()))?;

    println!("已生成：{}", path.display());
    println!("项目　：{}", res.root.display());
    println!();
    println!("双击它 = 打开信使面板（黑色信封）。关掉窗口 = 停止观测。");
    Ok(())
}

fn default_desktop() -> std::path::PathBuf {
    std::env::var("USERPROFILE")
        .map(|p| std::path::PathBuf::from(p).join("Desktop"))
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// `warrantd ui` —— 打开「黑色信封」面板（浏览器窗口，只监听本机）。
fn cmd_ui(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let port: u16 = flag(rest, "--port")
        .and_then(|x| x.parse().ok())
        .unwrap_or(0); // 0 = 让系统分配空闲端口
                       // --no-open：测试与远程场景用（不弹浏览器）
    let open_it = !rest.iter().any(|a| a == "--no-open");
    ui::serve(&res.root, port, open_it)
}

/// `warrantd open` —— **用户手动打开**（`[MANUAL-OPEN-2026-10-27]`）。
///
/// 用户裁决：**不要开机自启，手动打开即可**。所以这就是「打开」的全部含义：
/// 前台跑、人读输出、**关掉窗口就停止观测**。
///
/// 由此产生一条必须写在最前面的诚实边界：
/// **关着的时候世界照样在变，那段时间我看不见** —— 下次打开只能和上次快照比。
/// 这不是缺陷，是这个形态的代价；把它说清楚比假装「一直在看」重要得多。
fn cmd_open(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    let repo = res.root;
    let (watch, src) = watch_list(&repo, rest);
    if watch.is_empty() {
        return Err(
            "观测面为空，没什么可看。请建 .warrant/watch.list（一行一个路径或目录），或加 --watch a,b"
                .into(),
        );
    }
    let interval: u64 = flag(rest, "--interval")
        .and_then(|x| x.parse().ok())
        .unwrap_or(30);

    println!("══ 信使已打开 ══");
    println!("项目　：{}", repo.display());
    println!("观测面：{} 项（{}）", watch.len(), src);
    println!(
        "账本　：{}",
        repo.join(LEDGER_DIR).join("entries.jsonl").display()
    );
    println!();
    println!("关掉这个窗口 = 停止观测。");
    println!("也就是说：关着的时候世界照样在变，那段时间我看不见。");
    println!();
    println!("（按 Ctrl+C 退出）");
    println!();

    // [WATCH-2026-10-29] 同上：有事件就立刻扫，没有就等满 interval 再兜底扫一次
    let mut w = warrantd::watch::Watcher::start(&repo, &watch).ok();
    let mut first = true;
    loop {
        // 首轮立刻扫；之后**先等事件**（把这一波累计起来）再扫 —— [JITTER-2026-10-29]
        if !first {
            match &mut w {
                Some(w) => {
                    w.wait(Duration::from_secs(interval));
                }
                None => std::thread::sleep(Duration::from_secs(interval)),
            }
        }
        let is_first = first;
        first = false;
        // **[JITTER-2026-10-29] 事件先到、写入后到。**
        // 真机实测：收到事件后立刻扫，会扫到「还没写完」的旧内容 ⇒ changes=0，
        // 而计数已被这一轮 take 走 ⇒ 计数白丢。给 100ms 让写落盘。
        if w.is_some() {
            std::thread::sleep(Duration::from_millis(100));
        }
        let counts = w.as_ref().map(|x| x.counts_snapshot()).unwrap_or_default();
        match warrantd::sweep::sweep_with_events(&repo, &watch, &counts) {
            Ok(o) => {
                let hms: String = warrantd::util::now_rfc3339()
                    .chars()
                    .skip(11)
                    .take(8)
                    .collect();
                if is_first {
                    println!(
                        "[{hms}] 基线已建：{} 项（{src}）；此后有变化才提示",
                        o.scanned
                    );
                    first = false;
                } else if o.changes > 0 {
                    if let Some(w) = w.as_mut() {
                        w.clear_counts();
                    }
                    println!("[{hms}] {} 处变化，账本 {} 条", o.changes, o.offset);
                }
                // 没变化就不打印：安静是对的，刷屏会让人把它关掉
            }
            Err(e) => eprintln!("巡边失败（下一轮继续）：{e}"),
        }
    }
}

/// `warrantd mcp` —— 当 MCP server，让 agent 主动问信使。
///
/// ⚠️ **stdout 是 MCP 协议通道**：这里除了"启动就绪"这类诊断（走 stderr）外，
/// 绝不能往 stdout 写任何东西 —— 往 stdout 多一个字，host 就收到无法解析的垃圾。
fn cmd_mcp(rest: &[String]) -> Result<(), String> {
    let res = repo_of(rest)?;
    mcp::serve(&res.root)
}
