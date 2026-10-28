//! MCP server 薄壳 —— 让 agent **主动问信使**。
//!
//! # 它补的是哪一半
//!
//! | 形态 | 谁用 |
//! |---|---|
//! | `warrantd once/status/...` | 人敲命令 |
//! | `warrantd proxy` | 站在 host 与 MCP server 中间**看别人** |
//! | **`warrantd mcp`（本模块）** | **agent 问信使** |
//!
//! 前两种都不需要 agent 配合；但没有这一层，agent 就**没有嘴可以问**。
//!
//! # 「薄」在哪
//!
//! 判定逻辑全在 `slices` / `store` / `probe` 里，本模块**只做协议翻译**，
//! 不重复实现任何判定 —— 否则账本里会出现第二套判据（这正是本项目反复吃的亏）。
//!
//! # 两条纪律
//!
//! 1. **stdout 只能有协议帧**：任何诊断一律走 stderr。往 stdout 多打一个字，
//!    host 就会收到无法解析的垃圾，表现为「工具突然坏了」。
//! 2. **协议层用宽松 JSON，账本用严格 JSON**：MCP 是外部协议（参数里可能有 `1.5`），
//!    而 `warrant::json` 按规范拒浮点。所以本模块用 `serde_json`，
//!    **但任何写进账本的东西仍然走 `warrant::json`** —— 两套解析器各有各的边界。
//!
//! # 工具名与描述为什么这么写
//!
//! 工具描述用**人和模型说这件事时的原话**（「开工前先看」「你不在的时候变了什么」），
//! 不用自造词。依据：本项目「加能力 ≠ 加代码」已被真机证过三次 ——
//! 模型是照着描述里的触发语决定用不用的。
//!
//! # 一条跨模块的纪律：这里**不许写 markdown 标记**
//!
//! 工具描述、返回文本、盲区串都会被**纯文本消费者**直接显示（MCP 的 `text`、面板的 `textContent`）。
//! 真机已经踩过两次：`**…**` 原样显示了两个星号。强调用「」，不用 `**`。

use std::io::{BufRead, Write};
use std::path::Path;

use serde_json::{json, Value as J};

use crate::{probe, slices, store};

/// MCP 协议版本（用被广泛实现的稳定版，不用最新）
const PROTOCOL_VERSION: &str = "2024-11-05";

/// 跑 MCP server，阻塞到 stdin 关闭。
pub fn serve(repo: &Path) -> Result<(), String> {
    // 启动即校验项目根：宁可起不来，也不要起来之后把账本写到错地方
    let store_ok = store::Store::open(repo);
    if let Err(e) = &store_ok {
        eprintln!("warrantd mcp: 打不开账本（{}）：{e}", repo.display());
        return Err("账本不可用".into());
    }
    drop(store_ok);
    eprintln!(
        "warrantd mcp: 就绪（项目 {}），等 host 说话",
        repo.display()
    );

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = stdin
            .lock()
            .read_line(&mut buf)
            .map_err(|e| format!("读 stdin 失败：{e}"))?;
        if n == 0 {
            break;
        }
        let line = buf.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(resp) = handle(repo, line) {
            let mut out = stdout.lock();
            // 单行 JSON —— MCP stdio 是换行分隔
            let s = resp.to_string();
            out.write_all(s.as_bytes())
                .and_then(|_| out.write_all(b"\n"))
                .and_then(|_| out.flush())
                .map_err(|e| format!("写 stdout 失败：{e}"))?;
        }
    }
    Ok(())
}

/// 处理一条消息。**返回 `None` = 这是通知，不应答**（MCP 规定通知无响应）。
fn handle(repo: &Path, line: &str) -> Option<J> {
    let v: J = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            // 解析不了也要按 JSON-RPC 的规矩回 -32700（能拿到 id 的话拿不到，只能 id=null）
            return Some(json!({
                "jsonrpc": "2.0",
                "id": J::Null,
                "error": {"code": -32700, "message": format!("parse error: {e}")}
            }));
        }
    };
    let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = v.get("id").cloned().unwrap_or(J::Null);

    // 通知（无 id 或不带 method 的响应）⇒ 不回应
    if method.starts_with("notifications/") || (method.is_empty() && v.get("id").is_none()) {
        return None;
    }

    let ok = |result: J| json!({"jsonrpc": "2.0", "id": id, "result": result});
    let err = |code: i64, msg: String| json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}});

    match method {
        "initialize" => Some(ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "warrantd", "version": env!("CARGO_PKG_VERSION")},
            // 让 host 知道这是个「观测面」而不是「命令执行器」
            "instructions": "信使：打开 AI 的观测面。开工前可先调 warrant_status 看我盯了什么、看不见什么；\
        怀疑信息过期就调 warrant_since；想知道有没有人偷偷改东西就调 warrant_unreported；\
        你说自己改完某样东西之后可以调 warrant_check 核对。"
        }))),
        "ping" => Some(ok(json!({}))),
        "tools/list" => Some(ok(json!({"tools": tool_list()}))),
        "tools/call" => {
            let name = v
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let args = v
                .get("params")
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            Some(match call_tool(repo, name, &args) {
                Ok(text) => ok(json!({"content": [{"type": "text", "text": text}]})),
                Err(e) => ok(json!({
                    "content": [{"type": "text", "text": format!("错误：{e}")}],
                    "isError": true
                })),
            })
        }
        other => Some(err(-32601, format!("method not found: {other}"))),
    }
}

/// 把「我补扫了/我没在持续看」这类说明拼到文本末尾。
fn with_note(mut t: String, note: &str) -> String {
    if !note.is_empty() {
        t.push('\n');
        t.push_str(note);
        t.push('\n');
    }
    t
}

fn tool_list() -> J {
    json!([
        {
            "name": "warrant_status",
            "description": "开工前先看：信使在盯哪些文件、账本在哪、有几个未申报变更，以及「我看不见什么」。\
    什么时候该用：开始干一段活之前，或者怀疑自己拿到的信息已经过期时。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "detail": {"type": "boolean", "description": "是否附带完整观测白名单（默认 false）"}
                }
            }
        },
        {
            "name": "warrant_since",
            "description": "你上次看到之后，世界变了什么。什么时候该用：跨会话接着干、或者别的 agent 可能动过这个项目。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "offset": {"type": "integer", "description": "上次拿到的 offset（不知道就给 0）"}
                }
            }
        },
        {
            "name": "warrant_unreported",
            "description": "有哪些文件变了，但没有任何 agent 申报过。什么时候该用：想知道有没有人在偷偷改东西，\
    或者交付前做一次对账。",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "warrant_admit",
            "description": "准入自检：你现在到底有多可观测（L0 盲 / L1 事后 / L2 持续 / L3 全经），以及离下一级差什么。\
    什么时候该用：开始一段重要工作之前，确认「我做的事真能被看见吗」。",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "warrant_check",
            "description": "核对一条声明：它说的和账本里的观测对得上吗、有几条独立证据支撑。\
    什么时候该用：你说自己改完了某样东西之后。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "claim_id": {"type": "string", "description": "账本条目的 id（sha256:…）"}
                },
                "required": ["claim_id"]
            }
        }
    ])
}

fn call_tool(repo: &Path, name: &str, args: &J) -> Result<String, String> {
    // [MCP-FRESH-2026-10-27] **被问到时先自检新鲜度**。
    //
    // 场景：agent 通过 `warrantd mcp` 问，但没有常驻 daemon 在跑。
    // 不处理的话它看到的是空账本 —— 表现成"信使什么都没记"，
    // 而真相是"没人看着"。**这两件事必须能被区分**，否则它就是新的黑盒。
    let (watch, _src) = watch_of(repo);
    let freshness_note = crate::sweep::ensure_fresh(repo, &watch);
    let note = freshness_note.as_deref().unwrap_or("");
    match name {
        "warrant_status" => {
            let detail = args
                .get("detail")
                .and_then(|d| d.as_bool())
                .unwrap_or(false);
            let st = store::Store::open(repo)?;
            let (watch, src) = watch_of(repo);
            let unreported = slices::unreported(st.entries())
                .iter()
                .map(|u| u.changes.len())
                .sum::<usize>();
            // 只算两个数就够 —— 其余字段由下面的文本直接渲染（不要再拼一层 JSON）
            let n_files = watch
                .iter()
                .filter(|r| !repo.join(r.as_str()).is_dir())
                .count();
            let n_dirs = watch
                .iter()
                .filter(|r| repo.join(r.as_str()).is_dir())
                .count();
            // 返回**人读文本**而不是 JSON：MCP 的 text 字段本来就是给模型/人读的，
            // 再套一层 JSON 会让 agent 多一次转义解析（真机上就是这么暴露的）。
            let mut t = String::new();
            t.push_str(&format!(
                "项目：{}
",
                repo.display()
            ));
            t.push_str(&format!(
                "账本：offset={}，链完整={}，锁空闲={}
",
                st.offset(),
                st.verify().is_empty(),
                store::lock_is_free(repo)
            ));
            t.push_str(&format!(
                "观测面：{} 个文件（内容级）+ {} 个目录（结构级），来源：{}
",
                n_files, n_dirs, src
            ));
            t.push_str(&format!(
                "未申报变更：{}
",
                unreported
            ));
            t.push_str(&format!(
                "上次观测：{}
",
                match crate::sweep::snapshot_age_secs(repo) {
                    Some(sec) => format!("{sec} 秒前"),
                    None => "从未（还没扫过）".to_string(),
                }
            ));
            // 分两组渲染（做不到 / 还没做）——两边共用同一份数据，不许各写一套
            // 「我以为它在看，其实有东西没被看」——覆盖率也要报，否则边界又成黑盒
            if let Some(n) = untracked_count(repo) {
                if n > 0 {
                    t.push_str(&format!(
                        "观测面覆盖：git 里还有 {} 个未跟踪文件不在观测面内（补法：往 .warrant/watch.list 加，或直接加常用目录）\n",
                        n
                    ));
                }
            }
            // 分三组渲染（做不到 / 还没做 / 你选的形态）——两边共用同一份数据，不许各写一套
            t.push_str(&format!("\n{}\n", blind_spots_text()));
            if detail {
                t.push_str(
                    "
观测白名单：
",
                );
                for d in probe::WHITELIST {
                    t.push_str(&format!(
                        "· {} （申报 {}，真实上限 {}）{}
",
                        d.id, d.tier, d.tier_hint, d.desc
                    ));
                }
            }
            Ok(with_note(t, note))
        }
        "warrant_since" => {
            let off = args.get("offset").and_then(|o| o.as_u64()).unwrap_or(0) as usize;
            let st = store::Store::open(repo)?;
            let rep = slices::since(st.entries(), off);
            let mut t = String::new();
            t.push_str(&format!(
                "水位 {} → {}：新增 {} 条记录，其中世界变更 {} 批
",
                rep.from,
                rep.to,
                rep.items.len(),
                rep.world.len()
            ));
            for i in &rep.items {
                t.push_str(&format!(
                    "· seq={} {} {}（{}）
",
                    i.seq, i.kind, i.type_, i.actor
                ));
            }
            if !rep.unreported.is_empty() {
                t.push_str(&format!(
                    "
其中没被任何 agent 申报过的 {} 条：
",
                    rep.unreported.len()
                ));
                for u in &rep.unreported {
                    t.push_str(&format!(
                        "· {}（{}）
",
                        u.path,
                        u.kind.as_str()
                    ));
                }
            }
            Ok(with_note(t, note))
        }
        "warrant_unreported" => {
            let st = store::Store::open(repo)?;
            let rules = probe::ignore_rules(repo);
            let mut items: Vec<J> = Vec::new();
            let mut excluded = 0usize;
            for u in slices::unreported(st.entries()) {
                for c in u.changes {
                    if probe::is_ignored(&c.path, &rules) {
                        excluded += 1;
                        continue;
                    }
                    items.push(json!({"path": c.path, "kind": c.kind.as_str(), "world_claim": u.world_claim}));
                }
            }
            let mut t = String::new();
            if items.is_empty() {
                t.push_str(&format!(
                    "没有未申报变更。（忽略规则 {} 条，排除了 {} 条预期副作用）
",
                    rules.len(),
                    excluded
                ));
            } else {
                t.push_str(&format!(
                    "有 {} 个变更没有任何 agent 申报过：
",
                    items.len()
                ));
                for i in &items {
                    t.push_str(&format!(
                        "· {}（{})
",
                        i["path"].as_str().unwrap_or("?"),
                        i["kind"].as_str().unwrap_or("?")
                    ));
                }
                t.push_str(&format!(
                    "
（忽略规则 {} 条，另外排除了 {} 条预期副作用 —— 这些没被隐藏，只是不计入）
",
                    rules.len(),
                    excluded
                ));
            }
            t.push_str(
                "
这是负事实，不是错误。",
            );
            Ok(with_note(t, note))
        }
        "warrant_admit" => Ok(crate::admit::assess(repo).render()),
        "warrant_check" => {
            let cid = args
                .get("claim_id")
                .and_then(|c| c.as_str())
                .ok_or("缺 claim_id")?;
            let st = store::Store::open(repo)?;
            let v = slices::check_claim(st.entries(), cid)
                .ok_or_else(|| format!("账本里没有这条：{cid}"))?;
            let mut t = String::new();
            t.push_str(&format!(
                "条目：{}
",
                v.claim_id
            ));
            t.push_str(&format!(
                "状态：{}（{}）
",
                v.state, v.label
            ));
            t.push_str(&format!(
                "独立证据：{} 轴（{}），指向它的观测 {} 条
",
                v.d_eff,
                v.axes.join("/"),
                v.observations
            ));
            t.push_str(
                "
注意：state/label 是「有几条独立证据」的结论，不是「对不对」的判决。",
            );
            Ok(t)
        }
        other => Err(format!("未知工具 `{other}`")),
    }
}

/// 一条盲区的**性质**。
///
/// # 为什么必须分这两类（`[BLINDSPLIT-2026-10-28]`）
///
/// 原来七条混在一起写，用户一眼看不出「哪些是物理限制、哪些是我偷懒」。
/// **把工程欠账混进能力边界，本身就是一种不诚实** —— 它把责任模糊掉了：
/// 结构性的只能接受；没做的是我的账，该说清楚怎么补。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindKind {
    /// 真做不到（除非改架构/改协议）。
    Structural,
    /// **做得到，只是还没做。** 给了补法，就没资格说"看不见"。
    NotYet,
    /// **你选的形态造成的。** 不是做不到，也不是我偷懒 —— 是取舍。
    ///
    /// 单独一类，是因为它既不能算"能力边界"（那会把责任推给物理），
    /// 也不能算"欠账"（那是我说要补却没打算补）。**它是你的决定带来的代价，得单独说清。**
    ByChoice,
}

#[derive(Debug, Clone, Copy)]
pub struct BlindSpot {
    pub kind: BlindKind,
    pub what: &'static str,
    /// 为什么（结构性原因 / 为什么还没做）
    pub why: &'static str,
    /// `NotYet` 必填：怎么补。`Structural` 为 `None`。
    pub fix: Option<&'static str>,
}

use BlindKind::{ByChoice, NotYet, Structural};

/// **盲区自报**：观测者的第一条义务。
///
/// 这段会随 `warrant_status` 返回给 agent，也显示在面板上 —— **两边共用这一份**。
pub const BLIND_SPOTS: &[BlindSpot] = &[
    BlindSpot {
        kind: Structural,
        what: "内存 / 寄存器 / 硬件状态",
        why: "用户态进程读不到别的进程的寄存器；读内存需要调试特权（调试器/驱动级）",
        fix: None,
    },
    BlindSpot {
        kind: Structural,
        what: "未经代理的 MCP 调用",
        why: "MCP 是 host↔server 直连，第三方插不进去；不经过我们，就看不见",
        fix: None,
    },
    BlindSpot {
        kind: ByChoice,
        what: "信使没运行的时候",
        why: "你选的形态（不开机自启）。关闭期间世界照样在变",
        fix: Some("想要就改：开机自启，或加大打开频率。现在已能做的一半：下次打开会和上次快照比，知道「变了什么」——只是不知道中间改了几次、什么时候改的"),
    },
    BlindSpot {
        kind: NotYet,
        what: "是哪个进程发起的网络连接",
        why: "net.conns 已能看到对端地址/端口（[NET-2026-10-28] 补），但没关联到本机 PID",
        fix: Some("netstat -ano 的最后一列就是 PID，再查一次进程名即可 —— 纯解析，无新依赖"),
    },
    BlindSpot {
        kind: NotYet,
        what: "跨机器协作",
        why: "vcs.remote 已能看到和上游分支的差距（[REMOTE-2026-10-28] 补）；但对方那台机器上发生的事仍看不见",
        fix: Some("对方也跑 warrantd 并交换账本（账本本来就是可离线复算的，交换是可行路径）"),
    },
    BlindSpot {
        kind: NotYet,
        what: "没进观测面的路径（含未跟踪/被忽略文件）",
        why: "观测面由 .warrant/watch.list 或 git ls-files 决定；面外的东西不看",
        fix: Some("往 watch.list 里加路径/目录即可。每加一万个文件，每轮巡边多花约几十毫秒 —— 是代价问题，不是能力问题"),
    },
    BlindSpot {
        kind: NotYet,
        what: "两次巡边之间的抖动过程",
        why: "现在靠 mtime 对比：能发现「被碰过」，但不知道中间改了几次、每次是什么",
        fix: Some("上文件 watcher（Windows ReadDirectoryChangesW）能拿到逐次事件；代价是新依赖与事件风暴处理"),
    },
];

/// 盲区列表对外可读（面板与 MCP 用同一份，**不许各写一套**）。
pub fn blind_spots() -> &'static [BlindSpot] {
    BLIND_SPOTS
}

/// 渲染成人读文本（MCP 的 `text` 与诊断共用）。
///
/// **分两组打印**：做不到的在前（让人接受），没做的在后（那是我的账）。
pub fn blind_spots_text() -> String {
    let mut t = String::from(
        "我看不见（观测面边界）：
",
    );
    t.push_str(
        "
【做不到 · 结构性】
",
    );
    for b in BLIND_SPOTS.iter().filter(|b| b.kind == Structural) {
        t.push_str(&format!(
            "· {} —— {}
",
            b.what, b.why
        ));
    }
    t.push_str(
        "
【还没做 · 能补（这是欠账，不是边界）】
",
    );
    for b in BLIND_SPOTS.iter().filter(|b| b.kind == NotYet) {
        t.push_str(&format!(
            "· {} —— {}
",
            b.what, b.why
        ));
        if let Some(f) = b.fix {
            t.push_str(&format!(
                "   补法：{f}
"
            ));
        }
    }
    t.push_str(
        "
【你选的形态 · 取舍】
",
    );
    for b in BLIND_SPOTS.iter().filter(|b| b.kind == ByChoice) {
        t.push_str(&format!(
            "· {} —— {}
",
            b.what, b.why
        ));
        if let Some(f) = b.fix {
            t.push_str(&format!(
                "   {f}
"
            ));
        }
    }
    t
}

/// git 里有几个**未跟踪**文件（它们通常不在 `git ls-files` 的观测面里）。
///
/// [COVERAGE-2026-10-28] 用来回答一个很实际的问题：「我以为它在看，其实有东西没被看」。
/// 观测面覆盖率不报，用户永远不知道边界在哪 —— 那就又变成黑盒了。
fn untracked_count(repo: &Path) -> Option<usize> {
    let mut c = std::process::Command::new("git");
    c.args(["status", "--porcelain"]).current_dir(repo);
    crate::util::hide_console(&mut c);
    let o = c.output().ok()?;
    if !o.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| l.starts_with("??"))
            .count(),
    )
}

fn watch_of(repo: &Path) -> (Vec<String>, &'static str) {
    // 单源：解析只在 `sweep::watch_surface` 里有一份
    crate::sweep::watch_surface(repo)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_repo(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("warrantd-mcp-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".git")).unwrap();
        d
    }

    #[test]
    fn initialize_reports_tools_capability() {
        let repo = tmp_repo("init");
        let resp = handle(
            &repo,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        )
        .unwrap();
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(resp["result"]["capabilities"]["tools"].is_object());
        assert_eq!(resp["result"]["serverInfo"]["name"], "warrantd");
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn tools_list_has_the_four_asked_for() {
        let list = tool_list();
        let names: Vec<&str> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                "warrant_status",
                "warrant_since",
                "warrant_unreported",
                "warrant_admit",
                "warrant_check"
            ],
            "工具数刻意少（每多一个都在吃模型的注意力预算）——加一个必须想清楚"
        );
        // 描述里必须有**触发语**（人和模型说这件事时的原话），否则模型不会想到用
        let all = list.to_string();
        for trigger in [
            "开工前先看",
            "你上次看到之后",
            "没有任何 agent 申报过",
            "准入自检",
            "核对一条声明",
        ] {
            assert!(all.contains(trigger), "缺触发语「{trigger}」");
        }
    }

    /// 通知**不能**有响应（MCP 规定）。回了会让 host 收到无法配对的消息。
    #[test]
    fn notifications_get_no_reply() {
        let repo = tmp_repo("note");
        assert!(handle(
            &repo,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        )
        .is_none());
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn unknown_method_returns_jsonrpc_error_not_panic() {
        let repo = tmp_repo("unk");
        let resp = handle(
            &repo,
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/whatever"}"#,
        )
        .unwrap();
        assert_eq!(resp["error"]["code"], -32601);
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// **协议层必须能吃浮点**（`warrant::json` 会拒），否则 host 一发就崩。
    #[test]
    fn protocol_layer_accepts_floats_that_ledger_parser_rejects() {
        let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"warrant_since","arguments":{"offset":0,"_x":1.5}}}"#;
        assert!(
            warrant::json::parse(line).is_err(),
            "前提：严格解析器必须拒浮点"
        );
        let repo = tmp_repo("float");
        let resp = handle(&repo, line).expect("协议层必须能处理");
        assert!(
            resp["result"]["content"][0]["text"].as_str().is_some(),
            "应当正常返回文本而不是错误：{resp}"
        );
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn status_reports_blind_spots_and_offset() {
        let repo = tmp_repo("status");
        let resp = handle(
            &repo,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"warrant_status","arguments":{}}}"#,
        )
        .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        // 返回**人读文本**（不是 JSON 套 JSON）：agent 是模型，读自然语言没障碍
        assert!(
            !text.trim_start().starts_with('{'),
            "不该再返回一层 JSON：{text}"
        );
        assert!(text.contains("我看不见"), "盲区必须自报：{text}");
        assert!(text.contains("offset="), "要给出水位：{text}");
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// 四个工具都必须返回**非空人读文本**，而不是错误或空串。
    #[test]
    fn all_four_tools_return_readable_text() {
        let repo = tmp_repo("four");
        for (name, args) in [
            ("warrant_status", json!({})),
            ("warrant_since", json!({"offset": 0})),
            ("warrant_unreported", json!({})),
        ] {
            let line = json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": args}
            })
            .to_string();
            let resp = handle(&repo, &line).unwrap();
            assert!(
                resp["result"]["isError"].is_null(),
                "{name} 不该报错：{resp}"
            );
            let text = resp["result"]["content"][0]["text"].as_str().unwrap();
            assert!(!text.is_empty(), "{name} 不该返回空文本");
        }
        // warrant_check 需要一条真实 id
        let st = store::Store::open(&repo).unwrap();
        let gid = st.grant_id().to_string();
        drop(st);
        let line = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "warrant_check", "arguments": {"claim_id": gid}}
        })
        .to_string();
        let resp = handle(&repo, &line).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("独立证据"),
            "check 要回答「有几条独立证据」：{text}"
        );
        assert!(
            text.contains("不是「对不对」的判决"),
            "必须写明它不判决真假：{text}"
        );
        let _ = std::fs::remove_dir_all(&repo);
    }
}
