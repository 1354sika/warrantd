//! MCP 代理 —— 让「AI 通过 MCP 干了什么」也进观测面（**洞②**）。
//!
//! # 它解决什么
//!
//! agent 通过 MCP 工具改外部系统（如 EDA 工程）时，那些副作用**完全在文件观测面之外**。
//! 这一层把 MCP 调用本身变成观测对象。
//!
//! # 做法：站在中间，只旁观
//!
//! ```text
//! host ──stdin──▶ warrantd proxy ──stdin──▶ 真正的 MCP server
//!                ◀──stdout───┤   ◀──stdout──┘
//! ```
//!
//! host 的 MCP 配置里把命令从 `python x.py` 改成 `warrantd proxy -- python x.py` 即可 ——
//! **不改 host、不改 server、不需要任何一方配合**。
//!
//! # 三条不可违反的纪律
//!
//! 1. **逐字节转发**：代理绝不改写、绝不重排、绝不补字段。协议兼容性优先于一切 ——
//!    一个"帮忙修正"的代理会变成新的故障源。
//! 2. **转发不因记账失败而中断**：账本出错只记 stderr，转发继续。观测不能反过来伤害被观测的东西。
//! 3. **解析失败要如实降级**：warrant 的 JSON 解析器是严格档（拒浮点），而 MCP 参数里
//!    完全可能有 `1.5` ⇒ 解析失败是**正常情况**，此时退化为字符串提取并标记 `degraded`，
//!    **不能因此丢掉"这次调用发生过"这个事实**。
//!
//! # 诚实边界
//!
//! - 只记 `tools/call` 与对应响应。`initialize` / `notifications/*` / `resources/*` 不记。
//! - 不记录 stderr（原样透传）。
//! - 只支持 **换行分隔** 的 JSON-RPC（MCP stdio 规范如此）。若检测到 `Content-Length:` 分帧，
//!   **明确报不支持**，而不是静默把整段当一行转坏。

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use warrant::json::Value;

use crate::store::Store;
use crate::util;

/// 一次被代理的工具调用（旁路提取的结果）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub rpc_id: String,
    pub tool: String,
    /// 参数**键名**（不记值：值可能含密钥/隐私；键名已足够回答"这次调用动了什么"）
    pub args_keys: Vec<String>,
    /// 原始行长（字节）—— 说明这次调用有多重
    pub line_bytes: usize,
    /// 解析是否退化为字符串匹配（warrant 的 JSON 解析器拒浮点，MCP 参数里常见）
    pub degraded: bool,
}

/// 请求的旁路解析。
///
/// **先精确解析，失败再退化**：绝不因为解析不了就丢掉"这次调用发生过"。
pub fn analyze_request(line: &str) -> Option<Call> {
    let t = line.trim();
    if t.is_empty() {
        return None;
    }
    // ① 精确路径
    if let Ok(v) = warrant::json::parse(t) {
        if v.get("method").and_then(|m| m.as_str()) != Some("tools/call") {
            return None;
        }
        let rpc_id = match v.get("id") {
            Some(Value::Int(i)) => i.to_string(),
            Some(Value::Str(s)) => s.clone(),
            _ => String::new(),
        };
        let params = v.get("params");
        let tool = params
            .and_then(|p| p.get("name"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let args_keys: Vec<String> = params
            .and_then(|p| p.get("arguments"))
            .and_then(|a| a.as_object())
            .map(|o| o.iter().map(|(k, _)| k.clone()).collect())
            .unwrap_or_default();
        return Some(Call {
            rpc_id,
            tool,
            args_keys,
            line_bytes: t.len(),
            degraded: false,
        });
    }
    // ② 退化路径：严格解析器被浮点等挡下时，至少把"调用了哪个工具"抢出来
    if !t.contains("tools/call") {
        return None;
    }
    Some(Call {
        rpc_id: extract_after(t, "\"id\":"),
        tool: extract_after(t, "\"name\":\""),
        args_keys: Vec::new(),
        line_bytes: t.len(),
        degraded: true,
    })
}

/// 从 `"key":"value"` 里抢出 value（退化路径专用，**只做尽力而为**）。
fn extract_after(s: &str, key: &str) -> String {
    let Some(i) = s.find(key) else {
        return String::new();
    };
    let rest = s[i + key.len()..].trim_start();
    if key.ends_with('"') {
        // key 已经吃掉了开头那个引号（如 `"name":"`）⇒ rest 直接从值开始
        rest.split('"').next().unwrap_or("").to_string()
    } else if let Some(r) = rest.strip_prefix('"') {
        // key 是 `"id":` 形态 ⇒ rest 可能是 `"abc"` 也可能是 `7`
        r.split('"').next().unwrap_or("").to_string()
    } else {
        rest.chars()
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect()
    }
}

/// 响应的旁路解析：`(rpc_id, 是否成功, 行字节数)`。
pub fn analyze_response(line: &str) -> Option<(String, bool, usize)> {
    let t = line.trim();
    if t.is_empty() {
        return None;
    }
    let Ok(v) = warrant::json::parse(t) else {
        // 响应含浮点时同样解析不了 —— 只把它当"某条响应"，不猜 id
        return None;
    };
    let rpc_id = match v.get("id") {
        Some(Value::Int(i)) => i.to_string(),
        Some(Value::Str(s)) => s.clone(),
        _ => return None,
    };
    let ok = v.get("error").is_none();
    Some((rpc_id, ok, t.len()))
}

/// 检测 LSP 风格分帧（`Content-Length:`）。MCP stdio 规范是换行分隔；
/// 遇到这种帧**明确报不支持**，而不是把整段当一行转坏。
pub fn looks_like_lsp_framing(line: &str) -> bool {
    line.trim_start().starts_with("Content-Length:")
}

/// 跑代理，阻塞到子进程退出。
pub fn run(server_cmd: &[String], repo: &Path, server_name: &str) -> Result<(), String> {
    let (prog, args) = server_cmd
        .split_first()
        .ok_or("proxy 需要一个 server 命令：warrantd proxy -- <cmd> [args...]")?;

    let mut c = Command::new(prog);
    c.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()); // 透传：不解析、不改写
    util::hide_console(&mut c);
    let mut child = c
        .spawn()
        .map_err(|e| format!("起不来 MCP server `{prog}`：{e}"))?;

    let child_in = child.stdin.take().ok_or("拿不到 server stdin")?;
    let child_out = child.stdout.take().ok_or("拿不到 server stdout")?;

    let store = Arc::new(Mutex::new(Store::open(repo)?));
    // rpc_id → claim id（响应用它挂到对应 claim 上）
    let pending: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    let s1 = store.clone();
    let p1 = pending.clone();
    let name1 = server_name.to_string();
    let t_up = std::thread::spawn(move || {
        let _ = forward(
            std::io::stdin().lock(),
            child_in,
            &s1,
            &p1,
            &name1,
            Direction::HostToServer,
        );
    });

    let s2 = store.clone();
    let p2 = pending.clone();
    let name2 = server_name.to_string();
    let t_down = std::thread::spawn(move || {
        // ChildStdout 只实现 Read，不实现 BufRead ⇒ 必须包一层 BufReader
        let _ = forward(
            std::io::BufReader::new(child_out),
            std::io::stdout().lock(),
            &s2,
            &p2,
            &name2,
            Direction::ServerToHost,
        );
    });

    let status = child.wait().map_err(|e| format!("等待 server 退出失败：{e}"))?;
    let _ = t_up.join();
    let _ = t_down.join();
    if !status.success() {
        return Err(format!("MCP server 非正常退出：{status}"));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    HostToServer,
    ServerToHost,
}

/// 单方向转发：**先记账，再转发**（这样即使 server 崩了，「它被调用过」也留得下）。
fn forward<R: BufRead, W: Write>(
    mut reader: R,
    mut writer: W,
    store: &Arc<Mutex<Store>>,
    pending: &Arc<Mutex<HashMap<String, String>>>,
    server: &str,
    dir: Direction,
) -> std::io::Result<()> {
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        if looks_like_lsp_framing(&buf) {
            eprintln!(
                "warrantd proxy: 检测到 Content-Length 分帧（LSP 风格），本代理只支持换行分隔的 MCP stdio。\
                 为不把协议转坏，已停止记录，但继续原样转发。"
            );
        } else {
            match dir {
                Direction::HostToServer => {
                    if let Some(call) = analyze_request(&buf) {
                        record_call(store, pending, server, &call);
                    }
                }
                Direction::ServerToHost => {
                    if let Some((rpc_id, ok, bytes)) = analyze_response(&buf) {
                        record_response(store, pending, &rpc_id, ok, bytes);
                    }
                }
            }
        }
        // 逐字节原样转发 —— 代理绝不改写协议内容
        writer.write_all(buf.as_bytes())?;
        writer.flush()?;
    }
    Ok(())
}

fn record_call(
    store: &Arc<Mutex<Store>>,
    pending: &Arc<Mutex<HashMap<String, String>>>,
    server: &str,
    call: &Call,
) {
    // 记账失败**不能**中断转发：观测不许反过来伤害被观测的东西
    let Ok(mut st) = store.lock() else {
        return;
    };
    match st.append_mcp_call(server, &call.tool, &call.rpc_id, &call.args_keys, call.line_bytes, call.degraded) {
        Ok(id) => {
            if !call.rpc_id.is_empty() {
                if let Ok(mut p) = pending.lock() {
                    p.insert(call.rpc_id.clone(), id);
                }
            }
        }
        Err(e) => eprintln!("warrantd proxy: 记账失败（转发继续）：{e}"),
    }
}

fn record_response(
    store: &Arc<Mutex<Store>>,
    pending: &Arc<Mutex<HashMap<String, String>>>,
    rpc_id: &str,
    ok: bool,
    bytes: usize,
) {
    let claim_id = pending.lock().ok().and_then(|mut p| p.remove(rpc_id));
    let Some(claim_id) = claim_id else {
        return; // 不是 tools/call 的响应（initialize 之类），不记
    };
    let Ok(mut st) = store.lock() else {
        return;
    };
    if let Err(e) = st.append_mcp_result(&claim_id, ok, bytes) {
        eprintln!("warrantd proxy: 记观测失败（转发继续）：{e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_tools_call_and_extracts_fields() {
        let line = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"lceda_read","arguments":{"path":"/a","net":true}}}"#;
        let c = analyze_request(line).expect("应识别为 tools/call");
        assert_eq!(c.rpc_id, "7");
        assert_eq!(c.tool, "lceda_read");
        assert_eq!(c.args_keys, vec!["path".to_string(), "net".to_string()]);
        assert!(!c.degraded);
    }

    #[test]
    fn ignores_non_tool_methods() {
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"params":{"name":"x"}}"#,
            "",
            "   ",
        ] {
            assert!(analyze_request(line).is_none(), "不该当成工具调用：{line}");
        }
    }

    /// **退化为字符串匹配**：MCP 参数里带浮点很常见，而 warrant 的 JSON 解析器是严格档（拒浮点）。
    /// 关键要求：**解析失败也不能丢掉「这次调用发生过」这个事实**。
    #[test]
    fn float_arguments_degrade_instead_of_being_lost() {
        let line = r#"{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"set_zoom","arguments":{"level":1.5}}}"#;
        assert!(
            warrant::json::parse(line).is_err(),
            "前提：严格解析器必须拒浮点（否则本测试无意义）"
        );
        let c = analyze_request(line).expect("必须退化而不是丢失");
        assert!(c.degraded, "必须标记为退化，不能冒充精确");
        assert_eq!(c.tool, "set_zoom");
        assert_eq!(c.rpc_id, "abc");
    }

    #[test]
    fn response_pairs_by_id_and_flags_error() {
        let ok = analyze_response(r#"{"jsonrpc":"2.0","id":7,"result":{"ok":true}}"#).unwrap();
        assert_eq!(ok.0, "7");
        assert!(ok.1);
        let err = analyze_response(r#"{"jsonrpc":"2.0","id":7,"error":{"code":-1}}"#).unwrap();
        assert!(!err.1, "带 error 必须判为失败");
    }

    #[test]
    fn lsp_framing_is_detected_not_mangled() {
        assert!(looks_like_lsp_framing("Content-Length: 42\r\n"));
        assert!(!looks_like_lsp_framing(r#"{"jsonrpc":"2.0"}"#));
    }
}
