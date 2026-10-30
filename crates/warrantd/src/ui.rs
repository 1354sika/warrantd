//! 黑色信封 —— 信使的界面（最小版）。
//!
//! # 为什么是浏览器窗口，不是 Tauri
//!
//! Tauri 要前端工程 + tauri-cli + 打包流程。当前阶段的目标是**先做能看的，不先做能装的** ——
//! 所以这里起一个只监听 `127.0.0.1` 的极简 HTTP，把一页自包含 HTML 交给系统浏览器。
//!
//! **零新依赖**：HTTP/1.1 的 GET 只有那几行，手写比引一个库更省事，也符合 `warrantd` 的依赖纪律。
//!
//! # 界面为什么长这样
//!
//! 「黑色信封」不是仪表盘 —— 它是一封信。打开它应该看到：
//!
//! 1. **没申报的变更**（主角，最大的一块）—— 这是唯一"AI 没说你也能知道"的地方；
//! 2. **你不在的时候**（时间线）；
//! 3. **观测面与盲区**（脚注位置，但必须显眼）—— 观测者先承认自己瞎在哪。
//!
//! # 安全边界（这是本地面板，但仍然要守）
//!
//! - 只绑 `127.0.0.1`，不监听外网；
//! - 只实现 `GET`，不处理任何请求体；
//! - 不执行、不写文件、不代理 —— 它是**只读视图**，写操作仍走 CLI/MCP。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;

use serde_json::{json, Value as J};

use crate::{probe, slices, store};

/// 起面板：绑定、打印地址、打开浏览器、循环服务。阻塞。
pub fn serve(repo: &Path, port: u16, open_it: bool) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("绑定 127.0.0.1:{port} 失败：{e}"))?;
    let actual = listener
        .local_addr()
        .map_err(|e| format!("取端口失败：{e}"))?
        .port();
    let url = format!("http://127.0.0.1:{actual}/");
    println!("黑色信封：{url}");
    println!("（只监听本机；关掉这个窗口 = 停止服务。写操作仍走 warrantd open / mcp / claim）");
    if open_it {
        open_browser(&url);
    }

    for stream in listener.incoming() {
        let Ok(mut s) = stream else { continue };
        // 单请求即关：面板是只读轮询，不需要长连接
        if let Err(e) = handle_conn(&mut s, repo) {
            eprintln!("面板请求失败（不影响后续）：{e}");
        }
    }
    Ok(())
}

fn handle_conn(s: &mut TcpStream, repo: &Path) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    let n = s.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split_whitespace().nth(1).unwrap_or("/");

    let (ctype, body) = if path.starts_with("/api/state") {
        (
            "application/json; charset=utf-8",
            state_json(repo).to_string(),
        )
    } else if path.starts_with("/favicon") {
        ("text/plain; charset=utf-8", String::new())
    } else {
        ("text/html; charset=utf-8", HTML.to_string())
    };

    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body.as_bytes())?;
    s.flush()
}

/// 面板要的那一坨数据（**只读**，不写账本 —— 除了 `ensure_fresh` 的补扫）。
pub fn state_json(repo: &Path) -> J {
    // 被打开时自检新鲜度：打开面板这一刻就应该"补上你不在的时候"
    let (watch, src) = watch_surface(repo);
    let fresh_note = crate::sweep::ensure_fresh(repo, &watch);

    let Ok(st) = store::Store::open(repo) else {
        return json!({"error": "账本打不开", "repo": repo.display().to_string()});
    };
    let rules = probe::ignore_rules(repo);
    let mut unreported: Vec<J> = Vec::new();
    let mut excluded = 0usize;
    for u in slices::unreported(st.entries()) {
        for c in u.changes {
            if probe::is_ignored(&c.path, &rules) {
                excluded += 1;
                continue;
            }
            unreported.push(json!({"path": c.path, "kind": c.kind.as_str()}));
        }
    }
    // 最近 12 条：给"你不在的时候"一个时间线
    let recent: Vec<J> = st
        .entries()
        .iter()
        .rev()
        .take(12)
        .map(|e| {
            json!({
                "seq": e.body.get("chain").and_then(|c| c.get("seq")).and_then(|x| x.as_int()).unwrap_or(-1),
                "kind": e.body.get("kind").and_then(|x| x.as_str()).unwrap_or(""),
                "type": e.body.get("type").and_then(|x| x.as_str()).unwrap_or(""),
                "actor": e.body.get("actor").and_then(|a| a.get("id")).and_then(|x| x.as_str()).unwrap_or(""),
            })
        })
        .collect();

    json!({
        "repo": repo.display().to_string(),
        "offset": st.offset(),
        "chain_ok": st.verify().is_empty(),
        "lock_free": store::lock_is_free(repo),
        "last_seen_secs": crate::sweep::snapshot_age_secs(repo),
        "watch": {"count": watch.len(), "files": watch.iter().filter(|r| !repo.join(r.as_str()).is_dir()).count(),
                  "dirs": watch.iter().filter(|r| repo.join(r.as_str()).is_dir()).count(), "source": src},
        "unreported": unreported,
        "excluded_by_ignore": excluded,
        "ignore_rules": rules.len(),
        "recent": recent,
        "blind_spots": crate::mcp::BLIND_SPOTS.iter().map(|b| json!({
            "kind": match b.kind {
                crate::mcp::BlindKind::Structural => "structural",
                crate::mcp::BlindKind::NotYet => "not_yet",
                crate::mcp::BlindKind::ByChoice => "by_choice",
            },
            "what": b.what, "why": b.why, "fix": b.fix,
        })).collect::<Vec<_>>(),
        "fresh_note": fresh_note,
    })
}

fn watch_surface(repo: &Path) -> (Vec<String>, String) {
    // 单源：解析只在 `sweep::watch_surface` 里有一份
    let (v, src) = crate::sweep::watch_surface(repo);
    (v, src.to_string())
}

fn open_browser(url: &str) {
    let mut c = if cfg!(windows) {
        let mut c = Command::new("cmd");
        // 空串是 `start` 的窗口标题参数，不能省
        c.args(["/C", "start", "", url]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    crate::util::hide_console(&mut c);
    let _ = c.spawn();
}

/// 一页自包含面板。**所有样式与脚本内嵌**：不发第二个请求，也就不会因为断网/路径而白屏。
///
/// 用 `r##"…"##` 而不是 `r#"…"#`：CSS 里会出现 `"#` 这种组合（如 `color:"#fff"`）。
const HTML: &str = r##"<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>信使</title>
<style>
:root{--bg:#08080a;--card:#121217;--line:#23232c;--fg:#e9e6e1;--dim:#8b8792;--warn:#e0a03a;--ok:#4e9e70;--bad:#c8564f}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 50% -10%,#15151d 0%,var(--bg) 60%);color:var(--fg);
     font:15px/1.65 "Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif;padding:26px 18px 60px}
.wrap{max-width:860px;margin:0 auto}
header{display:flex;align-items:center;gap:14px;margin-bottom:4px}
svg{color:var(--fg);opacity:.92;flex:0 0 auto}
h1{font-size:19px;font-weight:600;margin:0;letter-spacing:.5px}
.sub{color:var(--dim);font-size:13px;margin:2px 0 26px 54px;word-break:break-all}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px}
.card.lead{border-color:#3a2f1d;background:linear-gradient(180deg,#191510 0%,#121217 100%)}
h2{font-size:13px;font-weight:600;letter-spacing:1.4px;color:var(--dim);margin:0 0 12px;text-transform:uppercase}
.big{font-size:40px;font-weight:700;line-height:1;letter-spacing:-1px}
.big.warn{color:var(--warn)} .big.ok{color:var(--ok)}
.hint{color:var(--dim);font-size:13px;margin-top:8px}
ul{list-style:none;padding:0;margin:0}
li{padding:7px 0;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:baseline;font-size:14px}
li:last-child{border-bottom:0}
.tag{font-size:11px;padding:1px 7px;border-radius:20px;border:1px solid var(--line);color:var(--dim);flex:0 0 auto}
.tag.touched{color:#9a8fd0;border-color:#2f2a45}
.tag.modified{color:#d08f5a;border-color:#42301f}
.tag.added{color:var(--ok);border-color:#1f3a28}
.tag.removed{color:var(--bad);border-color:#3a201f}
.path{word-break:break-all}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}
.kv .k{color:var(--dim);font-size:12px;letter-spacing:.6px}
.kv .v{font-size:16px;margin-top:2px}
.dim{color:var(--dim)}
.foot{color:var(--dim);font-size:12.5px;line-height:1.9}
.foot b{color:#b9b4be;font-weight:600}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px;vertical-align:middle}
.dot.ok{background:var(--ok)} .dot.bad{background:var(--bad)}
.note{background:#1a1710;border:1px solid #3a2f1d;color:#d8c9a8;border-radius:8px;padding:10px 12px;font-size:13px;margin-bottom:16px}
</style></head><body><div class="wrap">
<header>
<svg width="38" height="27" viewBox="0 0 38 27" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round">
<rect x="1" y="1" width="36" height="25" rx="2.5"/><path d="M1.5 3.5 19 15.5 36.5 3.5"/></svg>
<h1>信使</h1>
</header>
<div class="sub" id="repo">读取中…</div>

<div class="card lead">
  <h2>没申报的变更</h2>
  <div class="big" id="unrep-n">—</div>
  <div class="hint" id="unrep-hint">变了，但没有任何智能体说过它改过。</div>
  <ul id="unrep-list" style="margin-top:14px"></ul>
</div>

<div class="card">
  <h2>世界</h2>
  <div class="grid">
    <div class="kv"><div class="k">上次观测</div><div class="v" id="last">—</div></div>
    <div class="kv"><div class="k">账本条目</div><div class="v" id="offset">—</div></div>
    <div class="kv"><div class="k">观测面</div><div class="v" id="watch">—</div></div>
    <div class="kv"><div class="k">账本链</div><div class="v" id="chain">—</div></div>
  </div>
</div>

<div class="card">
  <h2>最近发生</h2>
  <ul id="recent"></ul>
</div>

<div class="card">
  <h2>我看不见</h2>
  <div class="foot" id="blind"></div>
</div>
</div>
<script>
const el=id=>document.getElementById(id);
let first=true;
async function tick(){
  try{
    const r=await fetch('/api/state',{cache:'no-store'});
    const s=await r.json();
    if(s.error){el('repo').textContent=s.error;return;}
    el('repo').textContent=s.repo;
    const n=s.unreported? s.unreported.length : 0;
    el('unrep-n').textContent=n;
    el('unrep-n').className='big '+(n>0?'warn':'ok');
    const ex=s.excluded_by_ignore||0;
    el('unrep-hint').textContent = n>0
      ? '变了，但没有任何智能体说过它改过 —— 这是负事实，不是错误。'
      : '干净。（忽略规则 '+s.ignore_rules+' 条，另外排除了 '+ex+' 条预期副作用 —— 它们没被隐藏，只是不计入）';
    const ul=el('unrep-list'); ul.innerHTML='';
    (s.unreported||[]).forEach(u=>{
      const li=document.createElement('li');
      li.innerHTML='<span class="tag '+u.kind+'">'+u.kind+'</span><span class="path"></span>';
      // 目录指纹的 `dir:` 前缀对人不友好，换成「整个目录」
      li.querySelector('.path').textContent = u.path.indexOf('dir:')===0 ? u.path.slice(4)+'/（整个目录）' : u.path;
      ul.appendChild(li);
    });
    el('last').textContent = s.last_seen_secs==null ? '从未' : (s.last_seen_secs<90? s.last_seen_secs+' 秒前' : Math.round(s.last_seen_secs/60)+' 分钟前');
    el('offset').textContent = s.offset;
    el('watch').textContent = s.watch.count+' 项';
    el('chain').innerHTML = (s.chain_ok?'<span class="dot ok"></span>完整':'<span class="dot bad"></span>异常');
    const rec=el('recent'); rec.innerHTML='';
    (s.recent||[]).forEach(e=>{
      const li=document.createElement('li');
      li.innerHTML='<span class="tag">#'+e.seq+'</span><span class="path"></span>';
      li.querySelector('.path').textContent=e.kind+' · '+(e.actor||'—');
      rec.appendChild(li);
    });
    const b=el('blind'); b.innerHTML='';
    const groups=[['structural','做不到 · 结构性','#8b8792'],['not_yet','还没做 · 能补（这是欠账，不是边界）','#e0a03a'],['by_choice','你选的形态 · 取舍','#7aa6c8']];
    groups.forEach(([k,title,color])=>{
      const items=(s.blind_spots||[]).filter(x=>x.kind===k);
      if(!items.length) return;
      const h=document.createElement('div');
      h.textContent=title; h.style.cssText='color:'+color+';font-size:12px;letter-spacing:.8px;margin:12px 0 6px';
      b.appendChild(h);
      items.forEach(x=>{
        const d=document.createElement('div'); d.style.marginBottom='6px';
        const w=document.createElement('b'); w.textContent='· '+x.what; d.appendChild(w);
        const y=document.createElement('span'); y.textContent=' —— '+x.why; d.appendChild(y);
        if(x.fix){const f=document.createElement('div'); f.style.cssText='color:#e0a03a;opacity:.85;margin-left:12px'; f.textContent='补法：'+x.fix; d.appendChild(f);}
        b.appendChild(d);
      });
    });
    if(s.fresh_note && first){const d=document.createElement('div');d.className='note';d.textContent=s.fresh_note;document.querySelector('.wrap').insertBefore(d,el('unrep-n').closest('.card'));first=false;}
  }catch(e){el('repo').textContent='连不上信使（窗口还开着吗？）';}
}
tick(); setInterval(tick,3000);
</script></body></html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("warrantd-ui-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".git")).unwrap();
        std::fs::create_dir_all(d.join(".warrant")).unwrap();
        d
    }

    #[test]
    fn state_has_the_four_screens() {
        let repo = tmp("state");
        std::fs::write(repo.join("a.txt"), b"hi").unwrap();
        std::fs::write(repo.join(".warrant/watch.list"), "a.txt\n").unwrap();
        let s = state_json(&repo);
        // 四块内容的数据都在
        assert!(s["unreported"].is_array(), "没申报的变更");
        assert!(s["recent"].is_array(), "最近发生");
        assert!(s["blind_spots"].as_array().unwrap().len() >= 7, "盲区");
        assert!(s["watch"]["count"].as_u64().unwrap() >= 1, "观测面");
        assert!(s["offset"].as_u64().unwrap() >= 1, "账本");
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// 面板是**只读视图**：打开它除了补扫，不该往账本里加任何东西。
    #[test]
    fn opening_panel_does_not_grow_ledger_when_fresh() {
        let repo = tmp("ro");
        std::fs::write(repo.join("a.txt"), b"hi").unwrap();
        std::fs::write(repo.join(".warrant/watch.list"), "a.txt\n").unwrap();
        let a = state_json(&repo)["offset"].as_u64().unwrap();
        let b = state_json(&repo)["offset"].as_u64().unwrap();
        assert_eq!(a, b, "第二次打开不该增加条目（世界没变）");
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// [BLINDSPLIT-2026-10-28] 盲区必须**分成两类**，而且"没做"的必须给出补法。
    ///
    /// 这条钉子的起因：用户问「为什么这些做不到」—— 而 7 条里只有 2 条真做不到。
    /// 把工程欠账混进能力边界，等于把责任模糊掉。
    #[test]
    fn blind_spots_are_split_and_not_yet_ones_carry_a_fix() {
        use crate::mcp::{BlindKind, BLIND_SPOTS};
        let structural = BLIND_SPOTS.iter().filter(|b| b.kind == BlindKind::Structural).count();
        let not_yet = BLIND_SPOTS.iter().filter(|b| b.kind == BlindKind::NotYet).count();
        let by_choice = BLIND_SPOTS.iter().filter(|b| b.kind == BlindKind::ByChoice).count();
        assert!(structural >= 1, "至少要有结构性的一条");
        assert!(not_yet >= 1, "至少要有还没做的一条");
        assert!(by_choice >= 1, "「你选的形态」要单独一类 —— 它既不是边界也不是欠账");
        for b in BLIND_SPOTS.iter().filter(|b| b.kind == BlindKind::NotYet) {
            assert!(b.fix.is_some(), "「还没做」的必须给出补法，否则等于说「做不到」：{}", b.what);
        }
        for b in BLIND_SPOTS.iter().filter(|b| b.kind == BlindKind::Structural) {
            assert!(b.fix.is_none(), "「做不到」的不该给补法（给了就说明它其实做得到）：{}", b.what);
        }
        // 文本渲染要分两组
        let t = crate::mcp::blind_spots_text();
        assert!(t.contains("做不到") && t.contains("还没做"), "{t}");
    }
}
