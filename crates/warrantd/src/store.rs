//! 账本 —— 项目内的 append-only 证据链（`<repo>/.warrant/entries.jsonl`）。
//!
//! # 三条不可违反的性质
//!
//! 1. **只追加**：任何"改写历史"都不做（含归档也不改字节 —— 与 `crates/core/src/warrant_ledger.rs`
//!    的封存口径一致：只切文件、不重编号）。
//! 2. **可离线复算**：每条都有 `id = sha256(域‖canonical(body))` 与 `chain{seq,prev}`，
//!    任何人拿到 `entries.jsonl` 都能用 `warrant::ledger::verify_chain` 自己算一遍。
//! 3. **身份可辨**：观测由 `verifier:warrantd` 签（不是 ai，也不是 human）。
//!
//! # 为什么账本在项目里
//!
//! 用户裁决（2026-10-27）：**账本住在用户的项目里**。后果要一并处理：
//! - `.warrant/` 会被 `git status` 看到 ⇒ 由 `.gitignore` 决定是否入库（默认建议忽略，
//!   对外分享走 `warrantd export` 生成可提交的证据包 —— 与 `messenger_export` 同一思路）；
//! - 跨项目不共享 ⇒ 这是**有意的**：账本属于项目，不属于某个应用。

//! # 多主体并发（`[MULTI-WRITER-2026-10-27]`）
//!
//! warrantd 是**常驻**进程，所以**不能像引擎那样长期持锁**：引擎（`crates/core/src/warrant_ledger.rs:307`）
//! 持锁一个进程生命周期是合理的（只有一个引擎），但 daemon 长期持锁 = 第二个 agent 永远写不进去
//! ⇒ 正好毁掉「多主体共享同一本账」这个核心价值。
//!
//! 所以本模块的规则是：**写时短暂持锁，持锁后重读，写完即放**。
//! - 不重读的后果：别人的进程已经追加了，你的 `seq` 会算错 ⇒ 链断 ⇒ 整本账作废（不可恢复）；
//! - 长期持锁的后果：第二个 agent 拿不到锁 ⇒ 退化成"又一个孤岛"，白做了常驻。

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use warrant::json::Value;
use warrant::{admission, canon, ledger, projection};

use crate::probe::Observed;
use crate::snapshot::Change;
use crate::util::{arr, now_rfc3339, obj, plus_days_rfc3339, s};

/// 世界变更（daemon 自产，作为"负事实"载体）
pub const T_WORLD_CHANGE: &str = "warrant://types/warrantd.world.change@1";
/// agent 申报（由 agent 侧写入，daemon 只负责对账）
pub const T_AGENT_CLAIM: &str = "warrant://types/warrantd.agent.claim@1";
/// MCP 代理记的一次工具调用（洞②：观测面从文件系统扩到 MCP 链路）
pub const T_MCP_CALL: &str = "warrant://types/warrantd.mcp.call@1";

// capability 与 lib.rs 共用同一份（单源；两份会漂移，而 P5 漂移是静默拒收）

/// 账本互斥锁（RAII：`Drop` 即释放）。
///
/// 机制与 `crates/core/src/warrant_ledger.rs:307` 同一套（Windows `share_mode(0)` 独占 ⇒
/// 其他进程对该文件的所有 open 都失败），**但持有期不同**：core 是进程生命周期，
/// 本 crate 是「一次写入」那么长。理由见模块头。
pub struct LedgerLock {
    /// 只为持有句柄（Drop 即释放）。内容仅记 pid，便于人排查。
    _f: std::fs::File,
}

const LOCK_ATTEMPTS: u32 = 3;
const LOCK_RETRY_MS: u64 = 400;

fn acquire_lock(dir: &Path) -> Result<LedgerLock, String> {
    acquire_lock_n(dir, LOCK_ATTEMPTS)
}

/// 探测账本当前是否**没人**在写（诊断用，立刻释放）。
///
/// 用途：`warrantd status` 如实显示「现在有别人在写吗」——
/// 排查「为什么这次写慢了 0.8 秒」时，这是第一条线索。
/// 只尝试 **1 次**（不复重试）：诊断要快，不要为了探测卡 1.2 秒。
pub fn lock_is_free(repo: &Path) -> bool {
    let dir = repo.join(crate::LEDGER_DIR);
    if !dir.exists() {
        return true;
    }
    match acquire_lock_n(&dir, 1) {
        Ok(l) => {
            drop(l);
            true
        }
        Err(_) => false,
    }
}

fn acquire_lock_n(dir: &Path, attempts: u32) -> Result<LedgerLock, String> {
    let path = dir.join("entries.lock");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // 独占：其他进程（含本进程）对该文件的所有 open 都会失败 ⇒ 天然跨进程互斥。
        opts.share_mode(0);
    }
    // 短重试：绝大多数冲突是瞬时的（另一个 warrantd 正在写完最后一行）。
    // 3 × 400ms ⇒ 写路径最多多等 0.8s，换来「不必用户手动关掉另一个 agent」。
    let mut last_err = String::new();
    for attempt in 0..attempts {
        match opts.open(&path) {
            Ok(mut f) => {
                use std::io::Write as _;
                let _ = f.set_len(0);
                let _ = writeln!(f, "pid={} daemon=warrantd", std::process::id());
                return Ok(LedgerLock { _f: f });
            }
            Err(e) => {
                last_err = e.to_string();
                if attempt + 1 < attempts {
                    std::thread::sleep(std::time::Duration::from_millis(LOCK_RETRY_MS));
                }
            }
        }
    }
    Err(format!(
        "账本被另一个进程占用（已重试 {attempts} 次）：{last_err}。\
         两个主体不能同时写同一本账 —— 链完整性不允许，这条不放宽。\
         若是崩溃残留：删掉 `.warrant/entries.lock` 再试（安全：锁文件不含任何数据）。"
    ))
}

/// 读账本并校验**链**（**不验签**）。
///
/// **[PERF-2026-10-29] 为什么这里不再验签**：
/// 每次 `append` 都要重读全账本，而验签是 ed25519（约 50 μs/条）。
/// 实测（release）：151 条时单条追加已 **49 ms**，1 万条会到 **3.3 秒** ——
/// 「账本越用越慢」的根因就在这一行。
///
/// **链校验很便宜**（字符串 + 哈希比对），保留；
/// **验签是事后审计的职责**，由 [`Store::verify`]（`warrantd verify` / `status`）全量执行。
///
/// 分工是有意的：**写路径只需「接得上」，读路径才关心「签名对不对」。**
/// 追加时不需要证明历史全对，只需要知道上一条的 id。
fn read_entries(dir: &Path) -> Result<Vec<ledger::Entry>, String> {
    let path = dir.join("entries.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("read entries: {e}"))?;
    let entries = ledger::load_jsonl(&text).map_err(|e| format!("entries parse: {e}"))?;
    let errs = ledger::verify_chain(&entries);
    if !errs.is_empty() {
        return Err(format!(
            "账本条链不连续（可能被外部改写，也可能归档时衔接有误）：{}。\
             后果：认定层整体停用。⛔ 不要手工把首条 seq 改成 0 —— 那才是真正的篡改。",
            errs.join("; ")
        ));
    }
    Ok(entries)
}

/// 把所有卷按顺序拼成一个列表：`volumes/vol-*.jsonl`（文件名序）然后当前卷。
///
/// `[SEAL-2026-10-29]` 封卷后 `since` 默认只看当前卷 —— 问「三个月前」就落空。
/// 这个函数把各卷串起来供 `--all` 使用。
///
/// **下标即全局序号**：拼接后的第 `i` 条就是逻辑 offset `i` 对应的条目，
/// 所以 `since(logical_offset)` 可以直接在这个列表上切片。
///
/// 注意：各卷的 `chain.seq` 都从 0 开始，拼起来后 seq **不连续** —— 这是预期行为，
/// 卷内链完好、卷间靠 `parents` 相连，不要用拼接结果去跑 `verify_chain`。
pub fn all_entries(repo: &Path) -> Result<Vec<ledger::Entry>, String> {
    let dir = repo.join(crate::LEDGER_DIR);
    let mut vols: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir.join(VOLUMES)) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("jsonl") {
                vols.push(p);
            }
        }
    }
    vols.sort();
    let mut out: Vec<ledger::Entry> = Vec::new();
    for v in vols.iter().chain(std::iter::once(&dir.join("entries.jsonl"))) {
        if let Ok(text) = std::fs::read_to_string(v) {
            if let Ok(mut es) = ledger::load_jsonl(&text) {
                out.append(&mut es);
            }
        }
    }
    Ok(out)
}

/// 验**所有卷** + **卷间谱系**。
///
/// **[SEAL-2026-10-29]** 单卷 verify 只能证明「这一卷自己没断」；
/// 封过卷之后还必须证明「这一卷接得上上一卷」，否则归档就等于断案。
///
/// 谱系判据：本卷首条必须带 `parents`，且其中一项等于**上一卷最后一条的 id**。
/// 首卷（bootstrap）没有上一卷，跳过。
///
/// 返回 `(卷清单, 错误)` —— 卷清单给 `--all` 打印，错误为空才算通过。
pub fn verify_all(repo: &Path) -> Result<(Vec<(String, usize)>, Vec<String>), String> {
    let dir = repo.join(crate::LEDGER_DIR);
    let mut vols: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir.join(VOLUMES)) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("jsonl") {
                vols.push(p);
            }
        }
    }
    vols.sort();
    let mut list: Vec<(String, usize)> = Vec::new();
    let mut errs: Vec<String> = Vec::new();
    let mut prev_head = String::new();
    let mut prev_name = String::new();

    for v in vols.iter().chain(std::iter::once(&dir.join("entries.jsonl"))) {
        let text = match std::fs::read_to_string(v) {
            Ok(t) => t,
            Err(e) => {
                errs.push(format!("{}: 读不到（{e}）", v.display()));
                continue;
            }
        };
        if text.trim().is_empty() {
            continue;
        }
        let entries = match ledger::load_jsonl(&text) {
            Ok(e) => e,
            Err(e) => {
                errs.push(format!("{}: 解析失败（{e}）", v.display()));
                continue;
            }
        };
        let name = v
            .file_name()
            .map(|x| x.to_string_lossy().to_string())
            .unwrap_or_default();
        let mut e1 = ledger::verify_chain(&entries);
        e1.extend(ledger::verify_signatures(&entries));
        for e in &e1 {
            errs.push(format!("{name}: {e}"));
        }
        // 谱系：本卷首条必须指向上一卷的 head（首卷没有上一卷，跳过）
        if !prev_head.is_empty() {
            let points_here = entries[0]
                .body
                .get("parents")
                .and_then(|p| p.as_array())
                .map(|a| a.iter().any(|x| x.as_str() == Some(prev_head.as_str())))
                .unwrap_or(false);
            if !points_here {
                errs.push(format!(
                    "{name}: 首条没有指向上一卷（{prev_name}）的 head —— 谱系断了，归档不可作证"
                ));
            }
        }
        prev_head = entries.last().map(|e| e.id.clone()).unwrap_or_default();
        prev_name = name.clone();
        list.push((name, entries.len()));
    }
    Ok((list, errs))
}

/// 增量刷新 entries：**没变就不动，只变长就只解析新行，变短才全量重读**。
///
/// **[PERF-2026-10-29] 这是把「每次写入 O(N²)」压回 O(1) 的关键。**
///
/// 原来的 `with_write` 每次都 `read_entries`（解析全部 + 全量验链），
/// 于是 N 次写 = O(N²)：release 实测 151 条时单条 37 ms，1 万条到秒级。
///
/// 现在按字节位置续读，并对**新增部分**做等价于 `verify_chain` 的三条检查
/// （id 对 body / seq 连续 / prev 接得上）。旧的部分已经验过，不重复验 ——
/// 但**变短就一定全量重读**，绝不沿用记忆。
///
/// 读半行怎么办：并发写还没写完最后一行时，只消费到**最后一个换行**，
/// 剩下的留到下次（宁可不读，也不把半行当条目）。
///
/// 返回：新增条目里最后一条 grant 的 id（没有则 `None`）。
fn refresh_entries(
    dir: &Path,
    entries: &mut Vec<ledger::Entry>,
    cursor: &mut u64,
) -> Result<Option<String>, String> {
    let path = dir.join("entries.jsonl");
    let len = match std::fs::metadata(&path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            entries.clear();
            *cursor = 0;
            return Ok(None);
        }
        Err(e) => return Err(format!("stat entries: {e}")),
    };
    if len == *cursor {
        return Ok(None); // 没变 —— O(1)
    }
    if len < *cursor {
        // 变短：被截断或归档。不能沿用内存里的条目，必须全量重读。
        *entries = read_entries(dir)?;
        *cursor = len;
        return Ok(None);
    }
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut f = std::fs::File::open(&path).map_err(|e| format!("open entries: {e}"))?;
    f.seek(SeekFrom::Start(*cursor))
        .map_err(|e| format!("seek entries: {e}"))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)
        .map_err(|e| format!("read tail: {e}"))?;
    let cut = match buf.rfind('\n') {
        Some(i) => i + 1,
        None => return Ok(None),
    };
    let fresh = ledger::load_jsonl(&buf[..cut]).map_err(|e| format!("entries parse: {e}"))?;
    let start = entries.len();
    let mut prev = entries.last().map(|e| e.id.clone()).unwrap_or_default();
    let mut last_grant: Option<String> = None;
    for (i, e) in fresh.iter().enumerate() {
        let want = (start + i) as i64;
        if canon::event_id(&e.body).ok().as_deref() != Some(e.id.as_str()) {
            return Err(format!("entry {want}: id 与 body 不符（账本可能被外部改写）"));
        }
        let ch = e.body.get("chain");
        let seq = ch.and_then(|c| c.get("seq")).and_then(|s| s.as_int());
        if seq != Some(want) {
            return Err(format!(
                "entry {want}: chain.seq={seq:?}，应为 {want}（账本可能被外部改写，或归档时衔接有误）"
            ));
        }
        let pv = ch
            .and_then(|c| c.get("prev"))
            .and_then(|s| s.as_str())
            .unwrap_or("");
        if pv != prev {
            return Err(format!("entry {want}: chain.prev 接不上（账本可能被外部改写）"));
        }
        if e.body.get("type").and_then(|x| x.as_str()) == Some(projection::T_GRANT) {
            last_grant = Some(e.id.clone());
        }
        prev = e.id.clone();
    }
    entries.extend(fresh);
    *cursor += cut as u64;
    Ok(last_grant)
}

/// 封卷后的归档目录（`.warrant/volumes/`）。
///
/// **[SEAL-2026-10-29]** 账本没有上界是已知缺口。封卷的做法**不是截断**，
/// 而是「把整卷挪走 + 新卷写一条继承 grant」：
/// 每卷自己完整可验，卷与卷之间用 `parents` 相连 —— **谱系不断，旧账仍可作证**。
pub const VOLUMES: &str = "volumes";

pub struct Store {
    dir: PathBuf,
    entries: Vec<ledger::Entry>,
    /// 签 **observation** 的钥匙（`admission.rs:20`：observation 的 declare 只认 verifier）
    verifier_key: SigningKey,
    /// 签 **claim** 的钥匙（`admission.rs:19`：claim 的 declare 只认 ai/human/service）。
    ///
    /// **为什么必须两把**：协议把「我看到」和「我声称」分成了两种身份 ——
    /// 一个进程想两件事都做，就得用两个身份，否则它在账本里分不清
    /// 「这是观测」还是「这是主张」。这不是限制，是**账本可读性的前提**。
    service_key: SigningKey,
    grant_id: String,
    capability: Value,
    /// 已解析到 `entries.jsonl` 的第几个字节。
    ///
    /// `[PERF-2026-10-29]` 增量读指针：写路径只续读「上次之后新增的字节」，
    /// 不再每次全量重读 ⇒ N 次写从 O(N²) 回到 O(1)。
    cursor: u64,
    /// 当前是否持锁（`[MULTI-WRITER-2026-10-27]`：只在写路径的一瞬间为 `Some`）
    lock: Option<LedgerLock>,
}

impl Store {
    /// 打开（或初始化）项目账本。
    ///
    /// **读之前先抢锁**（与 core 同一纪律 `warrant_ledger.rs:394`「先抢锁，再读任何东西」）：
    /// 否则可能读到另一个 warrantd 正在写的半行。持锁范围只到 `open` 返回 ——
    /// 因为 `[MULTI-WRITER-2026-10-27]`：常驻进程不能长期持锁。
    pub fn open(repo: &Path) -> Result<Self, String> {
        let dir = repo.join(crate::LEDGER_DIR);
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        // 先抢锁：**bootstrap 也必须在锁内**，否则两个进程同时 open 空账本会各写一条 grant ⇒ 链必坏。
        let lock = acquire_lock(&dir)?;
        let keys = dir.join("keys");
        std::fs::create_dir_all(&keys).map_err(|e| format!("create {}: {e}", keys.display()))?;
        let key = load_or_gen_key(&keys, "verifier")?;
        let service_key = load_or_gen_key(&keys, "service")?;
        let capability =
            warrant::json::parse(crate::CAPABILITY_JSON).map_err(|e| format!("capability: {e}"))?;

        let entries = read_entries(&dir)?;
        // 读指针 = 刚读到的字节位置；之后只续读新增部分
        let cursor = std::fs::metadata(dir.join("entries.jsonl"))
            .map(|m| m.len())
            .unwrap_or(0);
        let mut st = Self {
            dir,
            entries,
            verifier_key: key,
            service_key,
            grant_id: String::new(),
            capability,
            cursor,
            lock: Some(lock),
        };
        if st.entries.is_empty() {
            st.grant_id = st.bootstrap_grant()?;
        } else {
            st.grant_id = st.current_grant_id()?;
        }
        st.lock = None; // open 结束即放锁
        Ok(st)
    }

    /// 当前生效 grant = 账本里最后一笔 grant。
    fn current_grant_id(&self) -> Result<String, String> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.body.get("type").and_then(|x| x.as_str()) == Some(projection::T_GRANT))
            .map(|g| g.id.clone())
            .ok_or_else(|| "账本没有 grant（布局损坏）".to_string())
    }

    /// **写路径统一入口**：抢锁 → **重读** → 执行 → 放锁。
    ///
    /// 为什么必须重读：别的进程可能已经追加了若干条，不重读就会用过期 `seq` 算链位 ⇒ 链断。
    /// 链断不是「有点乱」，而是**整本账作废**（`verify_chain` 从 seq 0 起逐条对，错一位即全废）。
    fn with_write<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, String>) -> Result<T, String> {
        if self.lock.is_none() {
            self.lock = Some(acquire_lock(&self.dir)?);
            // [PERF-2026-10-29] 增量续读：账本没变就是 O(1)（原先每次全量重读 + 验链）
            if let Some(g) = refresh_entries(&self.dir, &mut self.entries, &mut self.cursor)? {
                self.grant_id = g;
            }
            if self.grant_id.is_empty() {
                self.grant_id = self.current_grant_id()?;
            }
        }
        let r = f(self);
        self.lock = None;
        r
    }

    /// 封卷前的累计条数（从当前卷首条 seal grant 的 `sealed_total` 读；首卷为 0）。
    ///
    /// `[SEAL-2026-10-29]` 它让 `offset` **跨卷单调**：封卷后 offset 不回退到 0，
    /// 否则 `warrant_since(offset)` 会把旧条目重复返回一遍。
    pub fn base_offset(&self) -> usize {
        self.entries
            .first()
            .and_then(|e| e.body.get("action"))
            .and_then(|a| a.get("args"))
            .and_then(|a| a.get("sealed_total"))
            .and_then(|x| x.as_int())
            .unwrap_or(0) as usize
    }

    /// 跨卷单调的逻辑序号 = 已封各卷条数 + 当前卷条数。
    ///
    /// 对外的 `offset` 一律用这个；`offset()` 保留为「当前卷内条数」供内部/测试用。
    pub fn logical_offset(&self) -> usize {
        self.base_offset() + self.entries.len()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn entries(&self) -> &[ledger::Entry] {
        &self.entries
    }

    /// 当前水位（= 已写条数）。消费者用 `since(offset)` 读自己没看过的部分。
    pub fn offset(&self) -> usize {
        self.entries.len()
    }

    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    pub fn verify(&self) -> Vec<String> {
        let mut errs = ledger::verify_chain(&self.entries);
        errs.extend(ledger::verify_signatures(&self.entries));
        errs
    }

    /// 封卷：把当前卷整体挪进 `volumes/`，然后在新卷写一条继承 grant。
    ///
    /// **[SEAL-2026-10-29]** 为什么不是「截断」：
    /// 链上的每条 id 都依赖它自己的 `chain.seq`，任何截断都会让保留下来的条目
    /// 全部 id 失效（等于伪造历史）。所以这里**只挪卷、不改条目**：
    ///
    /// ```text
    /// 旧卷：seq 0..N（原样不动，仍可独立验签）
    /// 新卷：seq 0 = 继承 grant，parents = [旧卷 head]   ← 谱系在这里接上
    ///       seq 1.. 后续条目
    /// ```
    ///
    /// 旧卷在新卷的 `action.args` 里被点名（卷名 + 条数 + head），
    /// 所以第三方拿到新卷就能知道「该去找哪一卷、该核对哪个 head」。
    pub fn seal(&mut self) -> Result<String, String> {
        let lock = acquire_lock(&self.dir)?;
        let r = (|this: &mut Self| {
            refresh_entries(&this.dir, &mut this.entries, &mut this.cursor)?;
            if this.entries.len() < 2 {
                return Err("账本不足 2 条，不需要封卷".to_string());
            }
            let head = this.entries.last().map(|e| e.id.clone()).unwrap_or_default();
            let count = this.entries.len();
            // 累计总数 = 此前已封各卷 + 本卷 ⇒ 跨卷单调，offset 不回退
            let total = this.base_offset() + count;
            let vol_name = format!("vol-{}.jsonl", crate::util::now_ms());
            let vol_dir = this.dir.join(VOLUMES);
            std::fs::create_dir_all(&vol_dir).map_err(|e| format!("create volumes: {e}"))?;
            // 原子改名：先挪走，再立新卷。中途崩了也只是「有卷无新卷」，不会丢条目。
            std::fs::rename(this.dir.join("entries.jsonl"), vol_dir.join(&vol_name))
                .map_err(|e| format!("move volume: {e}"))?;
            // 内存态归零（新卷从 seq 0 开始）
            this.entries.clear();
            this.cursor = 0;
            let id = this.seal_grant(&vol_name, count, total, &head)?;
            this.grant_id = id.clone();
            Ok(id)
        })(self);
        drop(lock);
        r
    }

    /// 新卷的首条：一条 grant —— 带上「我把哪一卷封了、它的 head 是什么」。
    ///
    /// 用 grant 而不是别的类型，是为了让后面的 claim 有一个**落在本卷内**的
    /// `authority.grant_id`（P2 要求它能解析到）。同时 `parents` 指向旧卷 head，
    /// 把谱系接上。
    fn seal_grant(
        &mut self,
        volume: &str,
        sealed: usize,
        total: usize,
        head: &str,
    ) -> Result<String, String> {
        let op = "user:local-operator";
        // grant 必填 nonce（admission STRUCT 会查）；带上被封面与条数，便于人工肉眼核对
        let nonce = format!("grant-seal-{}-{}-{}", sealed, crate::util::now_ms(), volume);
        let body = obj(vec![
            ("kind", s("claim")),
            ("type", s(projection::T_GRANT)),
            ("nonce", s(&nonce)),
            ("actor", obj(vec![("id", s(op)), ("kind", s("human"))])),
            (
                "subject",
                obj(vec![("id", s("org:local")), ("kind", s("warrant.org"))]),
            ),
            (
                "action",
                obj(vec![
                    ("verb", s("grant")),
                    (
                        "args",
                        obj(vec![
                            ("grantee", s(crate::SIGNER_ID)),
                            ("target", s("warrantd://workspace")),
                            (
                                "types",
                                arr(vec![
                                    s(projection::T_OBS),
                                    s(T_WORLD_CHANGE),
                                    s(T_AGENT_CLAIM),
                                    s(T_MCP_CALL),
                                ]),
                            ),
                            // 封卷坐标：第三方据此去找旧卷、核对 head
                            ("sealed_volume", s(volume)),
                            // sealed_count = 本卷条数；sealed_total = 含此前各卷的累计总数。
                            // offset 用它保持**跨卷单调**：封卷后 offset 不会回退到 0。
                            ("sealed_count", Value::Int(sealed as i64)),
                            ("sealed_total", Value::Int(total as i64)),
                            ("sealed_head", s(head)),
                        ]),
                    ),
                ]),
            ),
            ("expect", obj(vec![("grantee", s(crate::SIGNER_ID))])),
            // 谱系：新卷指着旧卷的最后一环
            ("parents", arr(vec![s(head)])),
            (
                "authority",
                obj(vec![
                    ("grant_id", s("")),
                    ("granted_by", s(op)),
                    ("kind", s("self")),
                ]),
            ),
            (
                "scope",
                obj(vec![
                    ("valid_within", arr(vec![s("org:local")])),
                    ("valid_across", arr(vec![])),
                ]),
            ),
            (
                "horizon",
                obj(vec![
                    ("issued_at", s(&now_rfc3339())),
                    ("expires_at", s(&plus_days_rfc3339(3650))),
                ]),
            ),
        ]);
        self.append_locked(body, None)
    }

    /// 首条 grant：操作员语义，**零签名自举**（与 `warrant_ledger::bootstrap_grant` 同形态）。
    /// 它不是 AI 自我扩权 —— 它的 `authority.kind = self`、`granted_by = user:local-operator`。
    fn bootstrap_grant(&mut self) -> Result<String, String> {
        let op = "user:local-operator";
        let nonce = format!("grant-warrantd-bootstrap-{}", crate::util::now_ms());
        let now = now_rfc3339();
        let body = obj(vec![
            ("kind", s("claim")),
            ("type", s(projection::T_GRANT)),
            ("actor", obj(vec![("id", s(op)), ("kind", s("human"))])),
            ("subject", obj(vec![("id", s("org:local")), ("kind", s("warrant.org"))])),
            (
                "action",
                obj(vec![
                    ("verb", s("grant")),
                    (
                        "args",
                        obj(vec![
                            ("grantee", s(crate::SIGNER_ID)),
                            ("target", s("warrantd://workspace")),
                            (
                                "types",
                                arr(vec![
                                    s(projection::T_OBS),
                                    s(T_WORLD_CHANGE),
                                    s(T_AGENT_CLAIM),
                                    s(T_MCP_CALL),
                                ]),
                            ),
                        ]),
                    ),
                ]),
            ),
            ("expect", obj(vec![("grantee", s(crate::SIGNER_ID))])),
            (
                "authority",
                obj(vec![
                    ("grant_id", s("")),
                    ("granted_by", s(op)),
                    ("kind", s("self")),
                ]),
            ),
            (
                "scope",
                obj(vec![
                    ("valid_within", arr(vec![s("org:local")])),
                    ("valid_across", arr(vec![])),
                ]),
            ),
            (
                "horizon",
                obj(vec![
                    ("issued_at", s(&now)),
                    ("expires_at", s(&plus_days_rfc3339(365))),
                ]),
            ),
            ("parents", arr(vec![s(&nonce)])),
            ("nonce", s(&nonce)),
        ]);
        self.append_locked(body, None)
    }

    /// 追加一条。`signer = None` 只用于 grant 自举（操作员语义，零签名）。
    ///
    /// 签名身份**必须显式给出**（`(key, signer_id, signer_kind)`）——不能在这里"默认用某把钥匙"：
    /// 默认值会让 observation 和 claim 用错身份，而 P3 的拒绝发生在**写入之后**才发现的话
    /// 就已经污了账本。显式传参让编译期就逼你想清楚"这条是谁说的"。
    fn append_locked(
        &mut self,
        body: Value,
        signer: Option<(&SigningKey, &str, &str)>,
    ) -> Result<String, String> {
        let seq = self.entries.len() as i64;
        let prev = self.entries.last().map(|e| e.id.clone()).unwrap_or_default();
        let mut pairs = match body {
            Value::Object(p) => p,
            _ => return Err("条目 body 必须是对象".to_string()),
        };
        pairs.push(("chain".to_string(), ledger::chain_body(seq, &prev)));
        let body = Value::Object(pairs);
        let id = canon::event_id(&body).map_err(|e| format!("event_id: {e}"))?;
        let signatures = match signer {
            Some((k, sid, skind)) => vec![sign_with(k, &id, &now_rfc3339(), sid, skind)],
            None => vec![],
        };
        let env = Value::Object(vec![
            ("spec".to_string(), s(ledger::SPEC)),
            ("id".to_string(), s(&id)),
            ("body".to_string(), body),
            ("signatures".to_string(), Value::Array(signatures)),
        ]);
        let entry = ledger::entry_from_value(&env).ok_or_else(|| "信封无效".to_string())?;
        let errs = admission::admission_errors(&entry, &self.entries, Some(&self.capability));
        if !errs.is_empty() {
            return Err(format!("admission 拒绝：{}", errs.join("; ")));
        }
        let mut bytes = canon::canonical_bytes(&env).map_err(|e| format!("canonical: {e}"))?;
        bytes.push(b'\n');
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("entries.jsonl"))
            .map_err(|e| format!("open entries: {e}"))?;
        f.write_all(&bytes).map_err(|e| format!("append entries: {e}"))?;
        // 自己写的那条也要推进读指针，否则下次续读会把它当「新增」再解析一遍（重复条目）
        self.cursor += bytes.len() as u64;
        self.entries.push(entry);
        Ok(id)
    }

    /// 写一条观测（`kind = observation`，由 verifier 签）。
    ///
    /// `subject` = 被观测的那条 claim 的 id；世界扫描类观测传 [`crate::store::Store::append_world_change`]
    /// 产出的 claim id。
    pub fn append_observation(&mut self, ob: &Observed, subject: &str) -> Result<String, String> {
        let ob = ob.clone();
        let subject = subject.to_string();
        self.with_write(move |s| s.append_observation_locked(&ob, &subject))
    }

    /// 内部实现：**假定已持锁**（由 [`Self::with_write`] 保证）。
    fn append_observation_locked(&mut self, ob: &Observed, subject: &str) -> Result<String, String> {
        let nonce = crate::util::nonce_for("warrantd:obs", &[&ob.method, &ob.observed_at, subject]);
        let now = now_rfc3339();
        let body = obj(vec![
            ("kind", s("observation")),
            ("type", s(projection::T_OBS)),
            (
                "actor",
                obj(vec![("id", s(crate::SIGNER_ID)), ("kind", s(crate::SIGNER_KIND))]),
            ),
            ("subject", obj(vec![("id", s(subject)), ("kind", s("warrant.entry"))])),
            (
                "observation",
                obj(vec![
                    ("channel", s(&ob.channel)),
                    ("tier", s(&ob.tier)),
                    // 真实上限（元数据，**不参与判定**）：不虚报，但也不丢失信息
                    ("tier_hint", s(&ob.tier_hint)),
                    ("method", s(&ob.method)),
                    ("result", ob.result.clone()),
                    ("evidence", crate::probe::evidence_json(&ob.evidence)),
                    ("observed_at", s(&ob.observed_at)),
                    ("self_side_effects", crate::probe::evidence_json(&ob.self_side_effects)),
                ]),
            ),
            (
                "horizon",
                obj(vec![
                    ("issued_at", s(&now)),
                    ("expires_at", s(&plus_days_rfc3339(365))),
                ]),
            ),
            // SPEC §2.4 必填（admission.rs:318）：observation 也要 parents
            ("parents", arr(vec![s(subject)])),
            ("nonce", s(&nonce)),
        ]);
        // observation 只认 verifier（admission.rs:20）。
        // 先把钥匙取到局部：append 要 &mut self，不能同时持有 self 的不可变借用。
        let k = self.verifier_key.clone();
        self.append_locked(body, Some((&k, crate::SIGNER_ID, crate::SIGNER_KIND)))
    }
    ///
    /// 它回答的是：「在我盯着的范围内，世界变了这些」。**不判定谁改的** ——
    /// 归因留给切片②（与账本里已有的 claim 对照）。
    /// 写一条「世界变更」claim。
    ///
    /// `window_from` / `window_to` = **这条记录覆盖的时间窗**（上一次巡边完成 → 这一次巡边完成）。
    /// [WINDOW-2026-10-28] 为什么要记它：变化发生在这个窗**内的某一刻，但不知道是哪一刻**。
    /// 把窗记下来，「你看到的东西有多旧」就从"感觉"变成**可查询的事实**：
    /// 窗宽 = 采样间隔，`now - window_to` = 观测延迟。两者都不再是界面上一行字。
    ///
    /// `event_counts`：本窗口内每个路径被文件事件碰了几次（`[JITTER-2026-10-29]`）。
    /// 快照差分只知道「最后长什么样」；计数把「改了一次」和「改了 17 次」分开 ——
    /// 后者通常意味着在反复试错，这个信息对读账本的人很值钱。
    /// 传空 map = 没有 watcher（`once` 等一次性调用），行为与以前完全一致。
    pub fn append_world_change(
        &mut self,
        changes: &[Change],
        scanned: usize,
        window_from: &str,
        window_to: &str,
        event_counts: &std::collections::HashMap<String, usize>,
    ) -> Result<String, String> {
        let changes = changes.to_vec();
        let wf = window_from.to_string();
        let wt = window_to.to_string();
        let counts = event_counts.clone();
        self.with_write(move |s| {
            s.append_world_change_locked(&changes, scanned, &wf, &wt, &counts)
        })
    }

    /// 内部实现：**假定已持锁**。
    fn append_world_change_locked(
        &mut self,
        changes: &[Change],
        scanned: usize,
        window_from: &str,
        window_to: &str,
        event_counts: &std::collections::HashMap<String, usize>,
    ) -> Result<String, String> {
        let count = changes.len() as i64;
        let nonce = crate::util::nonce_for(
            "warrantd:world",
            &[&changes.first().map(|c| c.path.clone()).unwrap_or_default(), &now_rfc3339()],
        );
        let now = now_rfc3339();
        let body = obj(vec![
            ("kind", s("claim")),
            ("type", s(T_WORLD_CHANGE)),
            (
                "actor",
                obj(vec![
                    ("id", s(crate::SERVICE_SIGNER_ID)),
                    ("kind", s(crate::SERVICE_SIGNER_KIND)),
                ]),
            ),
            (
                "subject",
                obj(vec![("id", s("world:workspace")), ("kind", s("warrant.world"))]),
            ),
            (
                "action",
                obj(vec![
                    ("verb", s("observe")),
                    (
                        "args",
                        obj(vec![
                            ("count", Value::Int(count)),
                            ("scanned", Value::Int(scanned as i64)),
                            // 这条记录覆盖的时间窗（首扫时 from 为空 = 无基线）
                            ("window_from", s(window_from)),
                            ("window_to", s(window_to)),
                            // 抖动次数：只在有 watcher 时非空
                            (
                                "event_counts",
                                Value::Object(
                                    event_counts
                                        .iter()
                                        .map(|(k, v)| (k.clone(), Value::Int(*v as i64)))
                                        .collect(),
                                ),
                            ),
                            ("changes", crate::snapshot::changes_json(changes)),
                        ]),
                    ),
                ]),
            ),
            // P1：expect 的每个叶子都必须能在 action.args 里找到
            (
                "expect",
                obj(vec![
                    ("count", Value::Int(count)),
                    ("scanned", Value::Int(scanned as i64)),
                ]),
            ),
            (
                "authority",
                obj(vec![
                    ("grant_id", s(&self.grant_id)),
                    ("granted_by", s("user:local-operator")),
                    ("kind", s("self")),
                ]),
            ),
            (
                "scope",
                obj(vec![
                    ("valid_within", arr(vec![s("org:local")])),
                    ("valid_across", arr(vec![])),
                ]),
            ),
            (
                "horizon",
                obj(vec![
                    ("issued_at", s(&now)),
                    ("expires_at", s(&plus_days_rfc3339(365))),
                ]),
            ),
            ("parents", arr(vec![])),
            ("nonce", s(&nonce)),
        ]);
        // claim 只认 ai/human/service（admission.rs:19）⇒ 用 service 身份
        // claim 只认 ai/human/service（admission.rs:19）⇒ service 身份。
        // 钥匙取到局部：append 要 &mut self。
        let k = self.service_key.clone();
        self.append_locked(
            body,
            Some((&k, crate::SERVICE_SIGNER_ID, crate::SERVICE_SIGNER_KIND)),
        )
    }

    /// agent 申报：「我把 `<path>` 改成了 `<expect_hash>`」。
    ///
    /// 这是抗黑盒的**前提**：切片①要有「说」才能和「看」对账。
    /// 自愿的 —— 所以只在被声明的范围内必抗黑盒；范围外的由切片②兜（标成「未申报」）。
    pub fn append_agent_claim(
        &mut self,
        actor: &str,
        path: &str,
        expect_hash: &str,
    ) -> Result<String, String> {
        let actor = actor.to_string();
        let path = path.to_string();
        let expect_hash = expect_hash.to_string();
        self.with_write(move |s| s.append_agent_claim_locked(&actor, &path, &expect_hash))
    }

    /// 内部实现：**假定已持锁**。
    fn append_agent_claim_locked(
        &mut self,
        actor: &str,
        path: &str,
        expect_hash: &str,
    ) -> Result<String, String> {
        let nonce = crate::util::nonce_for("warrantd:claim", &[actor, path, expect_hash]);
        let now = now_rfc3339();
        let body = obj(vec![
            ("kind", s("claim")),
            ("type", s(T_AGENT_CLAIM)),
            // **不冒充**：签名身份是 service:warrantd，所以 actor 也必须是它。
            // 原申报者记在 `action.args.delegated_to` —— 账本里能一眼看出「这条是代记的」。
            (
                "actor",
                obj(vec![
                    ("id", s(crate::SERVICE_SIGNER_ID)),
                    ("kind", s(crate::SERVICE_SIGNER_KIND)),
                ]),
            ),
            ("subject", obj(vec![("id", s(path)), ("kind", s("warrant.path"))])),
            // P1（`admission.rs:82`）：expect 的每个叶子都必须能在 action.args 里找到。
            // **形状刻意做成 `{路径: 哈希}`** —— 与 `probe::run_fs_hash` 的 result 同形，
            // 这样「agent 说 X=H」与「daemon 看到 X=H」能直接用 `projection::compare` 比对，
            // 不需要任何翻译层（翻译层是判据分叉的温床）。
            (
                "action",
                obj(vec![
                    ("verb", s("write")),
                    ("delegated_to", s(actor)),
                    ("args", obj(vec![(path, s(expect_hash))])),
                ]),
            ),
            ("expect", obj(vec![(path, s(expect_hash))])),
            (
                "authority",
                obj(vec![
                    ("grant_id", s(&self.grant_id)),
                    ("granted_by", s("user:local-operator")),
                    ("kind", s("self")),
                ]),
            ),
            (
                "scope",
                obj(vec![
                    ("valid_within", arr(vec![s("org:local")])),
                    ("valid_across", arr(vec![])),
                ]),
            ),
            (
                "horizon",
                obj(vec![
                    ("issued_at", s(&now)),
                    ("expires_at", s(&plus_days_rfc3339(30))),
                ]),
            ),
            ("parents", arr(vec![])),
            ("nonce", s(&nonce)),
        ]);
        // claim 只认 ai/human/service（admission.rs:19）⇒ service 身份。
        // 钥匙取到局部：append 要 &mut self。
        let k = self.service_key.clone();
        self.append_locked(
            body,
            Some((&k, crate::SERVICE_SIGNER_ID, crate::SERVICE_SIGNER_KIND)),
        )
    }

    /// **观测申报的来源标注**（`actor.kind = service`）：让「谁写的」在账本里可辨。
    ///
    /// 这一步不改判定，只是把 `SPEC.md:71` 预留但从未使用的 `service` 值用起来。
    pub fn signer_json(&self) -> Value {
        obj(vec![
            ("id", s(crate::SIGNER_ID)),
            ("kind", s(crate::SIGNER_KIND)),
        ])
    }

    /// 记一次**被代理的 MCP 工具调用**（洞②）。
    ///
    /// 只记**参数键名不记值**：值里可能有密钥、客户数据、大段文件内容，
    /// 而"这次调用动了哪几个参数"已经足够回答「AI 通过 MCP 干了什么」。
    pub fn append_mcp_call(
        &mut self,
        server: &str,
        tool: &str,
        rpc_id: &str,
        args_keys: &[String],
        line_bytes: usize,
        degraded: bool,
    ) -> Result<String, String> {
        let server = server.to_string();
        let tool = tool.to_string();
        let rpc_id = rpc_id.to_string();
        let keys = args_keys.to_vec();
        self.with_write(move |s| {
            s.append_mcp_call_locked(&server, &tool, &rpc_id, &keys, line_bytes, degraded)
        })
    }

    fn append_mcp_call_locked(
        &mut self,
        server: &str,
        tool: &str,
        rpc_id: &str,
        args_keys: &[String],
        line_bytes: usize,
        degraded: bool,
    ) -> Result<String, String> {
        // MCP 调用是**事件**不是幂等操作 ⇒ nonce 带毫秒，不去重
        let nonce = format!(
            "warrantd:mcp:{}:{}:{}:{}",
            server,
            tool,
            rpc_id,
            crate::util::now_ms()
        );
        let now = now_rfc3339();
        let keys_arr = arr(args_keys.iter().map(|k| s(k)).collect());
        let subject = format!("mcp://{server}/{tool}");
        let body = obj(vec![
            ("kind", s("claim")),
            ("type", s(T_MCP_CALL)),
            (
                "actor",
                obj(vec![
                    ("id", s(crate::SERVICE_SIGNER_ID)),
                    ("kind", s(crate::SERVICE_SIGNER_KIND)),
                ]),
            ),
            ("subject", obj(vec![("id", s(&subject)), ("kind", s("warrant.mcp"))])),
            (
                "action",
                obj(vec![
                    ("verb", s("call")),
                    (
                        "args",
                        obj(vec![
                            ("server", s(server)),
                            ("tool", s(tool)),
                            ("rpc_id", s(rpc_id)),
                            ("args_keys", keys_arr),
                            ("line_bytes", Value::Int(line_bytes as i64)),
                            // 解析退化过就如实标 —— 不冒充精确
                            ("degraded", Value::Bool(degraded)),
                        ]),
                    ),
                ]),
            ),
            // P1：expect 的每个叶子都必须能在 action.args 里找到
            ("expect", obj(vec![("server", s(server)), ("tool", s(tool))])),
            (
                "authority",
                obj(vec![
                    ("grant_id", s(&self.grant_id)),
                    ("granted_by", s("user:local-operator")),
                    ("kind", s("self")),
                ]),
            ),
            (
                "scope",
                obj(vec![
                    ("valid_within", arr(vec![s("org:local")])),
                    ("valid_across", arr(vec![])),
                ]),
            ),
            (
                "horizon",
                obj(vec![
                    ("issued_at", s(&now)),
                    ("expires_at", s(&plus_days_rfc3339(30))),
                ]),
            ),
            ("parents", arr(vec![])),
            ("nonce", s(&nonce)),
        ]);
        let k = self.service_key.clone();
        self.append_locked(
            body,
            Some((&k, crate::SERVICE_SIGNER_ID, crate::SERVICE_SIGNER_KIND)),
        )
    }

    /// 记对应的**响应**（观测）：这次调用成功了没有、回了多大一坨。
    pub fn append_mcp_result(&mut self, claim_id: &str, ok: bool, bytes: usize) -> Result<String, String> {
        let claim_id = claim_id.to_string();
        self.with_write(move |s| s.append_mcp_result_locked(&claim_id, ok, bytes))
    }

    fn append_mcp_result_locked(
        &mut self,
        claim_id: &str,
        ok: bool,
        bytes: usize,
    ) -> Result<String, String> {
        let nonce = format!("warrantd:mcpres:{}:{}", claim_id, crate::util::now_ms());
        let now = now_rfc3339();
        let body = obj(vec![
            ("kind", s("observation")),
            ("type", s(projection::T_OBS)),
            (
                "actor",
                obj(vec![("id", s(crate::SIGNER_ID)), ("kind", s(crate::SIGNER_KIND))]),
            ),
            ("subject", obj(vec![("id", s(claim_id)), ("kind", s("warrant.entry"))])),
            (
                "observation",
                obj(vec![
                    ("channel", s(crate::CHANNEL)),
                    ("tier", s(crate::DECLARED_TIER)),
                    ("tier_hint", s("C1")),
                    ("method", s("mcp.proxy")),
                    (
                        "result",
                        obj(vec![
                            ("ok", Value::Bool(ok)),
                            ("response_bytes", Value::Int(bytes as i64)),
                        ]),
                    ),
                    ("observed_at", s(&now)),
                    (
                        "evidence",
                        arr(vec![s("warrantd proxy 亲眼看到的那一帧响应（旁路记录，未改写）")]),
                    ),
                    ("self_side_effects", arr(vec![])),
                ]),
            ),
            (
                "horizon",
                obj(vec![
                    ("issued_at", s(&now)),
                    ("expires_at", s(&plus_days_rfc3339(30))),
                ]),
            ),
            ("parents", arr(vec![s(claim_id)])),
            ("nonce", s(&nonce)),
        ]);
        let k = self.verifier_key.clone();
        self.append_locked(body, Some((&k, crate::SIGNER_ID, crate::SIGNER_KIND)))
    }
}

fn load_or_gen_key(dir: &Path, name: &str) -> Result<SigningKey, String> {
    let p = dir.join(format!("{name}.key"));
    if p.exists() {
        let text = std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
        let bytes = decode_hex(text.trim()).ok_or_else(|| format!("{}: hex 非法", p.display()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("{}: 密钥必须是 32 字节", p.display()))?;
        Ok(SigningKey::from_bytes(&arr))
    } else {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| format!("getrandom: {e}"))?;
        std::fs::write(&p, canon::hex(&seed)).map_err(|e| format!("write {}: {e}", p.display()))?;
        Ok(SigningKey::from_bytes(&seed))
    }
}

fn sign_with(key: &SigningKey, entry_id: &str, at: &str, signer_id: &str, signer_kind: &str) -> Value {
    let payload = canon::sig_payload(entry_id, "declare", signer_id, at);
    let bytes = canon::sig_bytes(&payload).expect("sig payload 必须可规范序列化");
    let sig = key.sign(&bytes);
    obj(vec![
        ("alg", s("ed25519")),
        ("key_id", s(&format!("ed25519:{}", canon::hex(&key.verifying_key().to_bytes())))),
        ("over", s(entry_id)),
        ("role", s("declare")),
        ("sig", s(&b64url(&sig.to_bytes()))),
        ("signed_at", s(at)),
        ("signer", obj(vec![("id", s(signer_id)), ("kind", s(signer_kind))])),
    ])
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// base64url（无填充）—— 与 `crates/core/src/warrant_ledger.rs` 的 `b64url` 同一形态。
fn b64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_repo(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("warrantd-store-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn bootstrap_grant_then_observation_is_chained_and_signed() {
        let repo = tmp_repo("obs");
        let mut st = Store::open(&repo).unwrap();
        assert_eq!(st.offset(), 1, "首开必须只有 bootstrap grant");
        let gid = st.grant_id().to_string();
        assert!(!gid.is_empty());

        let ob = Observed {
            method: "fs.hash".into(),
            tier: "C1".into(),
            tier_hint: "C2".into(),
            channel: crate::CHANNEL.into(),
            observed_at: now_rfc3339(),
            result: obj(vec![("a.rs", s("sha256:"))]),
            evidence: vec!["a.rs".into()],
            self_side_effects: vec![],
        };
        let oid = st.append_observation(&ob, &gid).unwrap();
        assert!(oid.starts_with("sha256:"));
        assert_eq!(st.offset(), 2);
        assert!(st.verify().is_empty(), "链与签名必须都过：{:?}", st.verify());

        // 重开：能从盘上读回、能验、grant 仍指向同一个
        let st2 = Store::open(&repo).unwrap();
        assert_eq!(st2.offset(), 2);
        assert_eq!(st2.grant_id(), gid);
        assert!(st2.verify().is_empty());
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn world_change_claim_satisfies_admission() {
        let repo = tmp_repo("world");
        let mut st = Store::open(&repo).unwrap();
        let changes = vec![Change {
            path: "src/a.rs".into(),
            kind: crate::snapshot::ChangeKind::Modified,
            from: Some("sha256:1".into()),
            to: Some("sha256:2".into()),
        }];
        let id = st.append_world_change(&changes, 10, "", "2026-10-28T00:00:00Z", &Default::default()).unwrap();
        assert!(id.starts_with("sha256:"));
        assert!(st.verify().is_empty());
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn agent_claim_requires_no_human_and_lands() {
        let repo = tmp_repo("claim");
        let mut st = Store::open(&repo).unwrap();
        let id = st
            .append_agent_claim("agent:claude-code", "src/a.rs", "sha256:abc")
            .unwrap();
        assert!(id.starts_with("sha256:"));
        assert!(st.verify().is_empty());
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn tampered_ledger_is_refused_not_silently_accepted() {
        let repo = tmp_repo("tamper");
        {
            let mut st = Store::open(&repo).unwrap();
            let _ = st.append_agent_claim("agent:x", "a.rs", "sha256:1").unwrap();
        }
        let p = repo.join(crate::LEDGER_DIR).join("entries.jsonl");
        let text = std::fs::read_to_string(&p).unwrap();
        // 改一个字节（把 last id 里的一个字符改掉）
        let tampered = text.replacen("sha256:", "sha256:0", 2);
        std::fs::write(&p, tampered).unwrap();
        // Store 不实现 Debug（内部持有私钥，**刻意不 derive**）⇒ 用 match 取错误串
        let e = match Store::open(&repo) {
            Ok(_) => panic!("篡改必须被发现，但账本被静默接受了"),
            Err(e) => e,
        };
        assert!(e.contains("不连续") || e.contains("tamper") || e.contains("无效"), "{e}");
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn b64url_has_no_padding_and_is_url_safe() {
        let x = b64url(&[0u8, 255, 254]);
        assert!(!x.contains('='));
        assert!(!x.contains('+') && !x.contains('/'), "{x}");
    }

    /// **[MULTI-WRITER-2026-10-27] 核心钉子**：两个「主体」交替写，链必须不断。
    ///
    /// 这条测试的意义：它是「多 agent 共享同一本账」成立的最小证明。
    /// 如果 `with_write` 不重读，`b` 会拿 `open` 时的旧 `seq` 去算链位 ⇒ 与 `a` 的条目撞号 ⇒ 链断。
    /// 链断不是「有点乱」，是**整本账作废**。
    /// **[SEAL-2026-10-29] 封卷后：谱系不断、新卷仍能写、全卷可验。**
    ///
    /// 这条钉子守的是「选项 A」的核心承诺 —— **归档之后旧账仍然可作证**。
    /// 判据有三：新卷首条的 `parents` 指向旧卷 head；封卷后写入照常；
    /// `verify_all` 能同时验两卷并核对谱系。
    #[test]
    fn seal_keeps_lineage_and_ledger_keeps_working() {
        let repo = tmp_repo("seal");
        let mut st = Store::open(&repo).unwrap();
        for i in 0..5 {
            st.append_agent_claim("agent:x", &format!("f{i}.rs"), "sha256:y")
                .unwrap();
        }
        assert_eq!(st.offset(), 6, "grant + 5 条 claim");
        let old_head = st.entries().last().unwrap().id.clone();

        let seal_id = st.seal().unwrap();
        assert_eq!(st.offset(), 1, "新卷只有首条 grant");
        assert_eq!(st.entries()[0].id, seal_id);

        // 谱系：新卷首条的 parents 必须指向旧卷 head
        let parents = st.entries()[0]
            .body
            .get("parents")
            .and_then(|p| p.as_array())
            .map(|a| a.to_vec())
            .unwrap_or_default();
        assert!(
            parents.iter().any(|x| x.as_str() == Some(old_head.as_str())),
            "新卷首条的 parents 必须指向旧卷 head，否则谱系断了"
        );

        // 封卷后照常写
        st.append_agent_claim("agent:x", "after.rs", "sha256:z")
            .unwrap();
        assert_eq!(st.offset(), 2);

        // 全卷验证：两卷都在，链与谱系都过
        let (list, errs) = verify_all(&repo).unwrap();
        assert_eq!(list.len(), 2, "一卷归档 + 一卷当前，实得 {list:?}");
        assert!(errs.is_empty(), "全卷验证不该有错：{errs:?}");
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// **[PERF-2026-10-29] 增量读的正确性钉：别的 handle 写进来的条目必须被看见。**
    ///
    /// 这条是 O(1) 优化的护栏。增量续读的收益来自「不重读历史」，
    /// 代价是**必须保证不漏读别人写的新条目** —— 漏了就会用过期 `seq` 算链位，链必断。
    ///
    /// 场景：A 打开 → B 打开并写一条 → A 再写。A 若只看自己的内存，就会撞 seq。
    #[test]
    fn incremental_read_sees_entries_from_another_handle() {
        let repo = tmp_repo("incr");
        let mut a = Store::open(&repo).unwrap();
        a.append_agent_claim("agent:a", "a.rs", "sha256:1").unwrap();

        // 第二个 handle 模拟另一个进程：它写完之后 A 的内存快照就过期了
        let mut b = Store::open(&repo).unwrap();
        b.append_agent_claim("agent:b", "b.rs", "sha256:2").unwrap();

        // A 再写：必须续读到 b 那条，否则 seq 会撞
        a.append_agent_claim("agent:c", "c.rs", "sha256:3").unwrap();

        let v = Store::open(&repo).unwrap();
        assert_eq!(v.offset(), 4, "grant + 三条 claim");
        assert!(v.verify().is_empty(), "增量读之后链仍必须完整：{:?}", v.verify());
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// **[PERF-2026-10-29] 账本规模 vs 写入/打开耗时 —— 回答「会不会爆炸」必须靠数，不靠感觉。**
    ///
    /// `#[ignore]`：默认不跑（会花几秒），手动：`cargo test -p warrantd -- --ignored --nocapture`
    ///
    /// 关键怀疑点：`with_write` 每次写入都**重读整个账本**（并发正确性要求）
    /// ⇒ 写 N 条是 O(N²)，不是 O(N)。这条测试把曲线打出来。
    #[test]
    #[ignore]
    fn measure_scaling_with_ledger_size() {
        let repo = tmp_repo("perf");
        // **累积**而不是每轮清空：要测的正是「账本越大越慢」这条曲线
        for n in [10usize, 20, 40, 80] {
            let mut st = Store::open(&repo).unwrap();
            let before = st.offset();
            let t = std::time::Instant::now();
            for i in 0..n {
                st.append_agent_claim("agent:perf", &format!("f{i}.rs"), "sha256:x")
                    .unwrap();
            }
            let write_ms = t.elapsed().as_millis();

            let t2 = std::time::Instant::now();
            let st2 = Store::open(&repo).unwrap();
            let open_ms = t2.elapsed().as_millis();

            println!(
                "账本 {}→{} 条：追加 {n:>3} 条花 {write_ms:>5} ms（{:.2} ms/条）｜open 花 {open_ms:>4} ms",
                before,
                st2.offset(),
                write_ms as f64 / n as f64
            );
        }
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn two_writers_alternating_keep_chain_intact() {
        let repo = tmp_repo("multi");
        let mut a = Store::open(&repo).unwrap();
        // 第二个 open 必须能拿到锁 —— 证明 open 是短持，不是进程级长期持锁
        let mut b = Store::open(&repo).unwrap();
        a.append_agent_claim("agent:a", "x.rs", "sha256:1").unwrap();
        b.append_agent_claim("agent:b", "y.rs", "sha256:2").unwrap();
        a.append_agent_claim("agent:a", "z.rs", "sha256:3").unwrap();
        b.append_world_change(&[], 0, "", "2026-10-28T00:00:01Z", &Default::default()).unwrap();

        let st = Store::open(&repo).unwrap();
        assert!(st.verify().is_empty(), "链/签名必须都过：{:?}", st.verify());
        assert_eq!(st.offset(), 5, "grant + 3 claims + 1 world change");
        // 两条 agent claim 都要在，且 seq 连续（3 表示中间没被吃掉）
        let seqs: Vec<i64> = st
            .entries()
            .iter()
            .map(|e| e.body.get("chain").and_then(|c| c.get("seq")).and_then(|x| x.as_int()).unwrap_or(-1))
            .collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4], "链位必须连续：{seqs:?}");
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// 持锁期间，第二个写者拿不到锁 —— 且错误信息必须说人话（说清后果与修法）。
    #[cfg(windows)]
    #[test]
    fn lock_is_exclusive_and_error_is_actionable() {
        let repo = tmp_repo("lock");
        let dir = repo.join(crate::LEDGER_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        let held = acquire_lock(&dir).unwrap();
        let e = match acquire_lock(&dir) {
            Ok(_) => panic!("持锁期间第二个写者必须失败"),
            Err(e) => e,
        };
        assert!(e.contains("占用"), "错误要说清是什么占着：{e}");
        assert!(e.contains("entries.lock"), "错误要给出修法：{e}");
        drop(held);
        // 释放后立刻可再拿（说明 Drop 真的放了）
        let _again = acquire_lock(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&repo);
    }
}
