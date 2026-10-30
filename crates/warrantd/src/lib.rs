//! warrantd —— 常驻观测者与账本（独立于任何智能体）
//!
//! **它是什么**：一个不隶属于任何智能体的第三方进程。它持续观测世界、把观测写进
//! **项目内的账本**（`<repo>/.warrant/entries.jsonl`），并提供三种切片给任何消费者查。
//!
//! **为什么必须常驻**（`kb/信使独立化-常驻第三方-抗黑盒与滞后-讨论纪要-2026-10-27.md`）：
//! - 抗黑盒 = 「看」与「说」的差 ⇒ 需要 observation；
//! - 抗滞后 = 「看」的时间序列 + 读者水位 ⇒ **不需要任何 agent 配合**；
//! - 两者共用同一条「看」⇒ 一条世界流、三种切片。
//!
//! **依赖纪律**：本 crate 只依赖 `warrant`（判定内核）与通用基础库，
//! **禁止 import 任何执行层 crate**（core / tools / mcp / ...）。
//! 这不是洁癖：warrantd 要被 ZeroPage 之外的智能体使用，拖进引擎就等于把它变成 ZeroPage 的配件。
//! 反向检查：`cargo tree -p warrantd | grep -c " core "` 应为 0。
//!
//! **不被信任原则**（`crates/warrant/ADAPTER.md:23`）：「适配器不被信任——它和被控软件一样会撒谎」。
//! warrantd 自己也是被控对象 —— 所以：
//! ① 它只能用**封闭白名单**里的方式看世界（`probe::WHITELIST`）；
//! ② 它自己的副作用必须申报（`Observed::self_side_effects`）；
//! ③ 它只说结论，不下 verdict —— 比对交给 `warrant::projection::compare`。

pub mod admit;
pub mod mcp;
pub mod probe;
pub mod proxy;
pub mod root;
pub mod slices;
pub mod snapshot;
pub mod store;
pub mod sweep;
pub mod ui;
pub mod util;
pub mod watch;

/// 观测白名单的契约版本：**新增/删除原语、改档位必须升号**（与 `RULESET_VERSION` 同一纪律）。
pub const PROBE_SPEC_VERSION: &str = "warrantd.probe/1";

/// 账本目录（相对项目根）。
pub const LEDGER_DIR: &str = ".warrant";

/// 当前卷超过这么多条就**自动封卷**（[SEAL-2026-10-29]）。
///
/// 为什么是 5000：一条约 1.2 KB ⇒ 一卷约 6 MB；`open` 全量读约 0.34 ms/条 ⇒ 单次 ≈ 1.7 秒。
/// 再往上就明显影响每轮巡边了。封卷不删数据（挪进 `volumes/`），只是让「当前卷」保持小。
pub const SEAL_AFTER: usize = 5000;

/// 本 daemon 的记账身份。观测条目必须由 `verifier` 签
/// （`crates/warrant/src/admission.rs:20`：`("observation","declare") => ["verifier"]`）。
pub const SIGNER_ID: &str = "verifier:warrantd";
pub const SIGNER_KIND: &str = "verifier";

/// **申报**身份（`kind = claim`）。与观测身份**必须分开**：
/// `admission.rs:19-20` 规定 `claim/declare` 只认 ai/human/service，`observation/declare` 只认 verifier。
/// 一个进程扮演两个角色，就得有两把密钥、两个身份 —— 账本里才分得清「我看到」和「我声称」。
pub const SERVICE_SIGNER_ID: &str = "service:warrantd";
pub const SERVICE_SIGNER_KIND: &str = "service";

/// 观测写入的通道名。**必须沿用 `warrant::rank::axis_of_channel` 认识的名字**，
/// 否则观测**不产轴**（`rank.rs:122`「未知通道一律 None —— 堵编个名字就白得一根轴」）。
///
/// 语义核对：甲轴 = 「我方独立（新进程读回 / 离线复算）」。warrantd 起新进程读真实文件、
/// 跑 git、跑测试 —— 正是甲轴的定义。**它不是乙轴**：乙轴是「被控软件自己报的」。
pub const CHANNEL: &str = "proc_spawn_readback";

/// 申报档位：**保守取 C1**。
///
/// 为什么不按每条原语的"真实上限"分别申报：`admission.rs:217-253`（P5）要求
/// `observation.tier` **逐字等于** capability 里该 channel 申报的 tier ⇒ 一个 channel 只能有一个档。
/// `ADAPTER.md:47` 原文「**低报允许，高报致命**」⇒ 全表报 C1（认定门槛 `tier ≥ C1` 已满足）。
/// 各原语的真实上限另记在 `observation.tier_hint`（元数据，**不参与判定**），不虚报。
pub const DECLARED_TIER: &str = "C1";

/// 引擎内建 capability（P5 通道申报，与本文件观测实现一一对应）。
///
/// **单源**：`store.rs` 引用的就是这一份。两份常量会漂移 —— 而 capability 漂移的后果是
/// P5 静默拒绝入账（`admission.rs:217`），账本会「看起来在写、其实一条都没进去」。
pub const CAPABILITY_JSON: &str = r#"{"channels":[{"id":"proc_spawn_readback","tier":"C1"}]}"#;
