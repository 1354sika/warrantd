//! messenger_export — P4-8 信使接入：引擎账本 → warrant/1 导出 bundle。
//!
//! 导出前提：结构性复算全绿（canon::event_id 逐条复算 + ledger::verify_chain 链位校验）。
//! bundle = entries.jsonl（原样字节）+ capability.json（通道档位声明，C2 离线复算档）
//! + report.json（复算报告：条数/类型/账本 sha256）。
//! 信使侧（只读复用 canon.py / ledger.py）对同一 entries.jsonl 独立复算——两侧一致即成立。

use std::path::PathBuf;
use warrant::json::Value;
use warrant::{canon, ledger};

fn arg_or(name: &str, default: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    for (i, a) in args.iter().enumerate() {
        if a == name {
            return args
                .get(i + 1)
                .cloned()
                .unwrap_or_else(|| default.to_string());
        }
    }
    default.to_string()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// epoch ms → UTC ISO 8601（civil_from_days 标准算法，无第三方依赖）。
fn utc_iso(ms: u64) -> String {
    let secs = ms / 1000;
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, mi, s) = (
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    );
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
}

fn write_json(path: &PathBuf, v: &Value) -> Result<(), String> {
    let bytes = canon::canonical_bytes(v).map_err(|e| format!("canonical 序列化失败: {e:?}"))?;
    std::fs::write(path, &bytes).map_err(|e| format!("写 {} 失败: {e}", path.display()))
}

fn main() {
    let entries_path = PathBuf::from(arg_or(
        "--entries",
        "app/.runtime/revd-home/warrant/entries.jsonl",
    ));
    let out_dir = PathBuf::from(arg_or("--out", "app/.runtime/p4-8/bundle"));
    let raw = std::fs::read_to_string(&entries_path).unwrap_or_else(|e| {
        eprintln!("读账本失败 {}: {e}", entries_path.display());
        std::process::exit(2)
    });
    let entries = ledger::load_jsonl(&raw).unwrap_or_else(|e| {
        eprintln!("账本解析失败: {e}");
        std::process::exit(2)
    });
    let errs = ledger::verify_chain(&entries);
    if !errs.is_empty() {
        eprintln!("结构性复算失败（不导出）:");
        for e in &errs {
            eprintln!("  - {e}");
        }
        std::process::exit(3);
    }
    let mut types: Vec<String> = Vec::new();
    for e in &entries {
        if let Some(t) = e.body.get("type").and_then(Value::as_str) {
            if !types.iter().any(|x| x == t) {
                types.push(t.to_string());
            }
        }
    }
    let n = entries.len() as i64;
    let first_id = entries.first().map(|e| e.id.clone()).unwrap_or_default();
    let last_id = entries.last().map(|e| e.id.clone()).unwrap_or_default();
    use sha2::{Digest, Sha256};
    let ledger_sha = format!(
        "sha256:{}",
        Sha256::digest(raw.as_bytes())
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    std::fs::create_dir_all(&out_dir).unwrap_or_else(|e| {
        eprintln!("建目录失败: {e}");
        std::process::exit(4)
    });
    std::fs::write(out_dir.join("entries.jsonl"), &raw).unwrap_or_else(|e| {
        eprintln!("写 entries.jsonl 失败: {e}");
        std::process::exit(4)
    });

    let cap = Value::Object(vec![
        ("spec".into(), Value::Str("warrant/1".into())),
        ("adapter".into(), Value::Str("zeropage/revd-engine".into())),
        ("version".into(), Value::Str(env!("CARGO_PKG_VERSION").into())),
        ("types".into(), Value::Array(types.iter().map(|t| Value::Str(t.clone())).collect())),
        ("channels".into(), Value::Array(vec![Value::Object(vec![
            ("id".into(), Value::Str("c_ledger".into())),
            ("tier".into(), Value::Str("C2".into())),
            ("read_only".into(), Value::Bool(true)),
            ("desc".into(), Value::Str("offline artefact: signed jsonl ledger; ids and chain recomputable by third parties (canon + chain verify)".into())),
        ])])),
        ("max_tier".into(), Value::Str("C2".into())),
        ("reversible".into(), Value::Bool(false)),
        ("exclusive".into(), Value::Bool(false)),
        ("idempotency".into(), Value::Str("id-addressed append-only; replay of a known id appends no second entry".into())),
        ("declared_at".into(), Value::Str(utc_iso(now_ms()))),
    ]);
    write_json(&out_dir.join("capability.json"), &cap).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(4)
    });

    let report = Value::Object(vec![
        ("spec".into(), Value::Str("warrant/1".into())),
        ("adapter".into(), Value::Str("zeropage/revd-engine".into())),
        (
            "source".into(),
            Value::Str(entries_path.display().to_string()),
        ),
        ("exported_at_ms".into(), Value::Int(now_ms() as i64)),
        ("entries".into(), Value::Int(n)),
        ("id_recompute".into(), Value::Str("verified".into())),
        ("chain".into(), Value::Str("verified".into())),
        (
            "types".into(),
            Value::Array(types.iter().map(|t| Value::Str(t.clone())).collect()),
        ),
        ("ledger_sha256".into(), Value::Str(ledger_sha)),
        ("first_id".into(), Value::Str(first_id)),
        ("last_id".into(), Value::Str(last_id)),
    ]);
    write_json(&out_dir.join("report.json"), &report).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(4)
    });

    println!(
        "OK entries={} types={} chain=verified id=verified -> {}",
        n,
        types.len(),
        out_dir.display()
    );
}
