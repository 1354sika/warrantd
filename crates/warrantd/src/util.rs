//! 小工具：JSON 构造、时间格式、规范字节。
//!
//! 时间函数与 `crates/core/src/warrant_ledger.rs` 的 `rfc3339_from_secs` 同一算法
//! （Howard Hinnant civil_from_days），**刻意不引第三方时间库**：daemon 要能被别的
//! 智能体拿走独立运行，依赖越少越好。

use warrant::canon;
use warrant::json::Value;

pub fn s(x: &str) -> Value {
    Value::Str(x.to_string())
}

pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

pub fn arr(items: Vec<Value>) -> Value {
    Value::Array(items)
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// RFC3339 UTC（civil_from_days）。`secs` = Unix 秒。
pub fn rfc3339_from_secs(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, sec)
}

pub fn now_rfc3339() -> String {
    rfc3339_from_secs((now_ms() / 1000) as i64)
}

pub fn plus_days_rfc3339(days: i64) -> String {
    rfc3339_from_secs((now_ms() / 1000) as i64 + days * 86400)
}

/// 规范字节（warrant 的 canonical 形式）单行表示。
///
/// **账本落盘与 CLI 输出共用这一个函数** —— 保证「屏幕上看到的」和「落盘/复算的」
/// 是同一串字节。想看规范形式之外的漂亮输出，请自己做，别在这里分叉。
pub fn to_line(v: &Value) -> String {
    match canon::canonical_bytes(v) {
        Ok(b) => String::from_utf8_lossy(&b).to_string(),
        Err(_) => "{}".to_string(),
    }
}

/// 生成 nonce（幂等键）。确定性 nonce 是幂等的关键：同一份观测重放不产生第二条。
pub fn nonce_for(prefix: &str, parts: &[&str]) -> String {
    let mut buf = String::from(prefix);
    for p in parts {
        buf.push(':');
        buf.push_str(p);
    }
    buf
}

/// [BLACKBOX-GUARD-2026-10-27] spawn 控制台子进程必须隐藏窗口。
///
/// 与 `crates/core/src/blackbox.rs` 的防回归钉子**同一口径**（它扫 `creation_flags` /
/// `hide_console(` 两个关键字）：GUI 宿主（`zeropage.exe` / 被 GUI 拉起的 warrantd）没有可继承的
/// 控制台 ⇒ 每次 spawn 一个控制台程序都会**新分配一个可见窗口**，用户看到的是「频繁闪黑框」。
/// 真机事故：v0.1.241 的 `fourth_action` 漏标志，21:42-21:43 连发 20 次 ⇒ 用户报「频繁闪黑框」。
///
/// 回滚：删本函数 + 三处 `hide_console(` 调用（warrantd 的每条观测都会 spawn ⇒ 不删更好）。
pub fn hide_console(c: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    #[cfg(not(windows))]
    {
        let _ = c;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_instant() {
        // 2026-10-27T00:00:00Z = 1793059200（手算：与 core 的同一算法对拍）
        assert_eq!(rfc3339_from_secs(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_from_secs(1793059200), "2026-10-27T00:00:00Z");
    }

    #[test]
    fn canonical_line_is_stable_and_single_line() {
        let v = obj(vec![("b", Value::Int(1)), ("a", s("x"))]);
        let line = to_line(&v);
        assert!(!line.contains('\n'), "必须是单行：{line}");
        // 键字节序：a 在 b 前
        assert_eq!(line, r#"{"a":"x","b":1}"#);
    }
}
