//! C10-C13：准入校验（信使 SPEC.md 10 节）。
//!
//! 用 vectors/validation_cases.json 的 12 个用例验证：
//! C10 P1 值级包含 C11 P2 授权范围 C12 P3 角色绑定 C13 P6 冻结绑证
//! 期望以**规则前缀**（"P1"...）给出；接受类用例必须零错误。

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use warrant::admission;
use warrant::json::{self, Value};
use warrant::ledger::{self, Entry};

fn xinshi(parts: &[&str]) -> PathBuf {
    // [VECTORS-IN-REPO-2026-10-28] 夹具随仓库走。
    // 原来这里硬编码了某台机器上的「信使系统」目录 —— 开源后别人跑 cargo test 必然全红，
    // 而且暴露了个人路径。现在 vectors/ 已入库，路径以 CARGO_MANIFEST_DIR 为基准。
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for x in parts {
        p.push(x);
    }
    p
}

fn entries_from(v: &Value) -> Vec<Entry> {
    v.as_array()
        .expect("entries must be a list")
        .iter()
        .map(|x| ledger::entry_from_value(x).expect("envelope"))
        .collect()
}

#[test]
fn c10_to_c13_admission_vectors() {
    let text = fs::read_to_string(xinshi(&["vectors", "validation_cases.json"]))
        .expect("读 vectors/validation_cases.json");
    let doc = json::parse(&text).expect("vectors 必须是合法 JSON");
    let default_cap = doc.get("capability").expect("顶层 capability");
    let cases = doc.get("cases").expect("cases").as_array().unwrap();

    let mut fails: Vec<String> = Vec::new();
    let mut codes: BTreeSet<String> = BTreeSet::new();
    let (mut n_ok, mut n_reject) = (0usize, 0usize);

    for c in cases {
        let name = c.get("name").and_then(|x| x.as_str()).unwrap_or("?");
        let entries = entries_from(c.get("entries").expect("entries"));
        let cap = c.get("capability").unwrap_or(default_cap);
        let ti = c.get("target_index").and_then(|x| x.as_int()).unwrap_or(0) as usize;
        let target = entries
            .get(ti)
            .unwrap_or_else(|| panic!("{name}: target_index {ti} 越界"));

        let errs = admission::admission_errors(target, &entries, Some(cap));

        if matches!(c.get("expect_ok"), Some(Value::Bool(true))) {
            n_ok += 1;
            if !errs.is_empty() {
                fails.push(format!("{name}: 应当接受，却报错 {errs:?}"));
            }
        } else {
            n_reject += 1;
            if errs.is_empty() {
                fails.push(format!("{name}: 应当拒绝，却放行"));
                continue;
            }
            // 规范把准入判定输出规定为错误列表，向量给出**逐字**期望；
            // 因此这里断言精确相等（比"前缀命中"强得多）。
            let want: Vec<String> = c
                .get("errors")
                .expect("errors")
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            if errs != want {
                fails.push(format!(
                    "{name}: 错误列表不同\n     我方 {errs:?}\n     向量 {want:?}"
                ));
            }
            // 前缀码用于覆盖自检（errors 是完整文本，expect_errors 是规则码）
            for code in c
                .get("expect_errors")
                .expect("expect_errors")
                .as_array()
                .unwrap()
            {
                codes.insert(code.as_str().unwrap().to_string());
            }
        }
    }

    assert!(
        fails.is_empty(),
        "准入向量不一致（{} 项）：\n{}",
        fails.len(),
        fails.join("\n")
    );
    for need in ["P1", "P2", "P3", "P6"] {
        assert!(codes.contains(need), "C10-C13 未覆盖 {need}");
    }
    assert!(
        n_ok >= 1 && n_reject >= 10,
        "用例分布异常: ok={n_ok} reject={n_reject}"
    );
}
