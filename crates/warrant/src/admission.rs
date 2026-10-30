//! 准入校验（SPEC.md 10 节）。返回非空 = 该条目不得入账。
//!
//! 覆盖 P1/P2/P3/P5/P6/P7（C10-C13 断言 P1/P2/P3/P6）。
//! P4（观测全部入账，不得过滤或挑选）**有意不在此层**：它是追加层规则，不是单条目
//! 校验——单条判定看不见"没提交的那部分"，机械上不可判。信使仓 2026-09-13-30 验收
//! 报告同裁决（C1-C13 未要求，参考实现亦不做）。revd 侧的结构性满足由
//! core::warrant_ledger 的 P4 钉死测试（patch_partial_readback_failure_still_recorded_p4）
//! 守护：核验部分失败的观测照样入账。
//! 注意：错误消息文本被 vectors/validation_cases.json 逐字钉死，
//! 改任何一个字都是对拍失败。

use crate::json::Value;
use crate::ledger::Entry;
use crate::projection::{C1_PLUS, T_GRANT};

/// 10.2 角色-身份绑定
fn role_allowed(kind: &str, role: &str) -> Option<&'static [&'static str]> {
    match (kind, role) {
        ("claim", "declare") => Some(&["ai", "human", "service"]),
        ("observation", "declare") => Some(&["verifier"]),
        ("testimony", "declare") => Some(&["human"]),
        ("claim", "freeze") => Some(&["human"]),
        ("claim", "reject") => Some(&["human"]),
        // [FUSE-2026-09-30] **门槛 ruling 也要由人类签才生效**（对齐信使 `_seek_ruling`：
        // 只认「被人类 freeze 过的 C1 ruling」）。引擎侧准入此前漏了 ruling 这一档。
        ("ruling", "freeze") => Some(&["human"]),
        ("ruling", "reject") => Some(&["human"]),
        _ => None,
    }
}

/// Python `repr()` 风格的字符串字面量，用于与向量里的错误消息逐字对齐。
fn py_repr(s: &str) -> String {
    format!("'{}'", s)
}

#[derive(Clone, PartialEq)]
enum ScalarVal {
    Str(String),
    Int(i64),
    Bool(bool),
    Null,
}

/// 叶子标量。**类型与值严格相等**才算同一项：`"2200"` 与 `2200` 不同。
///
/// 规范 profile 禁止浮点，因此这里不存在 float 叶子 —— 这是规范决定，不是遗漏。
#[derive(Clone, PartialEq)]
enum Leaf {
    Arr,
    Scalar(&'static str, ScalarVal),
}

fn leaves(v: &Value, out: &mut Vec<Leaf>) {
    match v {
        Value::Object(o) => {
            for (_, x) in o {
                leaves(x, out);
            }
        }
        Value::Array(_) => out.push(Leaf::Arr),
        Value::Str(s) => out.push(Leaf::Scalar("str", ScalarVal::Str(s.clone()))),
        Value::Int(i) => out.push(Leaf::Scalar("int", ScalarVal::Int(*i))),
        Value::Bool(b) => out.push(Leaf::Scalar("bool", ScalarVal::Bool(*b))),
        Value::Null => out.push(Leaf::Scalar("NoneType", ScalarVal::Null)),
    }
}

fn leaf_repr(l: &Leaf) -> String {
    match l {
        Leaf::Arr => "[]".to_string(),
        Leaf::Scalar(_, v) => match v {
            ScalarVal::Str(s) => format!("'{}'", s),
            ScalarVal::Int(i) => i.to_string(),
            ScalarVal::Bool(b) => if *b { "True" } else { "False" }.to_string(),
            ScalarVal::Null => "None".to_string(),
        },
    }
}

/// 10.1 P1 值级包含。**下限防护**：挡住"我说做 A、却预期 B"。
pub fn value_subset(expect: &Value, args: &Value) -> Vec<String> {
    if !matches!(expect.as_object(), Some(o) if !o.is_empty()) {
        return vec!["P1: expect must be a non-empty object".to_string()];
    }
    let mut exp = Vec::new();
    leaves(expect, &mut exp);
    let mut ags = Vec::new();
    if args.as_object().is_some() {
        leaves(args, &mut ags);
    }
    let mut errs = Vec::new();
    if exp.contains(&Leaf::Arr) {
        errs.push("P1: expect must not contain arrays".to_string());
    }
    for item in exp.iter().filter(|x| **x != Leaf::Arr) {
        if !ags.iter().any(|a| a == item) {
            errs.push(format!(
                "P1: expect value {} does not appear in action.args",
                leaf_repr(item)
            ));
        }
    }
    errs
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Str(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        _ => true,
    }
}

pub fn admission_errors(
    entry: &Entry,
    entries: &[Entry],
    capability: Option<&Value>,
) -> Vec<String> {
    let body = &entry.body;
    let kind = body.get("kind").and_then(|x| x.as_str()).unwrap_or("");
    let eid = entry.id.as_str();
    let is_grant = body.get("type").and_then(|x| x.as_str()) == Some(T_GRANT);
    // [FUSE-2026-09-30] 门槛 ruling：不适用 P6（它不是"认定某条声明"，而是"启用/停用门槛"）。
    let is_ruling = body.get("kind").and_then(|x| x.as_str()) == Some("ruling");
    let mut errs: Vec<String> = Vec::new();

    // ---- P1 ----
    if kind == "claim" && !is_grant {
        let expect = body.get("expect").cloned().unwrap_or(Value::Null);
        let args = body
            .get("action")
            .and_then(|a| a.get("args"))
            .cloned()
            .unwrap_or(Value::Null);
        errs.extend(value_subset(&expect, &args));
    }

    // ---- P2 ----
    if kind == "claim" && !is_grant && !entries.is_empty() {
        let gid = body
            .get("authority")
            .and_then(|a| a.get("grant_id"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        match entries.iter().find(|e| e.id == gid) {
            None => errs.push("P2: authority.grant_id does not resolve".to_string()),
            Some(g) => {
                let t = body.get("type").and_then(|x| x.as_str()).unwrap_or("");
                let in_scope = g
                    .body
                    .get("action")
                    .and_then(|a| a.get("args"))
                    .and_then(|a| a.get("types"))
                    .and_then(|x| x.as_array())
                    .map(|arr| arr.iter().any(|x| x.as_str() == Some(t)))
                    .unwrap_or(false);
                if !in_scope {
                    errs.push(format!("P2: type not in grant scope: {t}"));
                }
            }
        }
    }

    // ---- P7 证言结构 ----
    if kind == "testimony" {
        let tm = body.get("testimony");
        let st = tm.and_then(|t| t.get("statement")).and_then(|x| x.as_str());
        if st.map(|s| s.trim().is_empty()).unwrap_or(true) {
            errs.push("P7: testimony.statement must be a non-empty string".to_string());
        }
        for f in ["language", "method", "observed_at"] {
            if !truthy(tm.and_then(|t| t.get(f))) {
                errs.push(format!("P7: testimony.{f} is required"));
            }
        }
        if body
            .get("actor")
            .and_then(|a| a.get("kind"))
            .and_then(|x| x.as_str())
            != Some("human")
        {
            errs.push("P7: testimony actor must be human".to_string());
        }
    }

    // ---- P3 ----
    for sg in &entry.signatures {
        let role = sg.get("role").and_then(|x| x.as_str()).unwrap_or("");
        let k = sg
            .get("signer")
            .and_then(|s| s.get("kind"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        match role_allowed(kind, role) {
            None => errs.push(format!(
                "P3: role {} not allowed on kind {}",
                py_repr(role),
                py_repr(kind)
            )),
            Some(allowed) => {
                if !allowed.contains(&k) {
                    errs.push(format!(
                        "P3: signer kind {} may not sign {}/{}",
                        py_repr(k),
                        kind,
                        role
                    ));
                }
            }
        }
    }

    // ---- P5 ----
    if kind == "observation" {
        if let Some(cap) = capability {
            let cid = body
                .get("observation")
                .and_then(|o| o.get("channel"))
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let declared = cap
                .get("channels")
                .and_then(|x| x.as_array())
                .and_then(|arr| {
                    arr.iter()
                        .find(|c| c.get("id").and_then(|x| x.as_str()) == Some(cid))
                });
            match declared {
                None => errs.push(format!(
                    "P5: channel {} not declared in capability",
                    py_repr(cid)
                )),
                Some(c) => {
                    let tier = body
                        .get("observation")
                        .and_then(|o| o.get("tier"))
                        .and_then(|x| x.as_str());
                    let was = c.get("tier").and_then(|x| x.as_str());
                    if tier != was {
                        errs.push(format!(
                            "P5: tier {} != declared {} for channel {}",
                            py_repr(tier.unwrap_or("")),
                            py_repr(was.unwrap_or("")),
                            py_repr(cid)
                        ));
                    }
                }
            }
        }
    }

    // ---- P6（grant/ruling 豁免：授权由人类直接承担，不存在"关于授权的观测"）----
    if !is_grant && !is_ruling {
        for sg in &entry.signatures {
            if sg.get("role").and_then(|x| x.as_str()) != Some("freeze") {
                continue;
            }
            let based = match sg.get("based_on") {
                Some(v) if truthy(Some(v)) => Some(v.clone()),
                _ => sg
                    .get("sig_payload")
                    .and_then(|p| p.get("based_on"))
                    .filter(|v| truthy(Some(v)))
                    .cloned(),
            };
            let arr = match based.as_ref().and_then(|v| v.as_array()) {
                Some(a) => a,
                None => {
                    errs.push("P6: freeze without based_on".to_string());
                    continue;
                }
            };
            for oidv in arr {
                let oid = oidv.as_str().unwrap_or("");
                match entries.iter().find(|e| e.id == oid) {
                    None => errs.push(format!("P6: based_on {oid} not found")),
                    Some(o) => {
                        let ob = &o.body;
                        let is_obs_of_this = ob.get("kind").and_then(|x| x.as_str())
                            == Some("observation")
                            && ob
                                .get("subject")
                                .and_then(|s| s.get("id"))
                                .and_then(|x| x.as_str())
                                == Some(eid);
                        if !is_obs_of_this {
                            errs.push(format!(
                                "P6: based_on {oid} is not an observation of this entry"
                            ));
                        } else {
                            let tier = ob
                                .get("observation")
                                .and_then(|o| o.get("tier"))
                                .and_then(|x| x.as_str())
                                .unwrap_or("C0");
                            if !C1_PLUS.contains(&tier) {
                                errs.push(format!("P6: based_on {oid} tier below C1"));
                            }
                        }
                    }
                }
            }
        }
    }

    // ---- SPEC §2.3/§2.4/§2.5 必填字段（结构层）----
    // [F1-2026-09-29] 补上规范列出的必填字段校验。**放在最后执行**：既有 P1/P2/P3/P5/P6/P7 的
    // 错误消息被 vectors/validation_cases.json 逐字钉死，新增检查不得抢在它们前面。
    let required: &[&str] = match kind {
        "claim" => &[
            "kind",
            "type",
            "actor",
            "subject",
            "action",
            "expect",
            "authority",
            "scope",
            "horizon",
            "parents",
            "nonce",
            "chain",
        ],
        "observation" => &[
            "kind",
            "type",
            "actor",
            "subject",
            "observation",
            "parents",
            "nonce",
            "chain",
        ],
        "testimony" => &[
            "kind",
            "type",
            "actor",
            "subject",
            "testimony",
            "parents",
            "nonce",
            "chain",
        ],
        _ => &[],
    };
    for f in required {
        if body.get(f).is_none() {
            errs.push(format!("STRUCT: {kind} missing required field {f}"));
        }
    }

    // ---- §3.4 深度上限（[DEPTH-2026-09-29]）----
    // 证据链过长 ⇒ 推论叠推论、可信度衰减到不可复核。ZeroPage 的**默认裁决 = 拒绝入账**
    // （保守、可回滚；现状实测深度 4 ≪ N_MAX ⇒ 零影响）。
    // 必须把**本条目**一起建图，否则新条目不在 nodes 里、深度恒为 0。
    let mut all: Vec<Entry> = entries.to_vec();
    all.push(entry.clone());
    let gph = crate::graph::build(&all);
    let depth = gph.depth_of(eid);
    if depth > crate::graph::N_MAX {
        errs.push(format!(
            "X-DEPTH: entry depth {depth} exceeds N_MAX {}",
            crate::graph::N_MAX
        ));
    }

    errs
}
