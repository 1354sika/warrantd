//! Merkle 批锚 + 包含证明（`[MERKLE-2026-10-21]`）。
//!
//! **这是新增能力，不改任何既有条目语义**（SPEC §9：不得向 v1 追加必填字段；
//! 锚以「账本之外的锚文件 + 可离线复算的叶子列表」形态存在，见 `revd warrant-anchor`）。
//!
//! 为什么需要（技术评估 P0-1，已核实 `crates/warrant` 全目录无 `merkle|proof|anchor`）：
//! - 线性链 [crate::ledger::verify_chain] 是 **O(n) 全遍历**：外部要验一条，得拿整本账全量重算；
//! - 无法回答「我有这一条，且它在账里没被改」这种**单条问题**；
//! - 没有根 ⇒ 无法与外部（时间戳 / 客户留存 / 公开位置）低成本锚定。
//!
//! 定义（**写死，第三方照此复算**）：
//! - 叶子 `L_i = sha256("warrant/v1/merkle/leaf\x00" ‖ entry_id_ascii)`
//! - 内部 `N   = sha256("warrant/v1/merkle/node\x00" ‖ left ‖ right)`
//! - 树形 **RFC 6962 风格**：n>1 时在最大的 2 的幂 k（k<n）处切分，左 k / 右 n-k
//! - 单叶 ⇒ root = L_0；空集 ⇒ root = 32 字节全零
//!
//! 为什么用 RFC 6962 的切分而不是「补齐到 2 的幂」：补零会引入可被伪造的 `L(空)` 叶子
//! （第二原像问题），RFC 6962 的切分不补零。

use sha2::{Digest, Sha256};

use crate::canon;

/// 叶子域分隔（与 `warrant/v1/id`、`warrant/v1/sig`、`warrant/v1/link` 同族）。
pub const LEAF_DOMAIN: &[u8] = b"warrant/v1/merkle/leaf\x00";
/// 内部节点域分隔。
pub const NODE_DOMAIN: &[u8] = b"warrant/v1/merkle/node\x00";
/// 空集的根（32 字节全零 hex）——明确表达「没有叶子」，不是「根未知」。
pub const EMPTY_ROOT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

/// 叶子哈希：`sha256(LEAF_DOMAIN ‖ entry_id)`。
pub fn leaf_hash(entry_id: &str) -> [u8; 32] {
    hash(&[LEAF_DOMAIN, entry_id.as_bytes()])
}

/// 内部节点：`sha256(NODE_DOMAIN ‖ left ‖ right)`。
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash(&[NODE_DOMAIN, left.as_slice(), right.as_slice()])
}

/// 最大 2 的幂 k 满足 `k < n`（要求 n ≥ 2）。
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn root_of(hs: &[[u8; 32]]) -> [u8; 32] {
    match hs.len() {
        0 => [0u8; 32],
        1 => hs[0],
        n => {
            let k = split(n);
            node_hash(&root_of(&hs[..k]), &root_of(&hs[k..]))
        }
    }
}

/// 叶子列表的 Merkle 根（hex，小写）。
pub fn root_hex(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return EMPTY_ROOT.to_string();
    }
    let hs: Vec<[u8; 32]> = leaves.iter().map(|s| leaf_hash(s)).collect();
    canon::hex(&root_of(&hs))
}

/// 一步包含证明：兄弟子树的根 + 它在哪一侧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStep {
    /// `true` = 兄弟在右（当前节点是左孩子）。
    pub sibling_right: bool,
    /// 兄弟子树根的 hex（32 字节）。
    pub hash: String,
}

/// 生成包含证明（**由叶到根**，RFC 6962 PATH 口径：调用方按这个顺序消费）。
fn prove_inner(hs: &[[u8; 32]], i: usize, out: &mut Vec<ProofStep>) {
    if hs.len() <= 1 {
        return;
    }
    let k = split(hs.len());
    // 先递归到叶子，再 push 当前层的兄弟 ⇒ 输出顺序 = 由叶到根。
    // （反过来写会让 n=3 这类非满树当场对不上：第一步拿到的会是右子树的根。）
    if i < k {
        prove_inner(&hs[..k], i, out);
        out.push(ProofStep {
            sibling_right: true,
            hash: canon::hex(&root_of(&hs[k..])),
        });
    } else {
        prove_inner(&hs[k..], i - k, out);
        out.push(ProofStep {
            sibling_right: false,
            hash: canon::hex(&root_of(&hs[..k])),
        });
    }
}

/// 为第 `index` 个叶子生成包含证明（按 RFC 6962 切分顺序，**由叶到根**）。
pub fn prove(leaves: &[String], index: usize) -> Result<Vec<ProofStep>, String> {
    if leaves.is_empty() {
        return Err("empty leaf set: no root exists".to_string());
    }
    if index >= leaves.len() {
        return Err(format!("index {index} out of range (count {})", leaves.len()));
    }
    let hs: Vec<[u8; 32]> = leaves.iter().map(|s| leaf_hash(s)).collect();
    let mut out = Vec::new();
    prove_inner(&hs, index, &mut out);
    Ok(out)
}

fn decode32(hexstr: &str) -> Result<[u8; 32], String> {
    if hexstr.len() != 64 {
        return Err(format!("hash must be 64 hex chars, got {}", hexstr.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hexstr.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "hash is not ascii".to_string())?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| format!("bad hex {s:?}"))?;
    }
    Ok(out)
}

/// 验证包含证明：给定叶子 id、证明、根、叶子下标与总数，**无需整本账**。
///
/// 任何不一致（根不符、证明过短/过长、兄弟方向与下标矛盾、下标越界）都返回 `Err`。
pub fn verify(
    leaf_id: &str,
    proof: &[ProofStep],
    root_hex: &str,
    index: usize,
    count: usize,
) -> Result<(), String> {
    if count == 0 {
        return Err("count must be >= 1".to_string());
    }
    if index >= count {
        return Err(format!("index {index} out of range (count {count})"));
    }
    let mut cur = leaf_hash(leaf_id);
    // **自顶向下**记录每一层「当前节点落在父节点的左半边还是右半边」，
    // 然后**逆序**消费证明（prove 输出的是「由叶到根」）。
    // 直接按 `i < split(n)` 边算边消费是错的：叶层的父节点不是根，n=3 这类非满树会当场对不上。
    let mut in_left: Vec<bool> = Vec::new();
    let mut i = index;
    let mut n = count;
    while n > 1 {
        let k = split(n);
        if i < k {
            in_left.push(true);
            n = k;
        } else {
            in_left.push(false);
            i -= k;
            n -= k;
        }
    }
    if proof.len() != in_left.len() {
        return Err(format!(
            "proof has {} step(s), a path of this depth takes {}",
            proof.len(),
            in_left.len()
        ));
    }
    for (pos, step) in proof.iter().enumerate() {
        let left = in_left[in_left.len() - 1 - pos];
        if step.sibling_right != left {
            return Err(format!(
                "step {pos}: sibling side does not match the path (expected sibling_right={left})"
            ));
        }
        let sib = decode32(&step.hash)?;
        cur = if left { node_hash(&cur, &sib) } else { node_hash(&sib, &cur) };
    }
    let got = canon::hex(&cur);
    if got != root_hex.to_ascii_lowercase() {
        return Err(format!("root mismatch: computed {got}, expected {root_hex}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("sha256:{:064x}", i + 1)).collect()
    }

    /// **对拍**：满二叉（n 是 2 的幂）时，RFC 6962 切分等价于「逐层两两合并」的经典实现。
    /// 这是两套独立写法（递归切分 vs 自底向上成对），结果必须一致。
    fn classic_root(leaves: &[String]) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = leaves.iter().map(|s| leaf_hash(s)).collect();
        while level.len() > 1 {
            let mut next = Vec::new();
            for pair in level.chunks(2) {
                next.push(node_hash(&pair[0], &pair[1]));
            }
            level = next;
        }
        level[0]
    }

    #[test]
    fn root_matches_classic_for_power_of_two() {
        for n in [1usize, 2, 4, 8, 16] {
            let ls = ids(n);
            assert_eq!(
                root_hex(&ls),
                canon::hex(&classic_root(&ls)),
                "n={n}: RFC6962 切分与逐层合并必须一致"
            );
        }
    }

    #[test]
    fn every_index_proves_and_verifies() {
        // 覆盖满树与非满树（1..=17），每个下标都走一遍 prove+verify。
        for n in 1..=17usize {
            let ls = ids(n);
            let root = root_hex(&ls);
            for i in 0..n {
                let proof = prove(&ls, i).unwrap_or_else(|e| panic!("n={n} i={i}: {e}"));
                verify(&ls[i], &proof, &root, i, n)
                    .unwrap_or_else(|e| panic!("n={n} i={i}: {e}"));
            }
        }
    }

    #[test]
    fn tampered_leaf_changes_root() {
        let mut ls = ids(5);
        let before = root_hex(&ls);
        ls[2] = "sha256:deadbeef".to_string();
        assert_ne!(before, root_hex(&ls), "改任一叶子的 id，根必须变");
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let ls = ids(7);
        let root = root_hex(&ls);
        let mut proof = prove(&ls, 3).unwrap();
        proof[0].hash = canon::hex(&[9u8; 32]);
        assert!(verify(&ls[3], &proof, &root, 3, 7).is_err(), "改兄弟哈希必须被拒");
    }

    #[test]
    fn wrong_index_and_count_are_rejected() {
        let ls = ids(6);
        let root = root_hex(&ls);
        let proof = prove(&ls, 2).unwrap();
        assert!(verify(&ls[2], &proof, &root, 1, 6).is_err(), "换下标必须被拒");
        // ⚠️ 诚实边界：**同形的 count 无法区分**——i=2 在 5/6/7/8 叶树里的路径形状相同
        // （都是「左子树满 4 的第 2 个」），所以 proof 对这些 count 都自洽。
        // 包含证明承诺的是 **root**（根不同 ⇒ 一切不同），不是「总数」。
        // 这里用结构不同的 count=4 做负例（只有 2 层，路径长度对不上）。
        assert!(verify(&ls[2], &proof, &root, 2, 4).is_err(), "换总数（结构不同）必须被拒");
        assert!(verify(&ls[2], &proof[..proof.len() - 1], &root, 2, 6).is_err(), "证明缺一步必须被拒");
        let mut extra = proof.clone();
        extra.push(ProofStep { sibling_right: true, hash: canon::hex(&[0u8; 32]) });
        assert!(verify(&ls[2], &extra, &root, 2, 6).is_err(), "证明多一步必须被拒");
    }

    #[test]
    fn empty_set_has_defined_root_and_no_proof() {
        assert_eq!(root_hex(&[]), EMPTY_ROOT);
        assert!(prove(&[], 0).is_err());
        let ls = ids(3);
        assert!(prove(&ls, 3).is_err(), "越界下标必须报错");
    }
}
