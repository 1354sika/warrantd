# 怎么把这个仓库推到 GitHub

## 现状

- 目录：`C:\Users\sikaq\Desktop\第一代千青\_scratch\warrantd-open`
- 已就绪：两个 crate（`warrant` + `warrantd`）、README、LICENSE、NOTICE、CI、`.gitignore`
- **已独立验证**：脱离 ZeroPage 能编译；`cargo test --all` → **106 passed**；`fmt` 干净；`clippy -D warnings` 通过（两处 doc lint 明确豁免）
- release 产物：`1.48 MB` 单文件 exe，已打包 `warrantd-0.1.0-x86_64-pc-windows-msvc.tar.gz`（671 KB）
- **还没做**：`git init`（现在这里没有任何 git 仓库）

## 缺什么

| 东西 | 状态 |
|---|---|
| GitHub 账号 | 需要你自己有 |
| 认证（PAT / SSH key / gh CLI） | **本机没配** |
| 仓库名 | 未定 |

---

## 三条命令（你自己推，令牌不经过我）

先在 GitHub 网页建一个**空仓库**（不要勾 README / .gitignore / license）。

然后在这个目录开命令行：

```bat
cd /d C:\Users\sikaq\Desktop\第一代千青\_scratch\warrantd-open
git init
git add -A
git commit -m "warrantd 0.1.0: 常驻观测者与账本"
git branch -M main
git remote add origin https://github.com/<你的用户名>/<仓库名>.git
git push -u origin main
```

推送时会弹窗要用户名密码 —— **密码处填 PAT**，不是登录密码。

---

## ⛔ 一条必须遵守的规定：**不要把 token 写进 remote URL**

```bat
:: ❌ 绝对不要这样（token 会明文躺在 .git/config 里，谁拿到这个目录谁就有你的写权限）
git remote add origin https://ghp_xxxxxxxx@github.com/user/repo.git

:: ✅ 这样就行，认证交给凭据管理器
git remote add origin https://github.com/user/repo.git
```

**已经这么做过的话**：
1. 去 <https://github.com/settings/tokens> **把那个 token 撤销**（revoke）
2. 重新生成一个，用凭据管理器或 SSH 认证
3. 检查：`git remote -v` 里**不该出现 `ghp_` / `github_pat_` 字样**

> 为什么这条要写死：token 泄露 = 别人能往你的仓库推任意代码，也能读你的私有仓库。
> 而 `.git/config` 不会随 commit 走，所以**它不会被代码审查发现**，只会跟着目录复制一路传播。

---

## 怎么生成 PAT（如果走 HTTPS）

1. GitHub → 右上角头像 → Settings
2. 左下 → Developer settings
3. Personal access tokens → **Tokens (classic)** → Generate new token (classic)
4. 勾 `repo`，有效期建议 **30 天**
5. 生成后只显示一次，复制保存

## 或者用 SSH（更省心）

```bat
git remote add origin git@github.com:<你的用户名>/<仓库名>.git
git push -u origin main
```

---

## 推之前的两件事

### 1. 先设 private，跑一次 CI

推上去后 GitHub Actions 会自动跑（Windows + Ubuntu 编译测试，以及 fmt / clippy）。
**先确认全绿，再转 public。**

CI 里两处 doc lint 是**明确豁免**的（`doc_lazy_continuation` / `doc_overindented_list_items`），
写在 workflow 的命令行里而不是代码里 —— 这样"我们有意放行"是有据可查的。

### 2. 发布前过一遍这几处

| 检查 | 为什么 |
|---|---|
| `grep -rn "sikaq\|第一代千青\|Desktop" crates/` | 确认没有个人路径残留（已修过一次，别回退） |
| `crates/warrant/vectors/` 在不在 | 测试夹具，缺了别人跑 `cargo test` 必红 |
| `crates/warrant/tests/*.rs` 里没有外部绝对路径 | 同上 |
| `LICENSE` / `NOTICE` 在根目录 | Apache-2.0 要求 |
| `git remote -v` 里没有 token | 见上面那条红线 |

> **一处「故意保留」要说清**：`crates/warrant/vectors/*.json` 里仍会出现 `user:sikaq`（约 190 处）。
> 这不是漏改 —— 那些向量里的 `canonical` 字段**参与哈希计算**，改字就破坏夹具
> （真机试过：`c1_c2_c4_positive_cases` 立刻变红）。
> 它只是个**示例主体 id**，不是凭据；`SPEC.md` 里的示例已改成 `user:alice`。
> 如果确实要清掉，必须**重算每个受影响向量的 id/hash**，那是另一件事。

---

## 注意

- 这个目录在 `_scratch/` 下，**不入 ZeroPage 的库**。它是发布产物，不是源码。
- 它和 ZeroPage 里的 `crates/warrant*` **格式上已不同步**（这里 `cargo fmt` 过、clippy 修过）。
  以后改源码要重新同步一次 —— 这个欠账该做成脚本，目前没做。
- 许可证 Apache-2.0。为什么没选能强制署名的 BSD-4-Clause，见 `NOTICE` 与
  `kb/warrantd-许可决定-Apache-2.0-2026-10-28.md`。
