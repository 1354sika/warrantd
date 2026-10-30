# warrantd

> **Your agent says it's done. This lets you check.**
>
> A resident third-party observer that makes what an AI agent did
> *independently recomputable* — including the changes it never mentioned.

Not an AI governance platform. Not a security gateway. Not another MCP tool.
It observes. **It does not intercept** — and that is the first thing worth saying,
because everything else is easy to misread.

---

Every agent has two failure modes that no benchmark captures.

**The black box.** It says *done*. You cannot tell whether it changed one line or forty —
or whether it changed nothing at all and simply stopped.

**The lag.** The information you are holding is ten minutes old. The world moved on.

Same root cause: **the only record of what happened lives inside the agent's context window.**
If it doesn't mention it, you don't know. If it mentions it wrong, you can't tell.

warrantd is a resident process that sits next to your project and does one thing:
it watches the world and writes down **what it saw** next to **what the agent claimed** —
in a ledger you can recompute without trusting anyone.

> Does the claim match the world? · What changed that nobody claimed? · What happened while you weren't looking?

`1.5 MB · single binary · no runtime dependencies · Apache-2.0`

---

## What these two problems actually look like

Six incidents that really happened — all of them while building this thing.

They share one shape: **not "no record", but "a record that was broken or missing,
and nobody told you."**

### 1 · One field with the wrong type silently disabled evidence collection for two weeks

| | |
|---|---|
| **Symptom** | The attestation panel stayed empty for an entire stretch of development. |
| **What we assumed** | Not connected. Or "nothing to attest." |
| **What it was** | `capabilities` was written as a string; the schema wanted an array. The whole `mcp.json` failed to parse → `mcp disabled` → **the plugin that was configured correctly died with it.** |
| **Why nobody caught it** | There *was* a WARN line in the log. It said "skipped". It never said **what that meant**. |
| **Cost** | Two weeks of work. Not one entry recorded. |

**How warrantd handles it**: `warrantd admit` reports **L0 (blind)**. It does not let you
believe "everything is fine". It states, plainly: *"I know nothing about this project.
The sentence 'nothing happened' is meaningless here."*

### 2 · An agent saved two files, and both filenames lied

A real incident from giving an agent **direct control over a desktop application**
(Multisim, through its COM interface).

| | |
|---|---|
| **It claimed** | I produced a 6 V variant and a 1.25 V variant. |
| **The filenames promised** | `loop1_led_6v.ms14` → R2 = 800 Ω; `loop1_led_1p25v.ms14` → R2 = 1 Ω |
| **The files contained** | **R2 = 1720 Ω. Both of them.** Three read-backs, same value. |
| **How** | The value-setting call **failed** — the method name does not exist in that interface. The script **did not check the result** and went straight on to `SaveAs`. |
| **Worse** | The grant explicitly said *"probes must not call Save/SaveAs."* So it was not merely wrong — it was **out of scope**. |
| **Cost** | Two files that lie in their own names; two authorization violations. Artifacts deleted, **hashes kept** — nothing hidden. |

**Why this is the hard kind**: the run finished. Files appeared. Sizes looked right.
Saving returned success. **Everything looked correct.** The only problem was that
*what the name promised* and *what the file contained* were not the same thing —
and you only learn that by **reading it back**.

**How warrantd handles it**: a filename is a **claim**; file content is an **observation**.
Both are recorded separately and then reconciled — a mismatch is `CONTRADICTED`.
Scope violations are judgeable too: an action outside the grant's limits is recorded as
*happened, but not admissible as complete*.

> A positive counterpart from the same setup: in another run the agent wrote its own
> predictions to disk **before** simulating, then compared them against the target
> engine's measured values. Across five settings of R2, Vout matched to **7 significant
> figures** (relative difference < 1e-8).
> **It can be falsified — that is what makes "this one was right" mean anything.**

### 3 · "Not declared" was recorded as "not there" — and the failure called itself honest

| | |
|---|---|
| **Symptom** | An application was integrated. Every action "succeeded". The evidence chain only ever had one axis. |
| **What we assumed** | That application is just like that. |
| **What it was** | The read-back probe was **never declared** in config. No observation ⇒ **the second axis was always empty.** |
| **The nasty part** | The system logged the absence of evidence as **"honest: no second axis produced."** *The failure rationalized itself.* Nobody reading the log would ever suspect. |
| **Same family** | The variant with undeclared arguments: calling a read-only probe with empty args — anything with required parameters fails every time. Equally silent. |

**How warrantd handles it**: the observation surface is a **closed whitelist**, and every
capability must declare its tier. Nothing can "silently degrade": it either exists in the
table or it does not exist. `warrantd probes` shows all nine; `status` puts
*what I cannot see* on the first screen.

### 4 · A spec sat in the repo for 11 days and never entered a single design review

| | |
|---|---|
| **Symptom** | A complete, careful specification. Finalized on day one. |
| **What we assumed** | Everyone knows about it. Everyone follows it. |
| **What it was** | **For 11 days, not one design pass read it.** Then a late-night design was overturned by it on the spot — because the answer had been written down all along. |
| **The lesson** | **"Knowledge in the repo" is not "knowledge in use."** A spec nobody reads does not exist. |

**How warrantd handles it**: boundaries are not left to discipline. `status` puts them in
front of you; `admit` tells you your current level. Not *"you should go check"* —
**pushed to you every time.**

### 5 · Someone shipped a release at 23:00. At 23:32 I was still writing "three things missing."

| | |
|---|---|
| **Symptom** | I wrote up a list of three missing pieces. |
| **What it was** | **32 minutes earlier**, another session had finished all three and shipped. |
| **Why I didn't know** | The two sessions shared **no state at all**. It was in its context window; I was in mine. |
| **Cost** | Wasted work, and a conclusion that was void on arrival. |

**How warrantd handles it**: the ledger lives **in the project**, not inside one
application. Any subject — a human, this agent, that agent — writes to the same ledger.
`warrant_since(offset)` answers: *what changed since the last time you looked?*

### 6 · The ledger got archived once. The evidence layer switched itself off — and the UI looked fine.

| | |
|---|---|
| **Symptom** | The attestation panel was empty for weeks. |
| **What it was** | The ledger had been archived. Its first `seq` was no longer `0` ⇒ **chain verification failed** ⇒ the entire attestation layer shut down. |
| **The worst part** | The error read `chain broken (tamper?)` — **describing an archiving accident as possible tampering**, sending the reader in exactly the wrong direction. |
| **Cost** | Two weeks of "I thought it wasn't connected." It was never recording. |

**How warrantd handles it**: a broken ledger does not degrade silently. The error names
three things — the most likely cause (archived), **the consequence** (attestation is off;
nothing further is recorded), and the fix (put the archive back; ⛔ do **not** hand-edit
the first `seq` to `0` — *that* is actual tampering).

---

## What "it looked like it worked" looks like when an agent drives real software

Case 2 is about controlling an application. These are the details we actually hit —
every one of them **looked right at the time**, and **not one of them raised an error**.

| Trap | You think | What actually happens |
|---|---|---|
| **Same length ≠ same bytes** | Two responses of equal length ⇒ same run | The difference was only **vector order** (`na4\|a4mid` vs `a4mid\|na4`); the sha differs ⇒ **compare bytes, never lengths** |
| **Reading the DOM ≠ knowing what was pressed** | You read a control's `title`, so you know where the user clicked | It proves the entry point **exists**. It cannot tell you *which control was pressed*. |
| **Event payloads get truncated** | The hook returned "the whole frame" | It returned the **first 700 characters**. The 268 KB arrived 44 seconds later, by reading page memory in chunks. |
| **Progress dialogs linger** | The simulation finished | A **99% modal** is left on screen, blocking every subsequent action. |
| **Simulation documents don't persist** | Close the project, reopen, see whether the result survives | The content **was never saved**. That "verification method" is void. |
| **Official APIs are largely unusable** | Call `importChanges` to sync schematic ↔ PCB | It always returns `false`. Three families of netlist APIs are dead. `autoLayout` times out. **26 methods have no documentation.** |
| **Windows change** | The bridge is attached to "the active window" | It gets seized by a **zombie window** (requests time out forever); the extension reconnects every **20–30 s** with a **new `windowId`** ⇒ you must retry, and you must not cache it. |

**The common shape: none of these is an error.** Each one returns something that looks normal.

That is why *checking the return value* is not enough. You need a **second, independent
channel** that reads what actually happened. That is the whole reason warrantd exists:
**it does not ask whether you succeeded — it goes and reads.**

---

## How it answers

| Design | Case | In one line |
|---|---|---|
| **Closed-whitelist observation surface** | 3 | Nine primitives. Anything outside the table is **structurally impossible** — not "discouraged" |
| **Append-only, offline-recomputable ledger** | 6 | Every entry has an id and a chain position; **anyone with the file can recompute it**, no trust required |
| **Three slices** | 1, 5 | claim vs world / unclaimed changes / what happened while you were away |
| **Self-assessed level, L0–L3** | 1 | Tells you how observable you currently are, instead of letting you assume |
| **Every action independently re-readable** | 2 | Filename is a claim, content is an observation — recorded separately, then reconciled |
| **Blind spots in three groups, each with a fix** | all | *Structurally impossible* / *not built yet* / *your choice* — engineering debt never hides inside capability limits |

The most valuable one is the second slice:

> **Files that changed, with no agent claiming them.**

It does not depend on the agent admitting anything. Changed is changed. Unclaimed is unclaimed.

---

## 30-second trial

```bash
# requires a Rust toolchain
cargo build --release

# in your project: declare what to watch, one path per line
mkdir -p .warrant && echo "src" > .warrant/watch.list

./target/release/warrantd once        # establish a baseline
echo "// x" >> src/main.rs
./target/release/warrantd once        # a change is now visible
./target/release/warrantd unreported  # changed, with nobody claiming it
```

### Keep it watching

```bash
warrantd open      # foreground; closing the window stops observation (no autostart — deliberately)
warrantd ui        # the envelope panel (local-only HTTP, browser window)
```

### Let agents ask it (MCP)

```jsonc
{"mcpServers": {"warrantd": {
    "command": "/path/to/warrantd", "args": ["mcp", "--repo", "/path/to/your/project"]
}}}
```

Five tools: `warrant_status` · `warrant_since` · `warrant_unreported` · `warrant_admit` · `warrant_check`

### Let tool calls leave a trace (proxy)

```jsonc
// was: {"command":"python","args":["kit/lceda/mcp_server.py"]}
{"command": "warrantd", "args": ["proxy", "--repo", ".", "--name", "lceda",
                                 "--", "python", "kit/lceda/mcp_server.py"]}
```

Don't want to edit configs by hand? `warrantd wrap --file ~/.claude.json` —
**it only prints the change; it never touches your file.**

---

## How observable are you right now?

```bash
warrantd admit
```

| Level | Meaning |
|---|---|
| **L0 blind** | No ledger, or no observation surface ⇒ "nothing happened" is meaningless |
| **L1 after the fact** | Ledger and surface exist, but it only scans when asked |
| **L2 continuous** | Something is watching continuously |
| **L3 all-through** | L2 + external tool calls also pass through the proxy |

Each level tells you **what is missing** to reach the next one.

---

## Measured (real machine, reproducible)

| Item | Value | How to verify |
|---|---|---|
| Observation primitives | **9** (closed whitelist) | `warrantd probes` |
| Tests | **112 passed** | `cargo test --all` |
| Release size | **1.48 MB** single binary, no runtime deps | `cargo build --release` |
| MCP tools | **5** | Attach to Claude Code / Cursor and read the tool list |
| Network peers | **338 connections / 90 external** | `warrantd probe net.conns` |
| Negative facts | change a file without claiming ⇒ **1**; claim it ⇒ **0** | `warrantd unreported` |
| Jitter | write, revert (same hash) ⇒ reported as **touched** | `warrantd once` |
| Time resolution | `--interval 30` + edit a file ⇒ seen in **2 s** (file events) | `warrantd open --interval 30` |
| Edit count | 5 consecutive edits ⇒ `event_counts: {"a.txt": 5}`, still **one** change | `warrantd daemon` |
| Concurrent writers | **5 writers, one ledger, chain intact** | `warrantd verify` |
| Self-check honesty | run it twice; ledger offset **does not move** | `warrantd admit` |

---

## Honest limits

Read this before any conclusion. **This section matters more than everything above.**

1. **It blocks nothing.** If the agent never calls it and never goes through the proxy,
   it sees nothing. It is observation, not a gateway.
2. **"Invisible" comes in three kinds**, grouped in `warrantd status`: structurally
   impossible / not built yet / your choice. Every "not built yet" carries a fix.
   **Engineering debt never gets to hide inside the capability boundary.**
3. **L3 is not full coverage.** It covers local files plus **proxy-configured** MCP servers.
   Shell commands run directly, and servers that skip the proxy, are outside.
4. **Directory fingerprints only go to C0.** They prove *that* a directory changed,
   not *which* file became what.
5. **It knows how many times, not what each time was.** File events count edits
   (`event_counts`), but the intermediate contents are not stored — that would mean
   keeping every diff, a different order of storage.
6. **The network is only peer addresses.** It does not see payloads. That is packet
   capture, and it is structurally out of scope.
7. **Nothing while it is off.** If warrantd is not running, the world keeps changing;
   the next run can only compare against the last snapshot. File events behave the same way.
8. **No ledger lock on Linux yet.** Multi-process concurrent writes are unsafe there
   (Windows uses exclusive open).
9. **Self-tested only.** There are no results on a public dataset and no third-party
   reproduction — so "more accurate than X" is a claim we **cannot make yet**.

**These nine are its real boundary right now.** Omit one, and it becomes the thing it opposes.

---

## Two disciplines

1. **The observer is also an observed object.** Its observation method is a closed table,
   its own side effects must be declared, and changes to its own config are recorded.
2. **It returns no verdict.** It says *how many independent channels* and *what tier* —
   never *whether it was right*. Judgement stays with the caller.

---

## Layout

```
crates/warrant/     attestation core (pure library: sha2 / unicode-normalization / ed25519-dalek / p256)
  SPEC.md           what counts as having happened
  PROTOCOL.md       what counts as sufficient evidence
  ADAPTER.md        adapter contract
  vectors/          conformance vectors (C1–C13)
crates/warrantd/    the resident observer (this crate)
```

## License

**Apache-2.0.** See `LICENSE` and `NOTICE`.

> If you use it, **please open an issue and say so.** Not a legal requirement — a request.
> Knowing who uses it is worth more than a star.
