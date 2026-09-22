---
name: task-formation
description: Task-formation pass before dispatching hunters — consolidate raw observations into testable hypotheses, merge by fingerprint, split by boundary, skip empty queues
---

# Task Formation

Raw observations — scanner hits, code reads, crawl output, recon notes — are not tasks. Dispatching hunters against raw observations produces duplicated work, merged contexts, and hunters testing the same code path five ways. Run a task-formation pass first: consolidate observations into discrete, testable hypotheses, then dispatch.

## The Boundary Rule

> **One task = one attacker-controlled input reaching one dangerous operation in one context.**

- **One input**: a single request-derived value (or a set of aliases for the same value — `userId`, `user_id`, `id` bound to the same field).
- **One dangerous operation**: one sink call site — one `execute()`, one `open(w)`, one `fetch()`. A shared sink, CWE, file, line, payload, impact, or fix is *supporting evidence*, not a grouping reason.
- **One context**: one injection/render/authorization context — SQL value vs SQL identifier, HTML body vs JS string vs attribute, owner-check vs role-check.

Read `source`, `combined_sources`, `path`, and `sink_call` as one data flow. Use the slot type and observed sanitization to distinguish the context and its defense.

## Merge

Merge observations into one task when they share a root cause **and** one proof settles all of them:

- Same sink call site reached by different input aliases.
- Same flow reported by two tools (semgrep hit + manual read + SARIF row).
- Same parameterized route discovered at different concrete URLs (`/user/1`, `/user/2` → one `/user/:id` task).

Fingerprint for merge: normalized route + sink location + input field. Group only when a single proof against one controlled input and one dangerous operation would settle every observation with one verdict.

## Split

Split into separate tasks when observations differ in:

- **Input** — independently controlled values (`id` vs `filename` hitting the same handler).
- **Context** — same sink, different render/injection context (HTML body vs attribute; value vs identifier).
- **Defenses** — materially different controls on different paths (one route behind a WAF rule or sanitizer, sibling route not).
- **Operation** — different sink call sites, even of the same class. Each reachable instance stands or falls on its own — never collapse two call sites into one task because they share a root cause.

## Task Shape

Every emitted task carries:

- `hypothesis` — one sentence: "input X reaches dangerous op Y in context Z without control W".
- `source` / `sink` — concrete locations (route+param, file:line).
- `context` — the injection/render/authz context that determines payload shape.
- `witness_payload` — the minimal probe that distinguishes vulnerable from safe.
- `hunter_class` — which specialist queue it lands in (injection, xss, authz, ssrf, …).

## Queue Gating

Dispatch a hunter class **only if its queue is non-empty**. If task formation produces zero injection tasks, no injection hunter spawns — an empty queue is a clean signal, not a gap. Record the skip so the coverage critic can distinguish "no candidates existed" from "nobody looked".

## Rules

1. Task formation runs **before** dispatch, every wave — not once at scan start.
2. Merge by fingerprint, split by boundary — when in doubt, split: two narrow tasks beat one confused one.
3. A task without a `witness_payload` is not formed — it is an observation.
4. Never dispatch a hunter against an empty queue.
5. Observations that survive neither merge nor split (unverifiable, no reachable source) go to `needs_follow_up` with the gap named — not into a task.
