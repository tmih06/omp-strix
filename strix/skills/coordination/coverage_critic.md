---
name: coverage-critic
description: Post-wave coverage-critic protocol — a fresh reviewer audits the coverage ledger for gaps after every hunter wave and loops until a clean pass
---

# Coverage Critic

Hunters grade their own homework if you let them. After every hunter wave, spawn a **fresh critic** — an agent with no stake in the wave's results — to audit the coverage ledger against the attack surface. The critic reads the ledger, not the hunters' self-reports; a hunter's summary is a claim, the ledger is the record.

## When to Run

- After **every** hunter wave, before the next wave is dispatched.
- Before `finish_scan`, unconditionally — the last wave gets a critic too.
- Quick mode: exactly one hunter wave + one critic pass. No loop, no second wave — the critic's output is the final gap list.

## What the Critic Checks

Audit the ledger (`list_coverage`) against the threat model and discovered surface. Flag each of these:

1. **Unmapped entry points** — routes, params, or services discovered in recon with no coverage entry at all. Unvisited is indistinguishable from clean unless the ledger says otherwise.
2. **Unchecked parallel paths** — the same operation reachable through a second transport or route: REST vs GraphQL, web vs API, `/api/v1` vs `/api/v2`, admin alias for a user route. If one path was tested and its sibling was not, that is a gap.
3. **Missing lifecycle modes** — a surface tested in one mode but not others: unauthenticated vs authenticated, low-priv vs admin, single-tenant vs cross-tenant, create vs update vs delete on the same object.
4. **Selected attack classes without a unit** — a vuln class in scope for this scan (per threat model or scan mode) with no task that ever covered it. An empty queue is a decision; an unexamined class is a hole.
5. **Unjustified exclusions** — surfaces skipped or marked `not_applicable` without a recorded reason, or with a reason that does not hold ("internal only" never verified, "probably static" on a parameterized route).
6. **Units closed without evidence** — `ruled_out` entries that name no control, `no_issue_found` with empty evidence, `reported` with no linked report. A closure without evidence is an open item wearing a costume.

## Critic Output

The critic emits exactly two lists:

- `missing_units` — surfaces/classes needing a new task: `{surface, class, reason}`.
- `reassign_ids` — existing ledger entries whose state is wrong and must be reopened or re-dispatched: `{entry_id, correct_state, reason}`.

Every flag names the concrete gap. "Coverage looks thin" is not a finding; "`POST /api/export` has no authenticated-mode entry" is.

## The Loop

```
hunter wave → critic → missing_units/reassign_ids → dispatch fixes → critic → … → clean pass
```

- A **clean pass** means both lists empty — not small, empty.
- Dispatch the missing units as a new wave (or fold into the running one), then re-run the critic on the updated ledger.
- Loop until clean or until the scan's mode budget forces a stop — in which case every remaining gap is deferred, not dropped.

## Deferred Units

A unit that cannot run (missing credentials, unreachable service, out of scope pending clarification) is recorded with `record_coverage(outcome="needs_follow_up")` and the **specific reason** in evidence. Deferred units are data — they tell the report reader exactly what was not tested and why. A unit silently dropped is a lie by omission.

## Rules

1. The critic is always a fresh context — never the hunter that did the work, never the orchestrator that dispatched it.
2. The critic audits the ledger, not the conversation. If it isn't recorded, it didn't happen.
3. Reassign beats duplicate: fix a wrong entry with `update_coverage` rather than recording a parallel one.
4. A clean pass is the only exit — "good enough" is a deferred unit list with reasons.
5. Quick mode is one wave + one critic; the critic's gap list goes straight into the report's coverage section.
