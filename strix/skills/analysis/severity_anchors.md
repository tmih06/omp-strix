---
name: severity-anchors
description: Anchor definitions for each severity level — what actually qualifies, the demonstrated-impact ceiling, and the high/medium discriminator question
---

# Severity Anchors

Anchors, not vibes. Each level is defined by what the exploit *demonstrably does*, not by what it might lead to. Rate the weakness you proved — severity never exceeds demonstrated impact.

Apply after reachability and counterevidence are established. Pair with `severity_calibration` (CVSS honesty checklist); this file is the anchor set it calibrates against.

## The Ceiling Rule

**Severity never exceeds demonstrated impact.** A finding is rated on the effect you observed, not the worst case reachable through a chain of unproven assumptions. "Could become RCE if…" is a medium with a `severity_change_conditions` note, not a critical.

**`needs_validation` carries NO severity.** An unvalidated candidate has no rating — not "provisional high", not "potential critical". It gets a validation task, not a number.

## Anchors

### Critical

Decisive control or mass access, demonstrated:

- Unauthenticated remote code execution on a reachable surface.
- Full data-store access — arbitrary read/write across the database or equivalent.
- Arbitrary account takeover — any account, no interaction (auth bypass, forgeable tokens, mass IDOR on credentials/sessions).

### High

Fully defeats an explicit security control:

- Authentication bypass — you are in, and you were not supposed to be.
- Cross-tenant read or write — isolation boundary broken, proven with a second tenant's data.
- Stored XSS executing on other users.
- Authenticated RCE — code execution behind a real login.
- Unauthenticated remote stop — anyone can kill the service.

### Medium

A real boundary violation with limited blast radius:

- Single-user or single-object authorization failures.
- Reflected XSS requiring interaction; stored XSS in self-only contexts.
- CSRF on a meaningful state change.
- Scoped data exposure — real leak, narrow set.
- The high-impact version exists but is blocked by a confirmed constraint (privileged role required, internal-only reachability).

### Low

- Non-secret internals exposed — version strings, stack traces, internal paths.
- Sustained-effort/minimal-gain issues — enumeration, weak rate limits, verbose errors that aid but do not enable.
- Self-XSS, clickjacking on non-sensitive actions, missing hardening headers.

### Informational

- Confirmed prerequisite with minimal standalone impact — a version fingerprint that matters only if a CVE applies, a config note that shortens a real attack.
- Defense-in-depth gaps with no reachable path today.

## The High/Medium Discriminator

When torn between high and medium, ask one question:

> **Did this fully defeat an explicit security control, or is it a boundary violation with limited blast radius?**

- Full defeat of a control the system advertises (auth check, tenant isolation, role gate) → **high**.
- A real violation that stops short of full defeat — one object, one user, one narrow scope → **medium**.

If the honest answer needs a paragraph of caveats, it is medium.

## Rules

1. Demonstrated impact is the ceiling — imagine nothing.
2. `needs_validation` = no severity, ever.
3. Constrained findings get downgraded, not deleted — say what the constraint is.
4. Missing evidence lowers **confidence**, not the severity floor — "couldn't confirm exposure" is not "internal only".
5. State `severity_change_conditions`: the one piece of evidence that would move the rating.
