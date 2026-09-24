---
name: tempmail
description: Disposable email inboxes for registering accounts on the target — receive verification links, OTP codes, and password-reset emails to unlock authenticated attack surface. Baked into the sandbox image as `tempmail`.
---

# Temp Mail — Disposable Inboxes for Account Registration

Use this when the target has a signup/login wall and deeper scanning requires an
authenticated session: register a throwaway account, receive the verification
email (link or OTP), complete signup, then harvest the session for downstream
agents.

The `tempmail` CLI is **already installed** in the sandbox at
`/usr/local/bin/tempmail` — just run it. Stdlib-only Python, no setup.

## Commands

```bash
tempmail new                        # create inbox → prints the address (save it)
tempmail new --backend driftz       # pin a backend (mailtm|driftz|tempmaillol)
tempmail address                    # re-print current address
tempmail list                       # list messages
tempmail read latest                # full message + extracted links/OTP codes
tempmail wait --timeout 120         # poll until mail arrives, print it
tempmail wait --match 'verif'       # only match subject/body regex
tempmail otp --timeout 60           # print ONLY action links + OTP codes
tempmail delete                     # destroy inbox + session file
tempmail --json <cmd>               # machine-readable output on any command
```

Multiple inboxes: pass `--state /tmp/tm_<name>.json` to keep separate sessions
(e.g. one per test persona — needed for BOLA/IDOR cross-account testing).

## Backends (auto-failover)

`new` tries backends in order and falls over automatically:

1. **mailtm** (mail.tm) — primary. JWT-private inboxes, 7-day retention.
2. **driftz** (driftz.net) — 22 rotating public domains; best for evading
   disposable-domain blacklists.
3. **tempmaillol** (tempmail.lol) — token-gated, 1h TTL; inbound delivery is
   unreliable (verified 2026-09-24 — senders' mail never landed). Last resort.

Pin one with `--backend <name>` when you need a specific provider (e.g.
`--backend driftz` to get a fresh domain when the target blocks mail.tm's).

## Registration workflow

1. `tempmail new` → capture the printed address.
2. Submit the target's signup form with that address (curl or browser flow).
   Use a strong random password — record it.
3. `tempmail wait --timeout 120 --match 'verif|confirm|welcome'`
   → prints the message with `action links:` already extracted.
   Or `tempmail otp` to get only the links/codes.
4. Follow the verification link (curl GET) or submit the OTP code.
5. Log in on the target; capture cookies/tokens.
6. `record_artifact` the credential set (email + password + session token) so
   hunters can replay it for authenticated testing and BOLA/IDOR sweeps.
7. `login_and_save_session` if the scan needs a persistent browser session.
8. `tempmail delete` when done (mail.tm only; driftz/tempmail.lol auto-expire).

## Password reset testing

`tempmail wait --match 'reset'` after triggering the target's forgot-password
flow — the reset link lands the same way. Useful for testing reset-token
entropy, token reuse, and whether reset links expire.

## Known pitfalls (verified 2026-09-24)

- **Disposable-domain blacklists**: some targets reject temp-mail domains at
  signup (e.g. mastodon.social rejects mail.tm's `uberip.com` with
  `ERR_BLOCKED` but accepted a driftz domain). If rejected, retry
  `tempmail new --backend driftz` for a different domain — don't burn time
  re-trying the same one.
- **Username rule**: mail.tm rejects local-parts containing dictionary words
  (`test`, `user`, `agent`) with 422 — the tool generates random local-parts;
  don't pass English words to `--label`.
- **Rate limits**: mail.tm ~8 QPS/IP (auto-backed-off); tempmail.lol throttles
  inbox reads to ~1 per 3-5s (handled internally). Keep `--interval` ≥ 4s.
- **Public inboxes**: driftz inboxes are world-readable by address — never put
  real secrets in them; mail.tm inboxes are JWT-private.
- **No send**: all backends are receive-only. To trigger mail, drive the
  target's own signup/reset/login-email flows.
- **tempmail.lol inbound is flaky**: mail may never arrive — if `wait` times
  out on it, recreate with `--backend driftz` or `mailtm`.

## Source

Canonical source: `strix/tools/tempmail.py` in the omp-strix repo; baked into
the sandbox image via `sandbox/Dockerfile` (`COPY tempmail.py
/usr/local/bin/tempmail`). If running outside the sandbox, copy that file and
invoke `python3 tempmail.py` — identical CLI.
