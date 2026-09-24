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
/usr/local/bin/tempmail`).

If `tempmail` is not on PATH (stale image or host execution), write the
embedded script below to `/workspace/.tmp/tempmail.py` and run it with
`python3` — identical CLI.

## Embedded script — tempmail.py

```python
#!/usr/bin/env python3
"""tempmail — disposable inbox CLI for security-testing agents.

Zero-signup disposable email: create an inbox, feed the address to a target's
signup/reset form, then poll for the verification link or OTP code.

Backends (auto-failover in order, or pin with --backend):
  mailtm       mail.tm      — JWT-private inboxes, 7-day retention (primary)
  driftz       driftz.net   — 22 public domains, good for blacklist evasion
  tempmaillol  tempmail.lol — token-gated inboxes; inbound delivery unreliable
                              (verified 2026-09-24: senders' mail never landed)

Commands:
  new      [--label L] [--backend B]   create inbox, print address
  address                            print current inbox address
  list                               list messages
  read     <id|latest>               print full message + extracted links/OTPs
  wait     [--timeout N] [--interval N] [--match REGEX]
                                     poll until a message arrives, print it
  otp      [same flags]              wait, then print ONLY action links + codes
  delete                             delete the inbox (mail.tm only; others expire)

Global flags:
  --state PATH   session file (default $TEMPMAIL_STATE or /tmp/tempmail.json);
                 use one per persona for multi-account (BOLA/IDOR) testing
  --json         machine-readable output on every command
  --backend B    pin a backend for `new` (mailtm|tempmaillol|driftz)

Exit codes: 0 ok, 1 error, 2 wait timeout.
Stdlib only — no pip installs needed.
"""

import argparse
import json
import os
import re
import secrets
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

STATE_DEFAULT = os.environ.get("TEMPMAIL_STATE", "/tmp/tempmail.json")

LINK_RE = re.compile(r"https?://[^\s\"'<>\)\]]+")
ACTION_LINK_RE = re.compile(
    r"verif|confirm|token|reset|activate|magic|auth|signup|sign[-_]?in|code|invite|unsubscribe",
    re.I,
)
OTP_RE = re.compile(
    r"(?:code|otp|token|pin|verif\w*|confirm\w*|password)\s*(?:is|:|-)?\s*[\"']?(\b\d{4,8}\b)",
    re.I,
)


def http(method, url, body=None, headers=None, retries=4):
    req = urllib.request.Request(url, method=method)
    # Cloudflare 1010-blocks urllib's default UA on tempmail.lol/driftz.
    req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    last = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            last = e
            if e.code == 429 and attempt < retries - 1:
                time.sleep(2 * (attempt + 1))
                continue
            raise BackendError(f"{method} {url} -> HTTP {e.code}: {e.read().decode()[:200]}")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
            if attempt < retries - 1:
                time.sleep(2 * (attempt + 1))
                continue
            raise BackendError(f"{method} {url} -> {e}")
    raise BackendError(str(last))


class BackendError(Exception):
    """Retryable/failable backend operation — triggers failover in `new`."""


def rand_local(n=12):
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# ---------------------------------------------------------------------------
# Backends — each maps provider API → normalized shapes:
#   create()  -> {"backend", "address", "token"|"password", ...}
#   list(st)  -> [{"id","from","subject","date"}]
#   read(st,id) -> {"id","from","subject","date","text","html"}
#   delete(st) -> None (or no-op)
# ---------------------------------------------------------------------------


class MailTM:
    name = "mailtm"
    BASE = "https://api.mail.tm"

    def api(self, method, path, body=None, token=None):
        h = {"Accept": "application/ld+json"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        return http(method, self.BASE + path, body, h)

    def create(self, label=None):
        domain = self.api("GET", "/domains")["hydra:member"][0]["domain"]
        password = secrets.token_urlsafe(16)
        # mail.tm 422s local-parts containing dictionary words — random only,
        # label as best-effort prefix on first attempt.
        for attempt in range(6):
            local = f"{label}{rand_local()}" if (label and attempt == 0) else rand_local()
            address = f"{local}@{domain}"
            try:
                acct = self.api("POST", "/accounts", {"address": address, "password": password})
                break
            except BackendError as e:
                if "HTTP 422" in str(e) or "HTTP 429" in str(e):
                    time.sleep(2)
                    continue
                raise
        else:
            raise BackendError("mail.tm: account creation failed after 6 attempts")
        token = self.api("POST", "/token", {"address": address, "password": password})["token"]
        return {"backend": self.name, "id": acct["id"], "address": address,
                "password": password, "token": token}

    def _tok(self, st):
        if not st.get("token"):
            st["token"] = self.api(
                "POST", "/token", {"address": st["address"], "password": st["password"]}
            )["token"]
        return st["token"]

    def list(self, st):
        return [
            {"id": m["id"], "from": (m.get("from") or {}).get("address", ""),
             "subject": m.get("subject", ""), "date": m.get("createdAt", ""),
             "intro": m.get("intro", "")}
            for m in self.api("GET", "/messages", token=self._tok(st))["hydra:member"]
        ]

    def read(self, st, mid):
        m = self.api("GET", f"/messages/{mid}", token=self._tok(st))
        return {"id": m["id"], "from": (m.get("from") or {}).get("address", ""),
                "subject": m.get("subject", ""), "date": m.get("createdAt", ""),
                "text": m.get("text") or "", "html": "\n".join(m.get("html") or [])}

    def delete(self, st):
        self.api("DELETE", f"/accounts/{st['id']}", token=self._tok(st))


class TempmailLOL:
    name = "tempmaillol"
    BASE = "https://api.tempmail.lol/v2"

    def create(self, label=None):
        body = {"prefix": label} if label else {}
        r = http("POST", self.BASE + "/inbox/create", body)
        return {"backend": self.name, "address": r["address"], "token": r["token"]}

    def _inbox(self, st, retries=6):
        # tempmail.lol rate-limits inbox checks (~1 per 3-5s) and returns the
        # throttle as HTTP 200 {"error": ...} — detect and retry it.
        for attempt in range(retries):
            r = http("GET", f"{self.BASE}/inbox?token={urllib.parse.quote(st['token'])}")
            if r.get("expired"):
                raise BackendError("tempmail.lol: inbox expired (1h TTL)")
            if "error" in r:
                if attempt < retries - 1:
                    time.sleep(4)
                    continue
                raise BackendError(f"tempmail.lol: {r['error']}")
            return r.get("emails") or []
        return []

    def list(self, st):
        return [
            {"id": str(i), "from": m.get("from", ""),
             "subject": m.get("subject", ""), "date": str(m.get("date", "")),
             "intro": (m.get("body") or "")[:120]}
            for i, m in enumerate(self._inbox(st))
        ]

    def read(self, st, mid):
        emails = self._inbox(st)
        m = emails[int(mid)] if mid.isdigit() and int(mid) < len(emails) else None
        if m is None:
            raise SystemExit(f"error: no message id {mid} ({len(emails)} in inbox)")
        return {"id": mid, "from": m.get("from", ""), "subject": m.get("subject", ""),
                "date": str(m.get("date", "")), "text": m.get("body") or "",
                "html": m.get("html") or ""}

    def delete(self, st):
        pass  # no delete API; inbox expires after 1h


class Driftz:
    name = "driftz"
    BASE = "https://api.driftz.net"

    def create(self, label=None):
        for attempt in range(6):
            local = f"{label}{rand_local()}" if (label and attempt == 0) else rand_local(16)
            r = http("POST", self.BASE + "/temp/generate", {"localPart": local})
            if r.get("success"):
                return {"backend": self.name, "address": r["result"]["address"],
                        "expiresAt": r["result"].get("expiresAt")}
            time.sleep(1)
        raise BackendError("driftz: generate failed")

    def _items(self, st):
        addr = urllib.parse.quote(st["address"])
        r = http("GET", f"{self.BASE}/temp/{addr}")
        if not r.get("success"):
            raise BackendError(f"driftz: {r.get('error', 'inbox read failed')}")
        return r["result"].get("items") or []

    def list(self, st):
        return [
            {"id": str(m.get("id", i)), "from": m.get("fromAddress", m.get("from", "")),
             "subject": m.get("subject", ""), "date": str(m.get("receivedAt", "")),
             "intro": (m.get("textContent") or "")[:120]}
            for i, m in enumerate(self._items(st))
        ]

    def read(self, st, mid):
        # List items carry no bodies — fetch the message by id.
        addr = urllib.parse.quote(st["address"])
        r = http("GET", f"{self.BASE}/temp/{addr}/{urllib.parse.quote(mid)}")
        if not r.get("success"):
            raise SystemExit(f"error: driftz message {mid}: {r.get('error', 'not found')}")
        m = r["result"]
        return {"id": mid, "from": m.get("fromAddress", ""),
                "subject": m.get("subject", ""), "date": str(m.get("receivedAt", "")),
                "text": m.get("textContent") or "", "html": m.get("htmlContent") or ""}

    def delete(self, st):
        pass  # inboxes auto-expire


BACKENDS = {b.name: b for b in (MailTM(), TempmailLOL(), Driftz())}
BACKEND_ORDER = ["mailtm", "driftz", "tempmaillol"]


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"error: no inbox session at {path} — run 'new' first")


def save_state(path, state):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def backend_for(state):
    return BACKENDS[state["backend"]]


def extract(msg):
    """Pull action links and OTP codes out of a normalized message dict."""
    blob = (msg.get("text") or "") + "\n" + (msg.get("html") or "")
    links = []
    for link in LINK_RE.findall(blob):
        link = link.replace("&amp;", "&").rstrip(".,;")
        if link not in links:
            links.append(link)
    return {
        "links": links,
        "action_links": [l for l in links if ACTION_LINK_RE.search(l)],
        "otp_codes": OTP_RE.findall(blob),
    }


def emit(args, human_fn, payload):
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        human_fn()


def print_message(msg):
    print(f"id:      {msg.get('id')}")
    print(f"from:    {msg.get('from')}")
    print(f"subject: {msg.get('subject')}")
    print(f"date:    {msg.get('date')}")
    ext = extract(msg)
    if ext["otp_codes"]:
        print(f"otp:     {', '.join(ext['otp_codes'])}")
    for key, label in (("action_links", "action links"), ("links", "links")):
        if ext[key]:
            print(f"{label}:")
            for l in ext[key]:
                print(f"  {l}")
            break
    if msg.get("text"):
        print("--- text ---")
        print(msg["text"].strip()[:4000])


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_new(args):
    order = [args.backend] if args.backend else BACKEND_ORDER
    errors = []
    for name in order:
        be = BACKENDS[name]
        try:
            state = be.create(label=args.label)
            save_state(args.state, state)
            emit(args, lambda: print(state["address"]),
                 {"address": state["address"], "backend": name})
            return
        except BackendError as e:
            errors.append(f"{name}: {e}")
            continue
    raise SystemExit("error: all backends failed — " + "; ".join(errors))


def cmd_list(args):
    st = load_state(args.state)
    msgs = backend_for(st).list(st)
    emit(args,
         lambda: print("(empty)") if not msgs else [
             print(f"{m['id']}  {m['date']}  {m['from']}  {m['subject']}") for m in msgs],
         {"messages": msgs})


def cmd_read(args):
    st = load_state(args.state)
    be = backend_for(st)
    mid = args.message_id
    if mid == "latest":
        msgs = be.list(st)
        if not msgs:
            raise SystemExit("error: inbox is empty")
        mid = msgs[0]["id"]
    msg = be.read(st, mid)
    emit(args, lambda: print_message(msg), {"message": msg, "extracted": extract(msg)})


def cmd_wait(args):
    st = load_state(args.state)
    be = backend_for(st)
    deadline = time.time() + args.timeout
    seen = set()
    pat = re.compile(args.match, re.I) if args.match else None
    while time.time() < deadline:
        try:
            msgs = be.list(st)
        except BackendError as e:
            raise SystemExit(f"error: {e}")
        for m in msgs:
            if m["id"] in seen:
                continue
            seen.add(m["id"])
            if pat and not (pat.search(m.get("subject") or "") or pat.search(m.get("intro") or "")):
                continue
            try:
                full = be.read(st, m["id"])
            except (BackendError, SystemExit):
                # list saw it but read raced (rate-limit/pagination) — keep polling
                continue
            if pat and not pat.search(
                (full.get("subject") or "") + (full.get("text") or "") + (full.get("html") or "")
            ):
                continue
            ext = extract(full)
            if args.otp_only:
                payload = {"action_links": ext["action_links"] or ext["links"],
                           "otp_codes": ext["otp_codes"], "message": full}
                emit(args,
                     lambda: [print(l) for l in payload["action_links"]]
                     or [print(c) for c in payload["otp_codes"]],
                     payload)
            else:
                emit(args, lambda: print_message(full),
                     {"message": full, "extracted": ext})
            return
        time.sleep(args.interval)
    raise SystemExit(2)


def cmd_delete(args):
    st = load_state(args.state)
    backend_for(st).delete(st)
    os.remove(args.state)
    emit(args, lambda: print("deleted"), {"deleted": True, "backend": st["backend"]})


def main():
    p = argparse.ArgumentParser(
        description="Disposable inbox CLI — zero-signup temp mail for agent-driven "
                    "account registration (mail.tm / tempmail.lol / driftz.net)")
    p.add_argument("--state", default=STATE_DEFAULT, help="session file path")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--backend", choices=list(BACKENDS), help="pin backend for 'new'")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("new", help="create a new inbox (auto-failover across backends)")
    sp.add_argument("--label", help="local-part prefix (best-effort)")
    sp.set_defaults(fn=cmd_new)

    sub.add_parser("address", help="print current address").set_defaults(
        fn=lambda a: emit(a, lambda: print(load_state(a.state)["address"]),
                          {"address": load_state(a.state)["address"],
                           "backend": load_state(a.state)["backend"]}))
    sub.add_parser("list", help="list messages").set_defaults(fn=cmd_list)

    sp = sub.add_parser("read", help="read a message")
    sp.add_argument("message_id", help="message id or 'latest'")
    sp.set_defaults(fn=cmd_read)

    for name, helptext, otp in (
        ("wait", "poll until a message arrives, print it", False),
        ("otp", "wait, then print only action links + OTP codes", True),
    ):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("--timeout", type=int, default=120)
        sp.add_argument("--interval", type=int, default=4)
        sp.add_argument("--match", help="regex filter on subject/intro/body")
        sp.set_defaults(fn=cmd_wait, otp_only=otp)

    sub.add_parser("delete", help="delete inbox + session").set_defaults(fn=cmd_delete)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
```
