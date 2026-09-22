---
name: tool-recovery
description: Fallback matrix and rate-limit backoff for when a security tool fails, hangs, or gets WAF-blocked — plus partial-output salvage
---

# Tool Recovery

Tools fail constantly in real engagements: missing binaries, timeouts, WAF blocks, rate limits. The failure is never the end of the task — it is a routing decision. Diagnose the failure class, apply the matching recovery, and keep the evidence the failed run already produced.

## Failure Taxonomy

| Symptom | Class | First move |
|---|---|---|
| `command not found`, `No such file` | not installed | `apt`/`pip`/binary install, or jump straight to fallback |
| killed by timeout, no output | hang | bound with `timeout -k`, narrow scope, then fallback |
| HTTP 429, `retry-after`, `x-ratelimit-*` | rate-limited | drop a timing profile, retry |
| 403 on every request, CAPTCHA pages, connection resets after bursts | WAF-blocked | drop timing profile; if still blocked, switch tool family |
| empty results where hits expected | filtered/quiet | verify with a known-good probe before trusting the zero |

## Fallback Matrix

| Failed tool | Fallbacks (in order) |
|---|---|
| `nmap` | `rustscan -a <t> -r 1-65535 -- -sV` → `masscan --rate 1000 -p1-65535` |
| `gobuster` | `feroxbuster -u <url> -t 20` → `ffuf -u <url>/FUZZ -w <wl>` → `dirsearch -u <url>` |
| `arjun` | `paramspider -d <domain>` → `x8 -u <url> -w <params>` → `ffuf` param fuzz (`-d`/`?FUZZ=1`) |
| `subfinder` | `amass enum -passive -d <domain>` → `assetfinder --subs-only <domain>` |
| `nuclei` | `nikto -h <url>` → `dalfox url <url>` for XSS-class → single-template `nuclei -t <tpl>` |
| `katana` | `gau <domain>` → `waybackurls <domain>` → `hakrawler -url <url>` |
| `sqlmap` | manual probes: `'` error-based → boolean pair (`AND 1=1`/`AND 1=2`) → `AND SLEEP(5)` time-based |
| `dalfox` | `kxss` on reflected params → manual context probe (`<svg onload=1>`, `"'><img src=x>`) |
| `hydra` | `nxc <proto> <host> -u <user> -p <passfile>` (netexec) → `hydra` with `-t 4 -W 2` |
| `httpx` (probe) | `curl -skI` per host → `nmap --script http-title` |
| `dnsx` | `dig +short` loop → `massdns` |
| `wpscan` | `nuclei -tags wordpress` → manual `wp-content`/`wp-json` enumeration |

## Rate-Limit Detection

Watch stdout/stderr and response headers for: `429`, `403` storms, `retry-after`, `x-ratelimit-remaining: 0`, `x-ratelimit-reset`, `rate limit`, `too many requests`, `throttle`, `slow down`, `quota exceeded`, connection resets after a burst.

On detection, drop one timing profile and retry — never retry at the same rate:

| Profile | Threads | Delay | Timeout |
|---|---|---|---|
| aggressive | 50 | 0.1s | 5s |
| normal | 20 | 0.5s | 10s |
| conservative | 10 | 1.0s | 15s |
| stealth | 5 | 2.0s | 30s |

Rewrite the flags, don't just wait: `-t`/`--threads`, `--delay`, `-rate`, `-rl`, `-c`/`--concurrency` per tool. Start at `normal` on unknown targets; `aggressive` only on confirmed-unprotected infra.

## Partial-Output Salvage

A timeout kills the process, not the discoveries. Always:

1. Tee long scans to a file: `tool ... | tee out.txt` or `-o out.txt`.
2. On timeout, read the partial file — 90% of ports/dirs are usually already there.
3. Resume with narrowed scope (remaining ports, deeper path) instead of re-running the whole sweep.
4. Mark salvaged results as partial in coverage notes so nobody trusts them as complete.

## Rules

1. Never run the identical failing command a third time — change a parameter or change the tool.
2. Two failures from the same tool family → switch families, not flags.
3. Bound every network command: `timeout -k 5s <N>s <cmd>` plus the tool's own timeout flag.
4. A WAF block on one tool is a signal about the *target*, not the tool — record it (`create_note`) for the next agent.
5. Verify a suspicious zero with a known-good probe (request a path you know exists) before recording `no_issue_found`.
