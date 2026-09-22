---
name: recon-pipeline
description: Deterministic recon chain — subdomains to deduped routes — with tech-fingerprint-to-tool-parameter mapping and per-surface coverage recording
---

# Recon Pipeline

Recon is a deterministic chain, not a bag of commands. Each stage consumes the previous stage's output, dedupes it, and produces a typed artifact for the next. Run the stages in order; skip a stage only when its input set is empty — and say so in coverage.

## The Chain

```
subdomains → resolve → port scan → HTTP probe → crawl → params → normalize → coverage
```

### 1. Subdomain enumeration

```bash
subfinder -d example.com -all -recursive -silent -o subs_sf.txt
amass enum -passive -d example.com -o subs_amass.txt
assetfinder --subs-only example.com > subs_af.txt
cat subs_*.txt | anew subs.txt          # dedupe, keep first-seen order
```

`anew` appends only lines not already in the file — use it at every merge point, not just here.

### 2. DNS resolution

```bash
dnsx -l subs.txt -a -resp -silent -o resolved.txt
```

Drop names that don't resolve; keep the A/AAAA answers — they feed port scanning and vhost pivoting.

### 3. Port scan

```bash
naabu -list resolved.txt -top-ports 1000 -verify -silent -o ports.txt
# or fast full-range:
rustscan -a resolved.txt -r 1-65535 -- -sV -oN nmap_sv.txt
```

Always finish with `nmap -sV` (or rustscan's `-- -sV` handoff) on the open set — service banners drive the fingerprint table below.

### 4. HTTP probe

```bash
httpx -l ports.txt -tech-detect -status-code -title -server -tls-grab -json -o web.jsonl
```

Keep: status, title, tech stack, server header, cert SANs (each SAN is a new subdomain seed — loop back to stage 1).

### 5. Crawl / URL collection

```bash
katana -list web_urls.txt -d 3 -jc -kf all -silent -o urls_katana.txt
gau --threads 5 example.com > urls_gau.txt
waybackurls example.com > urls_wayback.txt
cat urls_*.txt | anew urls.txt
```

### 6. Parameter discovery

```bash
arjun -u <url> -m GET,POST --stable
paramspider -d example.com
x8 -u <url> -w params.txt
```

Harvest every parameter name into the surface ledger — params are where injection classes live.

### 7. Route normalization

Collapse parameterized paths before dedupe, or you test the same handler dozens of times:

```
/user/123          → /user/:id
/vehicle/42/location → /vehicle/:id/location
/post/550e8400-e29b-41d4-a716-446655440000 → /post/:id
```

Rules: numeric segments → `:id`; UUID/ULID/hash segments → `:id`; strip query strings for the route key but keep the param names. Dedupe on `METHOD host normalized_path`. Cap the per-host route budget — test each distinct handler once.

### 8. Coverage recording

`record_coverage` per surface — one entry per normalized route or service, not per raw URL. A surface nobody tested is indistinguishable from a surface nobody saw; the ledger is the difference.

## Tech Fingerprint → Tool Parameters

Match `httpx -tech-detect` output and server banners to tuned flags:

| Detected tech | Content discovery | Vuln scan | Injection |
|---|---|---|---|
| PHP (php, Laravel, PHPSESSID) | `-x php,html,txt` | `nuclei -tags php,laravel` | `sqlmap --dbms=mysql` |
| .NET (asp, aspx, IIS, ASP.NET_SessionId) | `-x asp,aspx,html,txt` | `nuclei -tags iis,aspnet` | `sqlmap --dbms=mssql` |
| Java (JSESSIONID, Tomcat, Spring) | `-x jsp,do,action,html` | `nuclei -tags java,spring,tomcat` | `sqlmap --dbms=mysql` |
| WordPress (wp-content, wp-includes) | `-x php,txt` + `wp-*` paths | `nuclei -tags wordpress` + `wpscan --url <t> --enumerate p,u` | `sqlmap --dbms=mysql` |
| Drupal (/sites/default, X-Drupal-Cache) | `-x php,txt` | `nuclei -tags drupal` | `sqlmap --dbms=mysql` |
| Node/Express (X-Powered-By: Express) | `-x js,json,html` | `nuclei -tags nodejs,express` | NoSQLi probes first |
| Python (Werkzeug, Django, Flask) | `-x py,html,txt` | `nuclei -tags python,django,flask` | `sqlmap --dbms=postgres,mysql` |
| GraphQL (/graphql, __schema) | introspection query | `nuclei -tags graphql` | batching/alias abuse |

## Rules

1. JSON/line output at every stage — the chain only works if stages compose.
2. `anew` at every merge; never concatenate without dedupe.
3. Normalize routes *before* handing URLs to hunters — parameterized duplicates burn the entire budget on one handler.
4. Every stage's output is a coverage surface: unprobed stages are gaps, not zeros.
5. Cert SANs and CNAMEs from stages 2–4 feed back to stage 1 — the pipeline is a loop until the set converges.
6. If a tool fails mid-chain, apply `tool_recovery` — never break the chain on one binary.
