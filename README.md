# omp-strix

Watch it run
![demo](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExZDc3cDRzZ3E5M2MwZGY3czNhMG0zanN1M3U1cTdzbHBkbmJvbTVkZCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/YghF6gJd21yXTCNUVf/giphy.gif)

Adversarial security-testing mode for [oh-my-pi](https://github.com/can1357/oh-my-pi) — a port of the [Strix](https://github.com/usestrix/strix) multi-agent pentest workflow to an omp plugin.

`/strix` toggles a full autonomous security-testing session: a dedicated root-agent system prompt, a shared Docker sandbox for command execution, a shared per-scan state store (notes / coverage / threat model / reports), 45 strix tools, 78 methodology skills, and specialist subagents for recon, hunting, validation, privesc, pivoting, and reporting.

> **Authorized use only.** This plugin runs real offensive tooling (nmap, sqlmap, nuclei, hydra, …) against the target you name. Point it at systems you own or have written permission to test.

## Requirements

- `omp` (oh-my-pi coding agent)
- Docker — optional but recommended; required for sandboxed command execution
- Bun — for development (`bun install`, `bun run check`)

## Install

Marketplace (recommended — auto-update via `omp plugin upgrade` or `marketplace.autoUpdate`):

```bash
omp plugin marketplace add tmih06/omp-strix
omp plugin install omp-strix@omp-strix
```

From git (pinned copy — re-run install to update):

```bash
omp plugin install github:tmih06/omp-strix
```

Local checkout (development):

```bash
omp plugin link /path/to/omp-strix
```

## Usage
```
/strix <target> [depth]   # start scanning immediately
/strix                   # toggle on — target named in next message
/strix                   # toggle off
```

`/strix` turns strix mode on. On activation it asks whether to run shell commands inside the Docker sandbox (decline → commands run on the host). Pass the **target** (and optionally **depth**) as command args to start immediately, or name them in your next message — the first prompt after activation is captured as the scan target and starts the scan:

```
/strix
> pentest-ground.com:4280, standard depth, white-box — source is in ./app
```

Scan depth selects a `scan_modes` skill: `quick` (fast surface sweep), `standard` (default), `deep` (exhaustive), `diff` (white-box, scoped to a change).

On activation the plugin:

1. Builds the strix system prompt (root-agent orchestration, methodology, skills catalog) and installs it via `before_agent_start`.
2. Activates the 45-tool strix toolset (`defaultInactive` until then).
3. Switches to the `strix-red` theme, shows a `◆ STRIX` status segment, and names the session `strix: <target>`.

`finish_scan` embeds scan metrics in `final-report.json`: wall-clock duration, main-session tokens/cost (from the session usage stats), and accumulated subagent usage from `task` tool results.

On the first `bash` call the plugin pulls `ghcr.io/tmih06/omp-strix-sandbox:latest` (Debian slim + nmap, masscan, gobuster, sqlmap, hydra, john, nuclei, httpx, python3, …) and starts a shared container with the session cwd mounted at `/workspace`; every `bash` call is rewritten to `docker exec` into it. If the pull fails and `sandbox/Dockerfile` is present (source checkout), it builds locally instead. If Docker is unavailable, commands run on the host.

`finish_scan` (or `/strix` off, or session shutdown) writes `final-report.json` + `final-report.md` into the scan dir and tears the container down.

## Tools

45 tools, inactive until strix mode is on:

| Tool | Purpose |
|---|---|
| `think` / `thought` | Structured reasoning scratchpad |
| `load_skill` | Pull a strix skill's body inline |
| `create_note` / `list_notes` / `get_note` / `update_note` / `delete_note` | Shared scan scratchpad |
| `record_coverage` / `update_coverage` / `list_coverage` | Coverage ledger — what was assessed and how it closed |
| `record_degradation` / `list_degradation` | Track partial/failed coverage with reason codes |
| `get_threat_model` / `save_threat_model` / `amend_threat_model` | Shared threat model per target |
| `create_vulnerability_report` / `create_dependency_report` | File findings (dynamic PoC / pinned-CVE) |
| `update_vulnerability_report` / `list_reports` / `get_report` / `disprove_report` | Revise, review, and retire filed findings |
| `record_candidate` / `submit_verdict` | Hunter→validator handoff — candidates and PoC verdicts |
| `record_signal` / `list_signals` / `ack_signal` | Cross-agent signal bus for live coordination |
| `record_artifact` / `list_artifacts` | Evidence ledger — PoC files, captures, dumps |
| `record_attack_hop` / `get_attack_path` | Attack-path graph for chained exploits |
| `update_plan` / `get_plan` | Shared scan task decomposition (scope-validated) |
| `scan` | Kick off / drive the scan workflow |
| `terminal` / `python` | Persistent interactive shell + scripting |
| `fetch_url` | SSRF-guarded, injection-sanitized web fetch |
| `login_and_save_session` / `totp` | Authenticated-session capture + TOTP |
| `verify_sqli` / `verify_ssti` / `verify_path_traversal` / `verify_timing` / `diff_probe` | Class-specific exploit verifiers |
| `finish_scan` | Close the scan, write `final-report.json` |

## Agents

Spawned via the native `task` tool; all share the scan state store:

| Agent | Role |
|---|---|
| `strix-recon` | Enumeration and attack-surface mapping |
| `strix-hunter` | Active vulnerability discovery — proves exploitability, doesn't file |
| `strix-validator` | Independent PoC proof / rejection of hunter candidates |
| `strix-privesc` | Privilege escalation after initial foothold |
| `strix-pivot` | Lateral movement / internal-network pivoting |
| `strix-reporter` | Files the report (with inline fix for white-box) |

The root agent orchestrates only — it delegates all target-touching work to subagents and tracks coverage.

## Skills

78 methodology skills under `strix/skills/`, loaded on demand via `load_skill`:

| Category | Contents |
|---|---|
| `scan_modes` | quick, standard, deep, diff |
| `reconnaissance` | asset discovery, infrastructure lifecycle |
| `vulnerabilities` | 32 classes — sqli, xss, ssrf, ssti, idor, jwt, deserialization, request smuggling, prompt injection, race conditions, … |
| `analysis` | counterevidence, fix verification, severity calibration, source-aware discovery |
| `coordination` | root-agent orchestration, white-box coordination |
| `custom` | api-spec testing, dependency CVE scanning, npx confusion, source-aware SAST |
| `frameworks` | django, fastapi, nestjs, nextjs |
| `protocols` | graphql, oauth |
| `technologies` | active directory, auth0, firebase, grafana/prometheus, llm apps, supabase |
| `cloud` | kubernetes |
| `tooling` | nmap, nuclei, sqlmap, ffuf, httpx, katana, semgrep, subfinder, naabu, hurl, hypothesis, agent browser |

## Sandbox

Commands run inside a Docker container (`runc`), not on the host. The session cwd is bind-mounted at `/workspace` so file tools and shell see the same tree. The container runs with `--network host` and `NET_RAW` for scanning.

The image is prebuilt on GHCR by `.github/workflows/sandbox-image.yml` (multi-arch amd64+arm64, pushed on changes to `sandbox/`). Users pull it; no local build needed.

| Env var | Effect |
|---|---|
| `STRIX_SANDBOX=off` | Disable sandboxing entirely (no prompt, commands on host) |
| `STRIX_SANDBOX_IMAGE` | Override the image ref; falls back to local `docker build` if pull fails and `sandbox/Dockerfile` exists |

Image contents are data-driven: `sandbox/tools-apt.txt` and `sandbox/tools-pip.txt` list packages; the Dockerfile consumes both in one layer. Add a line, push, the image rebuilds.

## Scan state & reports

Per-scan state lives under `<project>/strix/` (the session's working directory):

```
active.json                    -> { scanId, dir, target, scanMode, startedAt }
scans/<scanId>/
  notes/<id>.json              -> one file per note (append-only)
  coverage/<id>.json           -> one file per coverage entry
  threat-models/<slug>.json    -> { target, model, amendments[] }
  reports/vuln-NNNN.json       -> filed report (+ vuln-NNNN.md sibling)
  final-report.json            -> finish_scan payload (+ final-report.md); includes metrics block
```

File-backed and append-only so every agent session sees the same data with no read-modify-write races. Reports carry severity + CVSS v3.1 base score (computed in `src/cvss.ts`); markdown siblings are rendered by `src/report.ts`.

## CI/CD

| Workflow | Trigger | Jobs |
|---|---|---|
| `ci.yml` | push / PR | `check` (tsc + biome + bun test, on ubuntu/macos/windows) → `pack` (npm pack, prod-only assertion, packed-entry smoke import) → `sandbox-image` (amd64 build + tool verification) |
| `sandbox-image.yml` | push touching `sandbox/` | parallel per-arch builds (amd64 on `ubuntu-latest`, arm64 on `ubuntu-24.04-arm`) → gated `publish` merges into a multi-arch manifest and pushes `ghcr.io/<owner>/omp-strix-sandbox` |
| `release.yml` | `v*` tag | check + pack → GitHub Release with tarball; parallel per-arch image builds → gated merge tagged `latest` + semver + sha |

To publish the image under your own namespace: push the repo, the workflow lands it at `ghcr.io/<owner>/omp-strix-sandbox` — make the package public under Packages → Settings, or users need `docker login ghcr.io`.

## Development

```bash
bun install
bun run check        # tsc + biome + bun test (22 tests)
bun test             # tests only
bun run format       # biome --write
npm pack             # prod tarball (files whitelist in package.json)
```

## Layout

```
src/index.ts    extension entry — /strix command, prompt override, bash→docker rewrite
src/prompt.ts   system-prompt builder + skill loader
src/tools.ts    45 strix tools
src/state.ts    per-scan file-backed store
src/sandbox.ts  docker lifecycle + bash rewrite
src/report.ts   report/final-report markdown renderer
src/cvss.ts     CVSS v3.1 base-score calculator
src/omp.d.ts    ambient ExtensionAPI shim for tsc
agents/         strix-* subagent definitions
strix/skills/   78 ported strix skills
themes/         strix-red.json
sandbox/        Dockerfile + tools-apt.txt + tools-pip.txt
test/           cvss, report, state tests
```

## License

Apache-2.0
