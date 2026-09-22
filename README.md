# omp-strix

Adversarial security-testing mode for [oh-my-pi](https://github.com/can1357/oh-my-pi) — a port of the [Strix](https://github.com/usestrix/strix) multi-agent pentest workflow to an omp plugin.

`/strix` toggles a full autonomous security-testing session: a dedicated root-agent system prompt, a shared Docker sandbox for command execution, a shared per-scan state store (notes / coverage / threat model / reports), 19 strix tools, 75 methodology skills, and specialist subagents for recon, hunting, validation, and reporting.

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
/strix        # toggle on
/strix        # toggle off
```

`/strix` turns strix mode on. On activation it asks whether to run shell commands inside the Docker sandbox (decline → commands run on the host). Name the **target** and **depth** in your next message — the first prompt after activation is captured as the scan target and starts the scan:

```
/strix
> pentest-ground.com:4280, standard depth, white-box — source is in ./app
```

Scan depth selects a `scan_modes` skill: `quick` (fast surface sweep), `standard` (default), `deep` (exhaustive), `diff` (white-box, scoped to a change).

On activation the plugin:

1. Builds the strix system prompt (root-agent orchestration, methodology, skills catalog) and installs it via `before_agent_start`.
2. Activates the 19-tool strix toolset plus the native `goal` tool (`defaultInactive` until then).
3. Switches to the `strix-red` theme, shows a `◆ STRIX` status segment, and names the session `strix: <target>`.

The root agent's first action is `goal {op:"create"}` — omp's native goal mode tracks tokens and wall-clock for the scan and shows live progress in the status line. `finish_scan` embeds the metrics in `final-report.json`; the agent then calls `goal {op:"complete"}` for the final token/time report. Subagent usage (from `task` tool results) is accumulated separately into `metrics.subagent_tokens` since goal accounting only covers the main session.

On the first `bash` call the plugin pulls `ghcr.io/tmih06/omp-strix-sandbox:latest` (Debian slim + nmap, masscan, gobuster, sqlmap, hydra, john, nuclei, httpx, python3, …) and starts a shared container with the session cwd mounted at `/workspace`; every `bash` call is rewritten to `docker exec` into it. If the pull fails and `sandbox/Dockerfile` is present (source checkout), it builds locally instead. If Docker is unavailable, commands run on the host.

`finish_scan` (or `/strix` off, or session shutdown) writes `final-report.json` + `final-report.md` into the scan dir and tears the container down.

## Tools

19 tools, inactive until strix mode is on:

| Tool | Purpose |
|---|---|
| `think` | Structured reasoning scratchpad |
| `load_skill` | Pull a strix skill's body inline |
| `create_note` / `list_notes` / `get_note` / `update_note` / `delete_note` | Shared scan scratchpad |
| `record_coverage` / `update_coverage` / `list_coverage` | Coverage ledger — what was assessed and how it closed |
| `get_threat_model` / `save_threat_model` / `amend_threat_model` | Shared threat model per target |
| `create_vulnerability_report` / `create_dependency_report` | File findings (dynamic PoC / pinned-CVE) |
| `update_vulnerability_report` / `list_reports` / `get_report` | Revise and review filed findings |
| `finish_scan` | Close the scan, write `final-report.json` |

## Agents

Spawned via the native `task` tool; all share the scan state store:

| Agent | Role |
|---|---|
| `strix-recon` | Enumeration and attack-surface mapping |
| `strix-hunter` | Active vulnerability discovery — proves exploitability, doesn't file |
| `strix-validator` | Independent PoC proof / rejection of hunter candidates |
| `strix-reporter` | Files the report (with inline fix for white-box) |

The root agent orchestrates only — it delegates all target-touching work to subagents and tracks coverage.

## Skills

75 methodology skills under `strix/skills/`, loaded on demand via `load_skill`:

| Category | Contents |
|---|---|
| `scan_modes` | quick, standard, deep, diff |
| `reconnaissance` | asset discovery, infrastructure lifecycle |
| `vulnerabilities` | 28 classes — sqli, xss, ssrf, ssti, idor, jwt, deserialization, request smuggling, prompt injection, race conditions, … |
| `analysis` | counterevidence, fix verification, severity calibration, source-aware discovery |
| `coordination` | root-agent orchestration, white-box coordination |
| `custom` | api-spec testing, dependency CVE scanning, npx confusion, source-aware SAST |
| `frameworks` | django, fastapi, nestjs, nextjs |
| `protocols` | graphql, oauth |
| `technologies` | active directory, auth0, electron, firebase, grafana/prometheus, llm apps, supabase |
| `cloud` | aws, azure, gcp, kubernetes |
| `tooling` | nmap, nuclei, sqlmap, ffuf, httpx, katana, semgrep, subfinder, naabu, hurl, hypothesis, agent browser, python |

## Sandbox

Commands run inside a Docker container (`runc`), not on the host. The session cwd is bind-mounted at `/workspace` so file tools and shell see the same tree. The container runs with `--network host` and `NET_RAW` for scanning.

The image is prebuilt on GHCR by `.github/workflows/sandbox-image.yml` (multi-arch amd64+arm64, pushed on changes to `sandbox/`). Users pull it; no local build needed.

| Env var | Effect |
|---|---|
| `STRIX_SANDBOX=off` | Disable sandboxing entirely (no prompt, commands on host) |
| `STRIX_SANDBOX_IMAGE` | Override the image ref; falls back to local `docker build` if pull fails and `sandbox/Dockerfile` exists |

Image contents are data-driven: `sandbox/tools-apt.txt` and `sandbox/tools-pip.txt` list packages; the Dockerfile consumes both in one layer. Add a line, push, the image rebuilds.

## Scan state & reports

Per-scan state lives under `~/.omp/agent/strix/`:

```
active.json                    -> { scanId, dir, target, scanMode, startedAt }
scans/<scanId>/
  notes/<id>.json              -> one file per note (append-only)
  coverage/<id>.json           -> one file per coverage entry
  threat-models/<slug>.json    -> { target, model, amendments[] }
  reports/vuln-NNNN.json       -> filed report (+ vuln-NNNN.md sibling)
  goal.json                      -> latest goal record (tokens, wall-clock, status)
  final-report.json            -> finish_scan payload (+ final-report.md); includes metrics block
```

File-backed and append-only so every agent session sees the same data with no read-modify-write races. Reports carry severity + CVSS v3.1 base score (computed in `src/cvss.ts`); markdown siblings are rendered by `src/report.ts`.

## CI/CD

| Workflow | Trigger | Jobs |
|---|---|---|
| `ci.yml` | push / PR | `check` (tsc + biome + bun test) → `pack` (npm pack, prod-only assertion, packed-entry smoke import) → `sandbox-image` (amd64 build + tool verification) |
| `sandbox-image.yml` | push touching `sandbox/` | multi-arch build → push `ghcr.io/<owner>/omp-strix-sandbox` |
| `release.yml` | `v*` tag | check + pack → GitHub Release with tarball; multi-arch image push tagged `latest` + semver + sha |

To publish the image under your own namespace: push the repo, the workflow lands it at `ghcr.io/<owner>/omp-strix-sandbox` — make the package public under Packages → Settings, or users need `docker login ghcr.io`.

## Development

```bash
bun install
bun run check        # tsc + biome + bun test (21 tests)
bun test             # tests only
bun run format       # biome --write
npm pack             # prod tarball (files whitelist in package.json)
```

## Layout

```
src/index.ts    extension entry — /strix command, prompt override, bash→docker rewrite
src/prompt.ts   system-prompt builder + skill loader
src/tools.ts    19 strix tools
src/state.ts    per-scan file-backed store
src/sandbox.ts  docker lifecycle + bash rewrite
src/report.ts   report/final-report markdown renderer
src/cvss.ts     CVSS v3.1 base-score calculator
src/omp.d.ts    ambient ExtensionAPI shim for tsc
agents/         strix-* subagent definitions
strix/skills/   75 ported strix skills
themes/         strix-red.json
sandbox/        Dockerfile + tools-apt.txt + tools-pip.txt
test/           cvss, report, state tests
```

## License

Apache-2.0
