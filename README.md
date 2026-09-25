# omp-strix
<img width="800" height="426" alt="out-ezgif com-optimize" src="https://github.com/user-attachments/assets/a66ac064-c167-43f6-a740-718ce04f4697" />

Adversarial security-testing mode for [oh-my-pi](https://github.com/can1357/oh-my-pi) — a port of the [Strix](https://github.com/usestrix/strix) multi-agent pentest workflow to an omp plugin.

`/strix` toggles a full autonomous security-testing session: a dedicated root-agent system prompt, a shared Docker sandbox for command execution, a shared per-scan state store (notes / coverage / threat model / reports), 45 strix tools, 78 methodology skills, and specialist subagents for recon, hunting, validation, privesc, pivoting, and reporting.

> **Authorized use only.** This plugin runs real offensive tooling (nmap, sqlmap, nuclei, hydra, …) against the target you name. Point it at systems you own or have written permission to test.

## Requirements

- `omp` (oh-my-pi coding agent)
- Docker — required; Strix never runs agent-triggered commands or network requests on the host
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

`/strix` requires a verified Docker sandbox. It starts and checks the container **before** enabling scan tools; Docker or isolation failure aborts activation rather than falling back to the host. `STRIX_SANDBOX=off` is rejected. Pass the **target** (and optionally **depth**) as command args, or name them in your next message — the first post-activation prompt starts the scan:

```
/strix
> pentest-ground.com:4280, standard depth, white-box — source is in ./app
```

Scan depth selects a `scan_modes` skill: `quick` (fast surface sweep), `standard` (default), `deep` (exhaustive), `diff` (white-box, scoped to a change).

On activation the plugin:

1. Builds the strix system prompt (root-agent orchestration, methodology, skills catalog) and installs it via `before_agent_start`.
2. Activates the 45-tool strix toolset (`defaultInactive` until then).
3. Switches to the `strix-red` theme, shows a `◆ STRIX` status segment, and names the session `strix: <target>`.

`finish_scan` embeds scan metrics in `final-report.json`: wall-clock duration, main-session tokens/cost, and accumulated subagent usage from their session transcripts.

On activation the plugin checks for image updates, pulls `ghcr.io/tmih06/omp-strix-sandbox:latest` (Debian slim + security tools), and starts a shared container. If the pull fails and `sandbox/Dockerfile` is present, it builds locally. Image check/pull/build progress appears in a temporary bar **below the prompt**, separate from the steady `◆ STRIX` status-line segment; the bar disappears when startup completes or fails. Each subsequent command rechecks the container's mounts and security settings; a failed check prevents execution.

`finish_scan` writes `final-report.json` + `final-report.md` and closes the scan. `/strix` off or session shutdown ends any active scan and tears down the container; use `finish_scan` first to produce the final report.

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

Agent shell commands (`bash`, `terminal`, `python`, scanner wrappers) execute inside the Docker container. The current project directory is mounted **read-only** at `/workspace`; its private `./.strix/scratch` directory is separately mounted writable at `/scratch` for clones and temporary files. Both bind sources are under `./`, not `~/.omp`. The container runs as the invoking user's UID/GID, with a separate bridge network namespace, dropped capabilities except `NET_RAW`, `no-new-privileges`, and no Docker socket. Project source files cannot be changed through the mount.

In Strix mode, native host file tools (`read`, `write`, `edit`, `grep`, `glob`), host eval/browser/debug tools, unknown tools, and generic/custom subagents are blocked; inspect source and write scratch through `bash` in the container. All Strix script and HTTP tools require the sandbox and refuse host execution even if its marker disappears. Only the fixed `strix-*` specialist agents may be spawned. Built-in scan notes and reports are written by the **trusted host extension** to `./.strix/scans`; they are not agent-controlled file tools. `login_and_save_session` is unavailable because the image lacks its browser; use an in-container login flow and save the cookie jar in `/scratch`.

Harness orchestration (`task`, `wait`, `todo`, `ask`), subagent result submission (`yield`, displayed as **Submit Result**), and session-context management (`context_notes`, `new_context`) remain allowed. Result submission is permitted in independently initialized subagent runners as well as the owning session. These exceptions do not enable general host file, network, or eval access; context notes persist only through the harness-owned session store.

This is Docker process isolation, not a VM security boundary. A malicious kernel exploit, privileged host daemon, or another extension outside this plugin's tool hook is outside this plugin's enforcement. Bridge networking can still reach reachable host services; restrict the Docker daemon and network separately when scanning untrusted targets.

The image is prebuilt on GHCR by `.github/workflows/sandbox-image.yml` (multi-arch amd64+arm64, pushed on changes to `sandbox/`). Users pull it; no local build needed.

| Env var | Effect |
|---|---|
| `STRIX_SANDBOX=off` | Refuse `/strix` activation; remove this setting to enable the required sandbox |
| `STRIX_SANDBOX_IMAGE` | Override the image ref; falls back to local `docker build` if pull fails and `sandbox/Dockerfile` exists |

Image contents are data-driven: `sandbox/tools-apt.txt` and `sandbox/tools-pip.txt` list packages; the Dockerfile consumes both in one layer. Add a line, push, the image rebuilds.

## Scan state & reports

Per-scan state lives under `<project>/.strix/` (the session's working directory); the directory must be owner-owned and mode `0700`. Previous `./strix/scans` artifacts are left untouched:

```
sandbox.json                  -> active container marker for agent/subagent routing
scratch/                      -> writable bind source for /scratch
active.json                   -> { scanId, dir, target, scanMode, sandboxed, startedAt }
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
