# omp-strix

Strix adversarial security-testing mode for [oh-my-pi](https://github.com/can1357/oh-my-pi). `/strix` toggles a full multi-agent pentest workflow: a dedicated system prompt, a shared docker sandbox for command execution, a shared per-scan state store (notes / coverage / threat model / reports), and specialist subagents for recon, hunting, validation, and reporting.

## Install

```bash
omp plugin link /path/to/omp-strix        # local dev
# or
omp plugin install github:you/omp-strix   # from git
```

## Usage

```
/strix        # toggle on
/strix        # toggle off
```

`/strix` turns strix mode on. Name the target and depth (`quick` / `standard` / `deep`) in your next message — the first prompt after activation is captured as the scan target and starts the scan. `/strix` again turns it off.

On activation the plugin:

1. Builds the strix system prompt (root-agent orchestration + methodology + skills catalog) and installs it via `before_agent_start`.
2. Activates the strix toolset (19 tools, `defaultInactive` until then).
3. Switches to the `strix-red` theme and names the session `strix`.

On the first `bash` call the plugin pulls the prebuilt `ghcr.io/tmih06/omp-strix-sandbox` image (Debian slim + nmap, masscan, gobuster, sqlmap, hydra, john, python3, …) and starts a shared container with the session cwd mounted at `/workspace`; every `bash` call is rewritten to `docker exec` into it. If the pull fails and a `sandbox/Dockerfile` is present (source checkout), it builds locally instead.

`finish_scan` (or `/strix` off, or session shutdown) writes `final-report.json` into the scan dir and tears the container down.

## Tools

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

Spawned via the native `task` tool:

- `strix-recon` — enumeration and attack-surface mapping
- `strix-hunter` — active vulnerability discovery
- `strix-validator` — independent PoC proof / rejection
- `strix-reporter` — files the report (with inline fix for white-box)

## Sandbox

Commands run inside a docker container (`runc`), not on the host. The session cwd is bind-mounted at `/workspace` so file tools and shell see the same tree.

The image is prebuilt on GHCR by `.github/workflows/sandbox-image.yml` (multi-arch amd64+arm64, pushed on changes to `sandbox/`). Users pull it; no local build needed. To publish: push the repo to GitHub and the workflow runs automatically — the package lands at `ghcr.io/<owner>/omp-strix-sandbox` (make it public under Packages → Settings, or users need `docker login ghcr.io`).

- `STRIX_SANDBOX_IMAGE` — override the image (any registry ref; falls back to local `docker build` if pull fails and `sandbox/Dockerfile` exists)
- `STRIX_SANDBOX=off` — disable sandboxing entirely

## Layout

```
src/index.ts    extension entry — /strix command, prompt override, bash→docker rewrite
src/prompt.ts   system-prompt builder + skill loader
src/tools.ts    19 strix tools
src/state.ts    per-scan file-backed store (~/.omp/agent/strix/scans/<id>/)
src/sandbox.ts  docker lifecycle + bash rewrite
src/cvss.ts     CVSS v3.1 base-score calculator
sandbox/Dockerfile
agents/         strix-* subagent definitions
strix/skills/   75 ported strix skills
themes/strix-red.json
```
