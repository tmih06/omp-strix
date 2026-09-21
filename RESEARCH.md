# Oh My Pi (omp) Plugin & Extensibility System

## 1. Executive Summary

Oh My Pi (`omp`) provides a dual-track extensibility and plugin architecture. It bridges standard package ecosystems (npm packages, Git repositories, and local development links) with Anthropic Claude Code–compatible marketplace catalogs into a unified runtime engine. 

Extensions and plugins in `omp` run in-process under Bun, giving them deep access to intercept LLM prompts and provider requests, restrict or register tools, modify interactive TUI elements (including themes, window titles, and editor widgets), and implement entirely custom operational modes such as Plan or Review modes.

---

## 2. Architecture & Management Subsystems

Plugin management is handled by two distinct manager implementations that converge on disk and at runtime:

```
┌────────────────────────────────────────────────────────┐
│                   CLI / User Action                    │
│    `omp plugin install`  /  `/marketplace install`      │
└──────────────────────────┬─────────────────────────────┘
                           │
             Is target `name@marketplace`?
             ├─── YES ───► MarketplaceManager
             │               ├── Fetch catalog (.omp-plugin / .claude-plugin)
             │               ├── Cache plugin repository to ~/.omp/plugins/cache/
             │               └── Symlink cached package into <scope>/node_modules/
             │
             └─── NO  ───► PluginManager
                             ├── Validate npm / Git spec
                             ├── Invoke `bun install` / `bun uninstall`
                             └── Write <scope>/package.json
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Unified Disk Runtime Surface                           │
│  - <scope>/plugins/node_modules/ (packages and marketplace symlinks)            │
│  - <scope>/plugins/omp-plugins.lock.json (enablement, features, settings)       │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        Capability & Extension Loader                            │
│  - Scans manifest `omp.extensions` and `omp.tools`                              │
│  - Scans conventional `skills/`, `commands/`, `agents/`, `hooks/`, `.mcp.json`  │
│  - Mounts active modules into the Extension Runner                              │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1. `PluginManager` (`src/extensibility/plugins/manager.ts`)
- Governs npm dependencies, Git URLs/shorthands (`github:`, `gitlab:`, `bitbucket:`, `codeberg:`, `sourcehut:`), and local directory symlinks (`omp plugin link`).
- Directly manages `<scope>/package.json` and invokes `bun install` / `bun uninstall`.
- Performs pre-install and post-install rollbacks: snapshots `package.json`, `bun.lock`, and the target package directory before installation, restoring them if manifest validation or factory initialization fails.

### 2.2. `MarketplaceManager` (`src/extensibility/plugins/marketplace.ts`)
- Manages marketplace catalog registries (`marketplaces.json`).
- Compatible with Claude Code marketplace catalogs located at `.omp-plugin/marketplace.json` (preferred) or `.claude-plugin/marketplace.json` (fallback).
- Plugins are addressed as `name@marketplace` (e.g. `code-review@claude-plugins-official`).
- **Runtime Bridge**: Marketplace plugins are cloned/cached under `cache/plugins/<marketplace>___<plugin>___<version>/` and symlinked into `<scope>/plugins/node_modules/<package>`. Enablement and feature state are recorded in `omp-plugins.lock.json`. This makes marketplace plugins fully first-class runtime extension packages.

---

## 3. On-Disk Layout & Scope Precedence

Plugins can be installed at **User** or **Project** scope:

### 3.1. Directory Structure

#### User Scope (Default)
Stored in `~/.omp/plugins/` (or `$XDG_DATA_HOME/omp/plugins/` when XDG paths are configured via `omp config init-xdg`):
```text
~/.omp/
├── marketplaces.json                  # Added marketplace sources
└── plugins/
    ├── package.json                   # Private npm manifest for installed packages
    ├── node_modules/                  # Installed packages & marketplace symlinks
    │   ├── @scope/my-npm-plugin/
    │   └── marketplace-plugin -> ~/.omp/plugins/cache/plugins/...
    ├── omp-plugins.lock.json          # Enablement, active features, plugin settings
    ├── installed_plugins.json         # Marketplace install registry (v2)
    └── cache/
        ├── marketplaces/<source>/     # Cloned marketplace catalog repositories
        └── plugins/<cached-dirs>/     # Versioned plugin downloads
```

#### Project Scope
Located in `<anchor>/.omp/plugins/` (where `<anchor>` is the nearest parent directory containing `.omp/` or `.git/`):
```text
<project-root>/
└── .omp/
    ├── plugin-overrides.json          # Read-only configuration overrides
    └── plugins/
        ├── installed_plugins.json     # Project-specific marketplace installs
        ├── node_modules/              # Project-scoped packages & symlinks
        └── omp-plugins.lock.json      # Project runtime lockfile
```

### 3.2. Precedence & Shadowing Rules
- **Project Shadowing**: An enabled project-scoped plugin shadows a user-scoped plugin of the same package name. If the project copy is disabled, the user copy remains active.
- **Project Overrides (`plugin-overrides.json`)**: Can disable specific plugins or force feature selections without modifying the persistent lockfile:
  ```json
  {
    "disabled": ["untrusted-plugin"],
    "features": {
      "code-review": ["strict-lint"]
    }
  }
  ```

---

## 4. Plugin Packaging & Capabilities

A plugin package can bundle declarative capabilities (markdown definitions and configurations) alongside programmatic extension modules.

### 4.1. Conventional Directory Structure
```text
my-omp-plugin/
├── package.json                 # Manifest defining extension entrypoints & features
├── skills/                      # Static skill guides and domain modeling
│   └── code-review/SKILL.md
├── commands/                    # Custom slash commands
│   └── lint.md
├── agents/                      # Subagent definitions for task delegation
│   └── auditor.md
├── hooks/                       # Lifecycle hooks
│   ├── pre/guard.ts             # Pre-execution hooks
│   └── post/log.ts              # Post-execution hooks
├── tools/                       # Custom model-callable tools
│   └── git_metrics.ts
├── .mcp.json                    # Model Context Protocol servers
├── .lsp.json                    # Language server definitions
├── .dap.json                    # Debug adapter configurations
└── README.md
```

### 4.2. Manifest Contract (`package.json`)
The `omp` key declares code entry points. For backwards compatibility with older Pi packages, `pi` is accepted as a fallback.
```json
{
  "name": "my-omp-plugin",
  "version": "1.2.0",
  "omp": {
    "extensions": ["./src/index.ts"],
    "tools": ["./src/tools/custom-tool.ts"],
    "features": {
      "advanced-reporting": {
        "description": "Enables HTML report export",
        "default": false,
        "tools": ["./src/tools/report.ts"],
        "extensions": ["./src/extensions/reporting.ts"]
      }
    }
  }
}
```
- Manifest paths support `.ts`, `.js`, `.mjs`, and `.cjs` files, or directories containing `index.{ts,js,mjs,cjs}`.
- Feature brackets can be specified at install time: `omp plugin install my-plugin[advanced-reporting]` (or `[*]` for all, `[]` for none).

---

## 5. Extension Runtime & Lifecycle Model

Programmatic capabilities run inside the **Extension Runner** (`src/extensibility/extensions/runner.ts`).

### 5.1. Module Factory Contract
Every extension module must default-export a factory function:
```ts
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

export default function myExtension(pi: ExtensionAPI) {
  // 1. Synchronous or Promise-returning registration phase
  pi.registerTool({ ... });
  pi.registerCommand("my-command", { ... });

  // 2. Lifecycle event bindings
  pi.on("session_start", async (event, ctx) => { ... });
  pi.on("before_agent_start", async (event, ctx) => { ... });
  pi.on("tool_call", async (event, ctx) => { ... });
}
```

### 5.2. Two-Phase Execution Invariant
1. **Load/Registration Phase**: During module evaluation and factory execution, only registration calls (`pi.registerTool`, `pi.registerCommand`, `pi.registerShortcut`, `pi.registerFlag`, `pi.on`) are permitted. Calling live actions (e.g. `pi.sendMessage()`, `pi.setActiveTools()`) will throw `ExtensionRuntimeNotInitializedError`.
2. **Runtime Execution Phase**: Action methods become valid once `ExtensionRunner.initialize()` runs and hooks into the active session controller.

### 5.3. Process Model & Background Safety
- **No In-Process Sandboxing**: Extensions execute directly within the host Bun runtime.
- **Timer Safety**: Raw `setInterval` or `setTimeout` calls that throw will bypass handler `try/catch` blocks and crash the entire session process (`uncaughtException`). Extensions must use `ctx.setInterval(fn, ms)` and `ctx.setTimeout(fn, ms)`, which safely catch callback errors and automatically deregister on `session_shutdown`.

### 5.4. Tool Interception
All tools (built-in tools, MCP tools, custom tools, and extension tools) are wrapped by `ExtensionToolWrapper`:
- `tool_call`: Emitted before tool execution. Handlers can block execution (`{ block: true, reason: string }`) or mutate arguments (`{ input: Record<string, unknown> }`). Fails closed if a handler throws.
- `tool_result`: Emitted after execution. Handlers can inspect or rewrite output (`{ content, details, isError }`).

---

## 6. TUI Customization Capabilities

Plugins can inspect and modify the terminal user interface via `ctx.ui` (`ExtensionUIContext`).

### 6.1. Color Theming
An extension can programmatically switch themes at runtime:
```ts
pi.on("session_start", async (_event, ctx) => {
  if (ctx.hasUI) {
    // Switch to built-in (e.g. "titanium", "dark", "light")
    // or custom JSON theme in ~/.omp/agent/themes/<name>.json
    const res = await ctx.ui.setTheme("titanium");
    if (!res.success) {
      ctx.ui.notify(`Theme switch failed: ${res.error}`, "error");
    }
  }
});
```
- Themes define 11 core text/border tokens, 7 background tokens, 5 message tokens, 10 markdown tokens, 12 diff/syntax tokens, 8 thinking-level border tokens, and 13 status line tokens.
- Theme switching immediately rebinds the live ANSI formatting functions across the entire interface.

### 6.2. Titles (Terminal Window & Session Transcript)
Plugins control both types of titles:
1. **Terminal Tab / Window Title**:
   ```ts
   ctx.ui.setTitle("omp // Project Review [Architect Mode]");
   ```
2. **Session / Conversation Name**:
   ```ts
   pi.on("input", async (event, ctx) => {
     // Calling setSessionName during the initial input turn overrides
     // and disables the automatic model title generation.
     await pi.setSessionName("Refactor: Auth Service");
   });
   ```

### 6.3. Persistent Widgets & Status Line
- **Widgets (`setWidget`)**: Displays persistent framed text blocks above or below the input editor:
  ```ts
  ctx.ui.setWidget("my_banner", {
    placement: "aboveEditor", // or "belowEditor"
    content: [
      "╭─ PLAN MODE ACTIVE ───────────────────────────────────╮",
      "│ Mutation tools disabled. Analysis only.              │",
      "╰──────────────────────────────────────────────────────╯"
    ]
  });
  ```
  *(Content is capped at 10 lines).*
- **Status Bar (`setStatus`)**: Adds or updates segments on the status bar:
  ```ts
  ctx.ui.setStatus("plan_status", "📐 PLAN ACTIVE");
  ```
- **Working Message**: Overrides the spinner message during model generation:
  ```ts
  ctx.ui.setWorkingMessage("Generating architectural specifications...");
  ```

### 6.4. Composer Shapes & Custom Renderers
- **Composer Shape (`registerComposerShape`)**: Registers custom input-editor border/chrome styles (selectable under **Appearance → Composer Shape**).
- **Custom Message Renderers (`registerMessageRenderer`)**: Supplies custom TUI components for custom session entry types.
- **Thinking Block Renderers (`registerAssistantThinkingRenderer`)**: Appends custom display components beneath assistant reasoning blocks.
- **Tool Views**: `registerTool` supports `renderCall` and `renderResult` functions for domain-specific formatting in the transcript.

---

## 7. Implementing Custom Operational Modes

`omp` allows plugins to construct distinct operational modes (analogous to built-in Plan Mode, Vibe Mode, and Autoresearch Mode) by combining:
1. A toggle command (`registerCommand`) or keyboard shortcut (`registerShortcut`).
2. Dynamic system prompt replacement via `before_agent_start`.
3. Toolset restriction via `setActiveTools()` and fail-closed `tool_call` gating.
4. TUI status banners and widget updates.
5. Session history persistence via `appendEntry()`.

### 7.1. System Prompt Replacement Contract (`before_agent_start`)
The `before_agent_start` event receives:
```ts
{
  type: "before_agent_start",
  prompt: string,            // Concatenated user prompt text
  images: unknown[],         // Normalized input images
  systemPrompt: string[]     // Active base system prompt blocks
}
```
If an extension returns:
```ts
{
  systemPrompt: string | string[]
}
```
The Extension Runner replaces block 0 of the system prompt for that turn and its continuations.

### 7.2. Reference Implementation: Custom Architect / Plan Mode

Below is a complete, self-contained extension demonstrating how to implement a custom read-only Plan Mode:

```ts
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

export default function architectPlanMode(pi: ExtensionAPI) {
  let isPlanMode = false;
  let previousTools: string[] = [];

  const PLAN_SYSTEM_PROMPT = [
    "# Mode: Architect & Planning",
    "You are currently operating in STRICT ARCHITECT PLAN MODE.",
    "Your objective is to inspect the codebase and design an implementation plan.",
    "",
    "## Operational Rules:",
    "1. You are strictly in read-only analysis mode.",
    "2. Use read, glob, and grep to investigate files.",
    "3. NEVER attempt to write, edit, or delete files.",
    "4. Output architectural specifications in structured Markdown.",
  ];

  // Helper: Synchronize UI state
  function updateUI(ctx: ExtensionContext) {
    if (!ctx.hasUI) return;

    if (isPlanMode) {
      ctx.ui.setStatus("plan_mode", "📐 PLAN MODE");
      ctx.ui.setWidget("plan_banner", {
        placement: "aboveEditor",
        content: [
          "╭───────────────────────────────────────────────────────────╮",
          "│ 📐 ARCHITECT PLAN MODE ACTIVE                             │",
          "│ Read-only analysis enabled. Mutation tools locked.        │",
          "│ Run /plan to return to normal execution mode.             │",
          "╰───────────────────────────────────────────────────────────╯",
        ],
      });
    } else {
      ctx.ui.setStatus("plan_mode", "");
      ctx.ui.setWidget("plan_banner", {
        placement: "aboveEditor",
        content: [],
      });
    }
  }

  // 1. Slash Command to toggle mode: /plan
  pi.registerCommand("plan", {
    description: "Toggle Architect Plan Mode (read-only analysis)",
    handler: async (_args, ctx) => {
      isPlanMode = !isPlanMode;

      if (isPlanMode) {
        // Stash tools and restrict active set to read-only tools
        previousTools = pi.getActiveTools();
        const readOnlyTools = previousTools.filter((t) =>
          ["read", "glob", "grep", "ask", "web_search"].includes(t)
        );
        await pi.setActiveTools(readOnlyTools);
        ctx.ui.notify("Entered Architect Plan Mode (Read-Only)", "info");
      } else {
        // Restore previous tool surface
        if (previousTools.length > 0) {
          await pi.setActiveTools(previousTools);
        }
        ctx.ui.notify("Exited Plan Mode. Toolset restored.", "info");
      }

      // Persist state to session branch history
      pi.appendEntry("custom.mode.plan", { active: isPlanMode });
      updateUI(ctx);
    },
  });

  // 2. Interactive Keyboard Shortcut: Ctrl+X
  pi.registerShortcut("ctrl+x", {
    description: "Toggle Architect Plan Mode",
    handler: async (ctx) => {
      const cmd = pi.getCommands().find((c) => c.name === "plan");
      if (cmd) await cmd.handler("", ctx);
    },
  });

  // 3. CLI Startup Flag: omp --plan-mode
  pi.registerFlag("plan-mode", {
    description: "Start session in Architect Plan Mode",
    default: false,
  });

  // 4. Dynamic System Prompt Override
  pi.on("before_agent_start", async (event, _ctx) => {
    if (!isPlanMode) return;

    return {
      systemPrompt: [
        ...PLAN_SYSTEM_PROMPT,
        // Retain remaining base system context (project instructions, environment footer)
        ...event.systemPrompt.slice(1),
      ],
    };
  });

  // 5. Fail-Closed Tool Gatekeeper
  pi.on("tool_call", async (event, _ctx) => {
    if (isPlanMode && ["write", "edit", "bash"].includes(event.toolName)) {
      return {
        block: true,
        reason: `Tool '${event.toolName}' is blocked: Architect Plan Mode is read-only.`,
      };
    }
  });

  // 6. Session Tree & Branch Rehydration
  pi.on("session_start", async (_event, ctx) => {
    // Check initial CLI flag
    if (pi.getFlag("plan-mode")) {
      isPlanMode = true;
    }

    // Reconstruct state from branch history when resuming
    for (const entry of ctx.sessionManager.getBranch()) {
      if (entry.type === "custom" && entry.customType === "custom.mode.plan") {
        isPlanMode = Boolean((entry.data as { active?: boolean })?.active);
      }
    }

    updateUI(ctx);
  });
}
```

---

## 8. Command Reference Summary

### 8.1. CLI Operations
| Command | Action |
| :--- | :--- |
| `omp plugin list` | List installed npm/link and marketplace plugins. |
| `omp plugin install <spec>` | Install npm package, Git repo, or marketplace plugin (`pkg@marketplace`). |
| `omp plugin uninstall <name>` | Remove plugin and purge runtime lockfile state. |
| `omp plugin link <path>` | Symlink local plugin for development into user `node_modules`. |
| `omp plugin enable / disable <name>` | Toggle activation status in lockfile without uninstalling. |
| `omp plugin features <name> --set <f>` | Adjust optional feature flags declared in manifest. |
| `omp plugin doctor [--fix]` | Detect and repair dependency, lockfile, or feature drift. |
| `omp plugin marketplace add <src>` | Register a Git repo or JSON URL as a marketplace source. |
| `omp plugin discover [market]` | Browse available plugins across catalogs. |
| `omp plugin upgrade [name]` | Update marketplace catalogs and installed plugin versions. |

### 8.2. Interactive Slash Commands
| Slash Command | Action |
| :--- | :--- |
| `/marketplace` | Launch the full-screen interactive TUI marketplace browser. |
| `/marketplace install name@market` | Install marketplace plugin in the current session. |
| `/plugins list` | View effective plugins and active features. |
| `/plugins enable / disable <name>` | Toggle plugin activation interactively. |
| `/reload-plugins` | Reload skills, slash commands, and MCP servers without restarting session. |
