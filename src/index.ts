/**
 * omp-strix — Strix adversarial security-testing mode for omp.
 *
 * `/strix` toggles strix mode on/off. On activation the strix system prompt
 * replaces the base prompt, the strix toolset is activated, the strix-red
 * theme is applied, and the status line's `path`/`git`/`pr` segments are
 * hidden (runtime-only settings override — nothing persisted). The operator
 * names the target and depth in conversation; the first prompt after
 * activation is captured as the scan target and starts
 * the scan record. The sandbox container starts lazily on the first `bash`
 * call. `/strix` again (or `finish_scan`, or session shutdown) ends the mode.
 */

import { copyFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { buildSystemPrompt } from "./prompt";
import {
  dockerAvailable,
  ensureSandbox,
  markSandboxActive,
  recordSandbox,
  rewriteBashInput,
  rewritePathInput,
  stopSandbox,
} from "./sandbox";
import { activeScan, beginScan, endScan, recordSubagentUsage, resetScanMetrics } from "./state";
import { STRIX_TOOLS } from "./tools";

const TOOL_NAMES = STRIX_TOOLS.map((t) => t.name);
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

interface StrixState {
  active: boolean;
  systemPrompt: string | null;
  preTools: string[] | null;
  /** Set once the first post-activation prompt has been captured as target. */
  scanStarted: boolean;
  /** In-flight sandbox start, so concurrent bash calls don't double-start. */
  sandboxStarting: Promise<string | null> | null;
  /** Whether bash is routed into the container this activation. */
  sandboxEnabled: boolean;
}

const strix: StrixState = {
  active: false,
  systemPrompt: null,
  preTools: null,
  scanStarted: false,
  sandboxStarting: null,
  sandboxEnabled: true,
};

// ── Status-line takeover ───────────────────────────────────────────────────
// The extension API cannot touch built-in status-line segments: `setStatus`
// only appends hook-status LINES BELOW the bar (that's why "◆ STRIX" was
// showing under the input field), and `setFooter`/`setHeader` are no-op stubs
// in interactive mode. Segments are driven by the `statusLine.*` settings, so
// while strix mode is on we:
//   - drop `path`/`git`/`pr` (cwd + branch leak local topology in screenshots)
//   - inject the built-in `status` segment so our hook-status text ("◆ STRIX")
//     renders INSIDE the bar instead of as a line under it
//   - set `showHookStatus: false` so the same text isn't duplicated below
// All via runtime-only `settings.override()` — nothing persisted to config.
//
// Two wrinkles:
//  1. `leftSegments`/`rightSegments` only take effect under preset "custom",
//     so we resolve the user's effective layout (preset + their overrides),
//     filter it, and re-pin separator/segmentOptions that the custom preset
//     would otherwise reset.
//  2. The status-line component only re-reads settings when the
//     `statusLine.sessionAccent` signal fires, so we toggle it twice to
//     force a resync that lands back on the user's original value.

type SettingsLike = {
  get(path: string): unknown;
  override(path: string, value: unknown): void;
  clearOverride(path: string): void;
};

const HIDDEN_SEGMENTS = new Set(["path", "git", "pr"]);

// Mirrors packages/tui/src/status-line/presets.ts — needed to resolve the
// effective segment list before filtering. Unknown presets fall back to
// "default", matching upstream getPreset().
const STATUS_LINE_PRESET_SEGMENTS: Record<
  string,
  { left: string[]; right: string[]; separator?: string; segmentOptions?: Record<string, unknown> }
> = {
  default: {
    left: ["pi", "vim", "model", "mode", "collab", "stream", "path", "git", "pr", "context_pct", "cost"],
    right: ["session_name"],
    separator: "powerline-thin",
    segmentOptions: {
      model: { showThinkingLevel: true },
      path: { abbreviate: true, maxLength: 40, stripWorkPrefix: true },
      git: { showBranch: true, showStaged: true, showUnstaged: true, showUntracked: true },
    },
  },
  minimal: {
    left: ["vim", "path", "git"],
    right: ["session_name", "mode", "context_pct"],
    separator: "slash",
    segmentOptions: {
      path: { abbreviate: true, maxLength: 30 },
      git: { showBranch: true, showStaged: false, showUnstaged: false, showUntracked: false },
    },
  },
  compact: {
    left: ["vim", "model", "mode", "git", "pr"],
    right: ["session_name", "cost", "context_pct"],
    separator: "powerline-thin",
    segmentOptions: {
      model: { showThinkingLevel: false },
      git: { showBranch: true, showStaged: true, showUnstaged: true, showUntracked: false },
    },
  },
  full: {
    left: ["pi", "vim", "hostname", "model", "mode", "path", "git", "pr", "subagents"],
    right: [
      "session_name",
      "cache_hit",
      "token_in",
      "token_out",
      "token_rate",
      "cache_read",
      "cost",
      "context_pct",
      "time_spent",
      "time",
    ],
    separator: "powerline",
    segmentOptions: {
      model: { showThinkingLevel: true },
      path: { abbreviate: true, maxLength: 50 },
      git: { showBranch: true, showStaged: true, showUnstaged: true, showUntracked: true },
      time: { format: "24h", showSeconds: false },
    },
  },
  nerd: {
    left: ["pi", "vim", "hostname", "model", "mode", "path", "git", "pr", "session", "subagents"],
    right: [
      "session_name",
      "token_in",
      "token_out",
      "cache_read",
      "cache_write",
      "token_rate",
      "cost",
      "context_pct",
      "context_total",
      "time_spent",
      "time",
    ],
    separator: "powerline",
    segmentOptions: {
      model: { showThinkingLevel: true },
      path: { abbreviate: true, maxLength: 60 },
      git: { showBranch: true, showStaged: true, showUnstaged: true, showUntracked: true },
      time: { format: "24h", showSeconds: true },
    },
  },
  ascii: {
    left: ["vim", "model", "mode", "path", "git", "pr"],
    right: ["session_name", "token_total", "cost", "context_pct"],
    separator: "ascii",
    segmentOptions: {
      model: { showThinkingLevel: true },
      path: { abbreviate: true, maxLength: 40 },
      git: { showBranch: true, showStaged: true, showUnstaged: true, showUntracked: true },
    },
  },
  custom: {
    left: ["vim", "model", "mode", "path", "git", "pr"],
    right: ["session_name", "token_total", "cost", "context_pct"],
    separator: "powerline-thin",
    segmentOptions: {},
  },
};
const STATUS_LINE_OVERRIDE_KEYS = [
  "statusLine.preset",
  "statusLine.leftSegments",
  "statusLine.rightSegments",
  "statusLine.separator",
  "statusLine.segmentOptions",
  "statusLine.showHookStatus",
  // resyncStatusLine() overrides this to force a re-read; must be cleared too.
  "statusLine.sessionAccent",
] as const;

let statusLineTaken = false;

function liveSettings(pi: ExtensionAPI): SettingsLike | null {
  try {
    // `pi.pi` is the pi-coding-agent module namespace; `settings` is the live
    // singleton proxy (throws before init — hence the probe).
    const s = (pi.pi as { settings?: SettingsLike }).settings;
    if (!s) return null;
    s.get("statusLine.preset"); // probe: throws if uninitialized
    return s;
  } catch {
    return null;
  }
}

/** Toggle sessionAccent twice — its signal is the only trigger that makes the
 *  status-line component re-read the whole `statusLine.*` group. */
function resyncStatusLine(s: SettingsLike): void {
  const accent = s.get("statusLine.sessionAccent") !== false;
  s.override("statusLine.sessionAccent", !accent);
  s.override("statusLine.sessionAccent", accent);
}

function applyStrixStatusLine(pi: ExtensionAPI): void {
  const s = liveSettings(pi);
  if (!s || statusLineTaken) return;
  const preset = String(s.get("statusLine.preset") ?? "default");
  const def = STATUS_LINE_PRESET_SEGMENTS[preset] ?? STATUS_LINE_PRESET_SEGMENTS.default;
  const custom = preset === "custom";
  const left = (custom ? (s.get("statusLine.leftSegments") as string[] | undefined) : undefined) ?? def.left;
  const right =
    (custom ? (s.get("statusLine.rightSegments") as string[] | undefined) : undefined) ?? def.right;
  const separator = (s.get("statusLine.separator") as string | undefined) ?? def.separator;
  const segmentOptions = {
    ...(def.segmentOptions ?? {}),
    ...((s.get("statusLine.segmentOptions") as Record<string, unknown> | undefined) ?? {}),
  };
  const newLeft = left.filter((id) => !HIDDEN_SEGMENTS.has(id));
  // Inject the built-in `status` segment so setStatus text renders inside the
  // bar — right after `mode` when present, else at the front.
  if (!newLeft.includes("status") && !right.includes("status")) {
    const at = newLeft.indexOf("mode");
    newLeft.splice(at >= 0 ? at + 1 : 0, 0, "status");
  }
  s.override("statusLine.preset", "custom");
  s.override("statusLine.leftSegments", newLeft);
  s.override(
    "statusLine.rightSegments",
    right.filter((id) => !HIDDEN_SEGMENTS.has(id)),
  );
  s.override("statusLine.separator", separator);
  s.override("statusLine.segmentOptions", segmentOptions);
  // Suppress the below-bar hook-status lines so "◆ STRIX" isn't duplicated
  // under the input field. Side effect: other plugins' hook statuses are
  // hidden too while strix mode is on.
  s.override("statusLine.showHookStatus", false);
  statusLineTaken = true;
  resyncStatusLine(s);
}

function restoreStatusLine(pi: ExtensionAPI): void {
  const s = liveSettings(pi);
  if (!s || !statusLineTaken) return;
  for (const key of STATUS_LINE_OVERRIDE_KEYS) s.clearOverride(key);
  statusLineTaken = false;
  resyncStatusLine(s);
}

/** Copy the bundled theme into the agent themes dir so setTheme can find it. */
function installTheme(): void {
  try {
    const themesDir = join(homedir(), ".omp", "agent", "themes");
    mkdirSync(themesDir, { recursive: true });
    copyFileSync(join(PLUGIN_ROOT, "themes", "strix-red.json"), join(themesDir, "strix-red.json"));
  } catch {
    /* theme install is best-effort */
  }
}

async function deactivate(
  pi: ExtensionAPI,
  ctx: { ui: { notify(m: string, l?: string): void } },
): Promise<void> {
  strix.active = false;
  restoreStatusLine(pi);
  strix.sandboxStarting = null;
  strix.sandboxEnabled = true;
  strix.systemPrompt = null;
  strix.scanStarted = false;
  endScan();
  try {
    (ctx as { ui?: { setStatus?(k: string, t: string): void } }).ui?.setStatus?.("strix_mode", "");
  } catch {
    /* no UI */
  }
  markSandboxActive(false);
  await stopSandbox();
  ctx.ui.notify("Strix mode off.", "info");
}

export default function (pi: ExtensionAPI) {
  installTheme();
  // Register the strix toolset up front, inactive — /strix (or a strix-*
  // subagent's tools list) activates them by name.
  for (const tool of STRIX_TOOLS) {
    pi.registerTool({ ...tool, defaultInactive: true });
  }
  pi.registerCommand("strix", {
    description:
      "Toggle strix security-testing mode. `/strix <target> [depth]` starts the scan immediately; bare `/strix` waits for the target in chat. Off: restores tools and stops the sandbox.",
    handler: async (args, ctx) => {
      if (strix.active) {
        await deactivate(pi, ctx);
        return;
      }

      // Ask whether to run commands inside the docker sandbox. Declining
      // skips the image pull entirely — bash runs on the host.
      // STRIX_SANDBOX=off skips the prompt entirely (README contract).
      let sandbox = process.env.STRIX_SANDBOX !== "off";
      if (sandbox && ctx.hasUI && ctx.ui.confirm) {
        try {
          sandbox = await ctx.ui.confirm(
            "Strix sandbox",
            "Run shell commands inside a disposable docker container (pulls ghcr.io/tmih06/omp-strix-sandbox on first use)? Decline to run directly on the host.",
          );
        } catch {
          sandbox = true;
        }
      }
      strix.sandboxEnabled = sandbox;

      installTheme();
      strix.systemPrompt = buildSystemPrompt({ sandbox: strix.sandboxEnabled });
      const preTools = pi.getActiveTools();
      strix.preTools = preTools;
      // Strip `goal` from the active set: goal mode injects a continuation
      // steer on every turn end, which forces the agent to keep polling
      // instead of sleeping until subagent completions arrive.
      await pi.setActiveTools([...preTools.filter((t) => t !== "goal"), ...TOOL_NAMES]);
      strix.active = true;

      const themeResult = await ctx.ui.setTheme("strix-red");
      if (!themeResult.success) {
        ctx.ui.notify(`Theme 'strix-red' not loaded: ${themeResult.error}`, "warning");
      }
      pi.setSessionName("strix");
      ctx.ui.setWorkingMessage("Scanning…");
      ctx.ui.setStatus?.("strix_mode", "◆ STRIX");
      applyStrixStatusLine(pi);
      const target = args.trim();
      ctx.ui.notify(
        target
          ? `Strix mode on${strix.sandboxEnabled ? " (sandboxed)" : " (NO sandbox — host exec)"} — starting scan on: ${target}`
          : strix.sandboxEnabled
            ? "Strix mode on (sandboxed). Name the target and depth (quick / standard / deep) in your next message — the scan starts there. /strix again to exit."
            : "Strix mode on (NO sandbox — commands run on the host). Name the target and depth in your next message. /strix again to exit.",
        "info",
      );
      // Args become the first prompt: before_agent_start captures it as the
      // scan target and the agent starts working immediately.
      if (target) pi.sendUserMessage?.(target);
    },
  });

  // While strix mode is on, replace the system prompt with the strix one.
  // The first prompt after activation is captured as the scan target.
  pi.on("before_agent_start", async (event) => {
    if (!strix.active || !strix.systemPrompt) return;
    if (!strix.scanStarted) {
      strix.scanStarted = true;
      const target = event.prompt?.trim() || "unspecified";
      resetScanMetrics();
      beginScan(target, "conversation");
      pi.setSessionName(`strix: ${target.slice(0, 60)}`);
    }
    return { systemPrompt: strix.systemPrompt };
  });

  // Tools that execute code on the HOST, bypassing the container: eval runs
  // Python/JS in-process, computer/debug drive host programs, and browser's
  // tab.run has full Bun/Node access. When the sandbox is on, block them —
  // otherwise an agent can escape isolation without touching bash.
  const HOST_EXEC_TOOLS = new Set(["eval", "computer", "debug", "browser"]);

  // Route bash calls into the sandbox while strix mode is on; the container
  // starts lazily on the first call.
  pi.on("tool_call", async (event) => {
    if (!strix.active || !strix.sandboxEnabled) return;
    if (HOST_EXEC_TOOLS.has(event.toolName)) {
      return {
        block: true,
        reason:
          "strix sandbox is on — host-side code execution is disabled. Run it through the bash tool instead; commands execute inside the container.",
      };
    }
    if (event.toolName !== "bash") {
      // File tools (write/read/grep/glob/edit) run on the host — map the
      // container's /workspace prefix onto the mounted host root so agents
      // can use the paths the prompt shows them.
      const rewritten = rewritePathInput(event.input as Record<string, unknown>);
      if (rewritten) return { input: rewritten };
      return;
    }
    if (!activeScan()) return; // no scan yet — nothing to sandbox against
    strix.sandboxStarting ??= (async () => {
      if (!(await dockerAvailable())) return "docker not available";
      const err = await ensureSandbox(process.cwd());
      if (!err) {
        recordSandbox(process.cwd());
        markSandboxActive(true);
      }
      return err;
    })();
    const err = await strix.sandboxStarting;
    if (err) return; // sandbox unavailable — run unsandboxed
    const rewritten = rewriteBashInput(event.input as Record<string, unknown>);
    if (rewritten) return { input: rewritten };
  });

  // Subagent usage isn't in the main session's token accounting — accumulate
  // it from `task` tool results so the scan's true cost is reported.
  pi.on("tool_result", async (event, ctx) => {
    if (!strix.active) return;
    const e = event as { toolName?: string; details?: unknown };
    // finish_scan ends the mode too — the tool can't reach this module's
    // state, so the runner-side hook does the teardown.
    if (e.toolName === "finish_scan") {
      await deactivate(pi, ctx);
      return;
    }
    if (e.toolName !== "task" || !e.details || typeof e.details !== "object") return;
    const d = e.details as { usage?: unknown; results?: unknown[]; totalDurationMs?: number };
    const runs = Array.isArray(d.results) ? d.results.length : 0;
    recordSubagentUsage(d.usage, typeof d.totalDurationMs === "number" ? d.totalDurationMs : 0, runs);
  });

  pi.on("session_shutdown", async () => {
    if (strix.active || activeScan()) {
      strix.active = false;
      strix.scanStarted = false;
      // Rotate active.json aside — otherwise scanDir()'s .last fallback lets
      // the next session's tools write into this dead scan.
      endScan();
      markSandboxActive(false);
      await stopSandbox();
    }
  });
}
