/**
 * omp-strix — Strix adversarial security-testing mode for omp.
 *
 * `/strix` toggles strix mode on/off. On activation the strix system prompt
 * replaces the base prompt, the strix toolset is activated, the strix-red
 * theme is applied, and the status line's `path`/`git`/`pr` segments are
 * hidden (runtime-only settings override — nothing persisted). The operator
 * names the target and depth in conversation; the first prompt after
 * activation is captured as the scan target and starts the scan record.
 * The docker sandbox is mandatory: activation arms and verifies the
 * container (progress in a widget below the editor, never the status line)
 * and refuses to activate when it cannot start or when STRIX_SANDBOX=off —
 * agent commands never run on the host. `/strix` again (or session
 * shutdown) ends the mode — finish_scan closes the scan but keeps the mode
 * on so the user can discuss findings.
 */

import { copyFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { strixBash } from "./bash-tool";
import { PLUGIN_ROOT } from "./paths";
import { buildSystemPrompt } from "./prompt";
import {
  activeSandbox,
  armSandbox,
  disarmSandbox,
  ensureSandboxRunning,
  markSandboxActive,
  sandboxRoot,
  setSandboxContext,
  stopSandbox,
} from "./sandbox";
import {
  activeScan,
  beginScan,
  collectSubagentMetrics,
  endScan,
  resumableScan,
  setProjectDir,
} from "./state";
import { STRIX_TOOLS } from "./tools";

const TOOL_NAMES = STRIX_TOOLS.map((t) => t.name);

interface StrixState {
  active: boolean;
  systemPrompt: string | null;
  preTools: string[] | null;
  /** Set once the first post-activation prompt has been captured as target. */
  scanStarted: boolean;
  /**
   * Session id that ran /strix. Subagent sessions get their own
   * ExtensionRunner and emit session_start/before_agent_start/session_shutdown
   * on the shared module state — without this guard a subagent's shutdown
   * would end the scan and kill the sandbox mid-run.
   */
  ownerSessionId: string | null;
  /** Theme object active before /strix switched to strix-red. */
  prevTheme: unknown;
}

const strix: StrixState = {
  active: false,
  systemPrompt: null,
  preTools: null,
  scanStarted: false,
  ownerSessionId: null,
  prevTheme: null,
};

/** Session id of the ctx that emitted this event, or null when unknown. */
function eventSessionId(ctx: unknown): string | null {
  const sm = (ctx as { sessionManager?: { getSessionId?: () => string } } | undefined)?.sessionManager;
  try {
    return sm?.getSessionId?.() ?? null;
  } catch {
    return null;
  }
}

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
  const newRight = right.filter((id) => !HIDDEN_SEGMENTS.has(id));
  // Show cumulative token usage beside cost.
  if (!newRight.includes("token_total")) {
    const at = newRight.indexOf("cost");
    newRight.splice(at >= 0 ? at : newRight.length, 0, "token_total");
  }
  s.override("statusLine.rightSegments", newRight);
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

// ── Sandbox progress widget ──────────────────────────────────────────────
// Image check/pull/build and container startup can take minutes on first
// run. Progress renders in a dedicated widget BELOW the editor — never in
// the status line, which stays a steady "◆ STRIX". The widget is cleared on
// success, failure, /strix off, and session shutdown.
const PROGRESS_WIDGET_KEY = "strix_image_progress";
const PROGRESS_WIDGET_LABEL = "◆ STRIX — sandbox setup";

function showSandboxProgress(ctx: ExtensionContext, msg: string): void {
  try {
    ctx.ui.setWidget?.(PROGRESS_WIDGET_KEY, [PROGRESS_WIDGET_LABEL, `  ${msg}`], {
      placement: "belowEditor",
    });
  } catch {
    /* no UI */
  }
}

function clearSandboxProgress(ctx: ExtensionContext): void {
  try {
    ctx.ui.setWidget?.(PROGRESS_WIDGET_KEY, undefined);
  } catch {
    /* no UI */
  }
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

async function deactivate(pi: ExtensionAPI, ctx: ExtensionContext): Promise<void> {
  strix.active = false;
  restoreStatusLine(pi);
  clearSandboxProgress(ctx);
  try {
    markSandboxActive(false);
  } catch (e) {
    ctx.ui.notify(`Could not clear sandbox marker: ${String(e)}`, "error");
  }
  disarmSandbox();
  strix.systemPrompt = null;
  strix.scanStarted = false;
  strix.ownerSessionId = null;
  // Restore the toolset captured at activation — the command description
  // promises "restores tools" and strix tools must not leak into normal mode.
  if (strix.preTools) {
    try {
      await pi.setActiveTools(strix.preTools);
    } catch {
      /* tool restore is best-effort */
    }
    strix.preTools = null;
  }
  // Restore the pre-strix theme (captured as a Theme object at activation).
  if (strix.prevTheme) {
    try {
      await ctx.ui.setTheme?.(strix.prevTheme);
    } catch {
      /* theme restore is best-effort */
    }
    strix.prevTheme = null;
  }
  try {
    endScan();
  } catch (e) {
    ctx.ui.notify(`Could not finalize scan state: ${String(e)}`, "error");
  }
  try {
    ctx.ui.setStatus?.("strix_mode", "");
  } catch {
    /* no UI */
  }
  await stopSandbox();
  ctx.ui.notify("Strix mode off.", "info");
}

export default function (pi: ExtensionAPI) {
  // Register the strix toolset up front, inactive — /strix (or a strix-*
  // subagent's tools list) activates them by name.
  // Shadow the builtin bash: the transcript shows the agent's original
  // command while execute() routes into the container when the sandbox is
  // on. Registered unconditionally — it falls back to host bash otherwise.
  pi.registerTool(strixBash(pi));
  for (const tool of STRIX_TOOLS) {
    pi.registerTool({ ...tool, defaultInactive: true });
  }
  pi.on("session_start", (_event, ctx) => {
    const root = sandboxRoot() ?? ctx.cwd ?? process.cwd();
    setProjectDir(root);
    setSandboxContext(root);
  });
  pi.registerCommand("strix", {
    description:
      "Toggle strix security-testing mode (docker sandbox required — commands never run on the host). `/strix <target> [depth]` starts the scan immediately; bare `/strix` waits for the target in chat. Off: restores tools and stops the sandbox.",
    handler: async (args, ctx) => {
      if (strix.active) {
        await deactivate(pi, ctx);
        return;
      }

      // The docker sandbox is mandatory — agent-triggered commands must
      // never run on the host. STRIX_SANDBOX=off is a hard refusal, not a
      // host opt-out: reject before any side effects (theme, status line,
      // image pull, tool activation).
      if (process.env.STRIX_SANDBOX === "off") {
        ctx.ui.notify(
          "Strix requires the docker sandbox but STRIX_SANDBOX=off is set. Unset it to activate — commands never run on the host.",
          "error",
        );
        return;
      }
      installTheme();
      const tui = pi.pi;
      strix.prevTheme =
        tui &&
        typeof tui === "object" &&
        "getCurrentThemeName" in tui &&
        typeof tui.getCurrentThemeName === "function"
          ? String(tui.getCurrentThemeName() ?? "") || null
          : null;
      const themeResult = (await ctx.ui.setTheme?.("strix-red")) ?? { success: false, error: "no UI" };
      if (!themeResult.success) {
        ctx.ui.notify(`Theme 'strix-red' not loaded: ${themeResult.error}`, "warning");
      }
      pi.setSessionName("strix");
      applyStrixStatusLine(pi);

      // Arm and verify the container before any strix tool can run: image
      // check/pull/build and container creation happen here, with progress
      // in a widget below the editor — never in the status line. Command
      // handlers are interactive and not subject to the 30s event timeout.
      armSandbox(ctx.cwd ?? process.cwd());
      showSandboxProgress(ctx, "checking docker…");
      const onProgress = (msg: string) => showSandboxProgress(ctx, msg);
      const err = await ensureSandboxRunning(onProgress).catch((e) => String(e));
      if (err || !activeSandbox()) {
        // Never turn a failed sandbox into an unsandboxed scan.
        ctx.ui.notify(
          `Sandbox failed to start (${err ?? "state not recorded"}). Strix not activated.`,
          "error",
        );
        try {
          markSandboxActive(false);
        } catch {
          /* malformed .strix dir: keep the scan disabled */
        }
        disarmSandbox();
        await stopSandbox();
        clearSandboxProgress(ctx);
        ctx.ui.setStatus?.("strix_mode", "");
        restoreStatusLine(pi);
        if (strix.prevTheme) {
          await ctx.ui.setTheme?.(strix.prevTheme);
          strix.prevTheme = null;
        }
        return;
      }
      clearSandboxProgress(ctx);
      ctx.ui.notify("Sandbox container ready.", "info");

      ctx.ui.setStatus?.("strix_mode", "◆ STRIX");
      strix.systemPrompt = buildSystemPrompt({});
      const preTools = pi.getActiveTools();
      strix.preTools = preTools;
      // Retain only sandbox-approved orchestration tools. The hook below
      // also blocks unavailable/hidden tools requested by name.
      const activeTools = preTools.filter((t) => SANDBOX_TOOLS.has(t));
      await pi.setActiveTools([...new Set([...activeTools, ...TOOL_NAMES])]);
      strix.active = true;
      strix.ownerSessionId = eventSessionId(ctx);
      // Scan artifacts and both bind sources are rooted in ./.strix.
      setProjectDir(ctx.cwd ?? process.cwd());
      // the builtin cost segment. Refreshed on an interval; cleared on
      // session_shutdown by the runner's managed timers.
      const updateTokens = () => {
        if (!strix.active) return;
        const sm = ctx.sessionManager as
          | {
              getUsageStatistics?: () => {
                input?: number;
                output?: number;
                cacheWrite?: number;
              };
              getSessionFile?: () => string | undefined;
            }
          | undefined;
        // Match the agent hub's accounting: input+output+cacheWrite per
        // assistant message — cacheRead re-reads full context each turn and
        // would inflate the sum far past the hub's total.
        const u = sm?.getUsageStatistics?.();
        const main = (u?.input ?? 0) + (u?.output ?? 0) + (u?.cacheWrite ?? 0);
        const sub = collectSubagentMetrics(sm?.getSessionFile?.()).subagentUsage.effectiveTokens;
        const total = main + sub;
        if (total > 0) {
          const fmt = (n: number) =>
            n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)}M` : `${Math.round(n / 1000)}K`;
          ctx.ui.setStatus?.("strix_mode", `◆ STRIX · Σ ${fmt(total)}`);
        }
      };
      ctx.setInterval?.(updateTokens, 15_000);
      updateTokens();
      const target = args.trim();
      ctx.ui.notify(
        target
          ? `Strix mode on (sandboxed) — starting scan on: ${target}`
          : "Strix mode on (sandboxed). Name the target and depth (quick / standard / deep) in your next message — the scan starts there. /strix again to exit.",
        "info",
      );
      // Args become the first prompt: before_agent_start captures it as the
      // scan target and the agent starts working immediately.
      if (target) pi.sendUserMessage?.(target);
    },
  });

  // While strix mode is on, replace the system prompt with the strix one.
  // The first prompt after activation is captured as the scan target.
  pi.on("before_agent_start", async (event, ctx) => {
    // Only the owning session gets the strix prompt — subagent sessions emit
    // this event on their own runner and must keep their agent-def prompt.
    if (!strix.active || !strix.systemPrompt) return;
    if (strix.ownerSessionId && eventSessionId(ctx) !== strix.ownerSessionId) return;
    if (!strix.scanStarted) {
      strix.scanStarted = true;
      // Resume an interrupted scan: active.json survives a crash/kill, and
      // a scan dir without ended.json means the last session never closed
      // it. Reuse the dir so notes/coverage/reports accumulate in place.
      const prior = resumableScan();
      // Only a sandboxed scan may resume — a host-mode scan record is never
      // continued, it is replaced by a fresh sandboxed scan.
      if (prior?.sandboxed === true) {
        pi.setSessionName(`strix: ${prior.target.slice(0, 60)}`);
        const artifacts = `/workspace/.strix/scans/${prior.scanId}`;
        return {
          systemPrompt: strix.systemPrompt,
          message: `[strix] Resuming interrupted scan ${prior.scanId} of "${prior.target}" (started ${prior.startedAt}). Prior artifacts are in ${artifacts} — read notes/, coverage/, reports/ and threat-models/ there before re-running work.`,
        };
      }
      const target = event.prompt?.trim() || "unspecified";
      beginScan(target, "conversation", true);
      pi.setSessionName(`strix: ${target.slice(0, 60)}`);
    }
    return { systemPrompt: strix.systemPrompt };
  });

  // Only explicitly reviewed tool implementations may run while sandboxed.
  // Native file/network/MCP/eval tools run on the host, even for read-only
  // calls; an unrecognized plugin tool must not become a new escape hatch.
  const SANDBOX_TOOLS = new Set([...TOOL_NAMES, "bash", "task", "wait", "todo", "ask"]);
  const SANDBOX_AGENTS: Record<string, true> = {
    "strix-recon": true,
    "strix-hunter": true,
    "strix-validator": true,
    "strix-reporter": true,
    "strix-privesc": true,
    "strix-pivot": true,
  };

  // Dangerous-command guardrail (CAI-style): block destructive/exfiltrating
  // commands even inside the sandbox — a pentest agent should never need
  // rm -rf /, fork bombs, block-device writes, or env-var exfiltration.
  const DANGEROUS_COMMANDS: { pattern: RegExp; reason: string }[] = [
    {
      pattern:
        /\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+(-[a-zA-Z]*r[a-zA-Z]*)?|(-[a-zA-Z]*r[a-zA-Z]*\s+)?-[a-zA-Z]*f[a-zA-Z]*)\s+(?:--\s+)?\/(\s|$|\*|etc|boot|bin|sbin|usr|lib|var|dev|proc|sys|root|home)/,
      reason: "Recursive forced deletion of system-critical paths",
    },
    { pattern: /\bdd\b.*\bof\s*=\s*\/dev\//, reason: "Direct write to block device" },
    { pattern: /\bmkfs\b/, reason: "Filesystem format command" },
    { pattern: />\s*\/dev\/[sh]d[a-z]/, reason: "Redirect to block device" },
    { pattern: /:\(\)\{\s*:\|\s*:&\s*\}\s*;/, reason: "Fork bomb" },
    { pattern: /\b(shutdown|poweroff|halt)\b(\s|$)/, reason: "System shutdown/halt" },
    { pattern: /\bcurl\b.*\$\(env\)/, reason: "Environment variable exfiltration via curl" },
    { pattern: /\bcurl\b.*\$\(cat\s+\/etc\/(passwd|shadow)/, reason: "Credential exfiltration via curl" },
    { pattern: /\bbase64\s+(-d|--decode)\b.*\|\s*(ba)?sh\b/, reason: "Base64 decode-and-pipe to shell" },
  ];

  // This guard also runs in subagent extension runners: their local `strix`
  // flag can be false while the owning session's sandbox is active.
  pi.on("tool_call", (event) => {
    if (!(sandboxRoot() || activeSandbox() || activeScan()?.sandboxed)) return;
    if (!SANDBOX_TOOLS.has(event.toolName)) {
      return {
        block: true,
        reason:
          "strix sandbox is on: host-side tools are disabled. Read source and write scratch through bash inside the container (/workspace is read-only; /scratch is writable).",
      };
    }
    if (event.toolName === "task") {
      const tasks = event.input?.tasks;
      if (
        !Array.isArray(tasks) ||
        tasks.length === 0 ||
        tasks.some(
          (task: unknown) =>
            !task ||
            typeof task !== "object" ||
            !("agent" in task) ||
            typeof task.agent !== "string" ||
            !Object.hasOwn(SANDBOX_AGENTS, task.agent) ||
            ("tools" in task && task.tools !== undefined),
        )
      ) {
        return {
          block: true,
          reason: "Sandboxed scans can spawn only strix-* specialist agents with their fixed tool lists.",
        };
      }
    }
    if (event.toolName === "bash") {
      const cmd = String(event.input?.command ?? "");
      for (const { pattern, reason } of DANGEROUS_COMMANDS) {
        if (pattern.test(cmd)) {
          return { block: true, reason: `Blocked by strix safety guardrail: ${reason}` };
        }
      }
    }
  });

  pi.on("session_shutdown", async (_event, ctx) => {
    // Subagent sessions emit this on their own runner — only the session
    // that ran /strix may tear the scan down.
    if (!strix.active || !strix.ownerSessionId || eventSessionId(ctx) !== strix.ownerSessionId) return;
    strix.active = false;
    strix.scanStarted = false;
    // Rotate active.json aside — otherwise scanDir()'s .last fallback lets
    // the next session's tools write into this dead scan.
    try {
      endScan();
    } catch {
      /* always tear down the container, even if scan state is damaged */
    }
    try {
      markSandboxActive(false);
    } catch {
      /* marker may remain: subsequent agents will fail closed */
    }
    disarmSandbox();
    clearSandboxProgress(ctx);
    // Shutdown handlers get ~2s — docker rm can outlast that; don't await.
    void stopSandbox();
  });
}
