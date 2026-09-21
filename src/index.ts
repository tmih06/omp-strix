/**
 * omp-strix — Strix adversarial security-testing mode for omp.
 *
 * `/strix` toggles strix mode on/off. On activation the strix system prompt
 * replaces the base prompt, the strix toolset is activated, and the strix-red
 * theme is applied. The operator names the target and depth in conversation;
 * the first prompt after activation is captured as the scan target and starts
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
  sandboxImage,
  stopSandbox,
} from "./sandbox";
import { activeScan, beginScan, endScan } from "./state";
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
}

const strix: StrixState = {
  active: false,
  systemPrompt: null,
  preTools: null,
  scanStarted: false,
  sandboxStarting: null,
};

/** Copy the bundled theme into the agent themes dir so setTheme can find it. */
function installTheme(): void {
  try {
    const themesDir = join(homedir(), ".omp", "agent", "themes");
    mkdirSync(themesDir, { recursive: true });
    copyFileSync(
      join(PLUGIN_ROOT, "themes", "strix-red.json"),
      join(themesDir, "strix-red.json"),
    );
  } catch {
    /* theme install is best-effort */
  }
}

async function deactivate(pi: ExtensionAPI, ctx: { ui: { notify(m: string, l?: string): void } }): Promise<void> {
  strix.active = false;
  strix.systemPrompt = null;
  strix.scanStarted = false;
  strix.sandboxStarting = null;
  if (strix.preTools) await pi.setActiveTools(strix.preTools);
  strix.preTools = null;
  endScan();
  markSandboxActive(false);
  await stopSandbox();
  ctx.ui.notify("Strix mode off.", "info");
}

export default function (pi: ExtensionAPI) {
  for (const tool of STRIX_TOOLS) {
    pi.registerTool({ ...tool, defaultInactive: true });
  }

  installTheme();
  pi.registerCommand("strix", {
    description:
      "Toggle strix security-testing mode. On: strix prompt + tools + red theme; name the target and depth in chat. Off: restores tools and stops the sandbox.",
    handler: async (_args, ctx) => {
      if (strix.active) {
        await deactivate(pi, ctx);
        return;
      }

      installTheme();
      strix.systemPrompt = buildSystemPrompt({});
      const preTools = pi.getActiveTools();
      strix.preTools = preTools;
      await pi.setActiveTools([...preTools, ...TOOL_NAMES]);
      strix.active = true;

      const themeResult = await ctx.ui.setTheme("strix-red");
      if (!themeResult.success) {
        ctx.ui.notify(`Theme 'strix-red' not loaded: ${themeResult.error}`, "warning");
      }
      pi.setSessionName("strix");
      ctx.ui.setWorkingMessage("Scanning…");
      ctx.ui.notify(
        "Strix mode on. Name the target and depth (quick / standard / deep) in your next message — the scan starts there. /strix again to exit.",
        "info",
      );
    },
  });

  // While strix mode is on, replace the system prompt with the strix one.
  // The first prompt after activation is captured as the scan target.
  pi.on("before_agent_start", async (event) => {
    if (!strix.active || !strix.systemPrompt) return;
    if (!strix.scanStarted) {
      strix.scanStarted = true;
      const target = event.prompt?.trim() || "unspecified";
      beginScan(target, "conversation");
      pi.setSessionName(`strix: ${target.slice(0, 60)}`);
    }
    return { systemPrompt: strix.systemPrompt };
  });

  // Route bash calls into the sandbox while strix mode is on; the container
  // starts lazily on the first call.
  pi.on("tool_call", async (event) => {
    if (!strix.active) return;
    if (event.toolName !== "bash") return;
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

  pi.on("session_shutdown", async () => {
    if (strix.active || activeScan()) {
      strix.active = false;
      strix.scanStarted = false;
      markSandboxActive(false);
      await stopSandbox();
    }
  });
}
