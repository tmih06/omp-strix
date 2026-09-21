/**
 * omp-strix — Strix adversarial security-testing mode for omp.
 *
 * `/strix <target> [--mode quick|standard|deep] [--whitebox] [--diff]` starts a
 * scan: builds the strix system prompt, activates the strix toolset, mounts
 * the session cwd into a shared docker sandbox, and rewrites `bash` calls to
 * run inside it. `/strix-off` ends the mode. `finish_scan` ends the scan and
 * writes the final report.
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

interface StrixState {
  active: boolean;
  systemPrompt: string | null;
  preTools: string[] | null;
}

const strix: StrixState = { active: false, systemPrompt: null, preTools: null };

const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

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

function parseArgs(args: string): {
  target: string;
  mode: string;
  whitebox: boolean;
  diff: boolean;
} {
  const tokens = args.split(/\s+/).filter(Boolean);
  let mode = "standard";
  let whitebox = false;
  let diff = false;
  const positional: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === "--mode" && tokens[i + 1]) {
      mode = tokens[++i];
    } else if (t === "--whitebox" || t === "-w") {
      whitebox = true;
    } else if (t === "--diff") {
      diff = true;
    } else {
      positional.push(t);
    }
  }
  return { target: positional.join(" "), mode, whitebox, diff };
}

export default function (pi: ExtensionAPI) {
  for (const tool of STRIX_TOOLS) {
    pi.registerTool({ ...tool, defaultInactive: true });
  }

  pi.registerCommand("strix", {
    description:
      "Start a strix security scan: /strix <target> [--mode quick|standard|deep] [--whitebox] [--diff]",
    handler: async (args, ctx) => {
      const { target, mode, whitebox, diff } = parseArgs(args);
      if (!target) {
        ctx.ui.notify(
          "Usage: /strix <target> [--mode quick|standard|deep] [--whitebox] [--diff]",
          "error",
        );
        return;
      }
      if (strix.active) {
        ctx.ui.notify("A strix scan is already active — /strix-off first.", "warning");
        return;
      }

      const scan = beginScan(target, mode);

      // Sandbox: build/pull the image and start the shared container.
      installTheme();
      let sandboxNote = "";
      if (await dockerAvailable()) {
        const err = await ensureSandbox(process.cwd());
        if (err) {
          sandboxNote = ` Sandbox unavailable: ${err}`;
        } else {
          recordSandbox(process.cwd());
          markSandboxActive(true);
          sandboxNote = ` Sandbox: docker container 'omp-strix-sandbox' (${sandboxImage()}), cwd mounted at /workspace.`;
        }
      } else {
        sandboxNote = " Docker not available — commands run unsandboxed.";
      }

      strix.systemPrompt = buildSystemPrompt({
        target,
        scanMode: mode,
        isWhitebox: whitebox,
        isDiffScoped: diff,
      });
      const preTools = pi.getActiveTools();
      strix.preTools = preTools;
      await pi.setActiveTools([...preTools, ...TOOL_NAMES]);
      strix.active = true;

      const themeResult = await ctx.ui.setTheme("strix-red");
      if (!themeResult.success) {
        ctx.ui.notify(`Theme 'strix-red' not loaded: ${themeResult.error}`, "warning");
      }
      pi.setSessionName(`strix: ${target}`);
      ctx.ui.setWorkingMessage("Scanning…");
      ctx.ui.notify(
        `Strix scan started — target: ${target} | mode: ${mode}${whitebox ? " | whitebox" : ""}${diff ? " | diff" : ""}.${sandboxNote}`,
        "info",
      );
      ctx.ui.notify(
        "Scan initialized. The strix system prompt is active — describe the objective or let the agent begin recon.",
        "info",
      );
    },
  });

  pi.registerCommand("strix-off", {
    description: "End strix mode: restore tools, stop the sandbox, end the scan.",
    handler: async (_args, ctx) => {
      if (!strix.active) {
        ctx.ui.notify("No strix scan is active.", "warning");
        return;
      }
      strix.active = false;
      strix.systemPrompt = null;
      if (strix.preTools) await pi.setActiveTools(strix.preTools);
      strix.preTools = null;
      endScan();
      markSandboxActive(false);
      await stopSandbox();
      ctx.ui.notify("Strix mode off. Scan ended; sandbox removed.", "info");
    },
  });

  // While a scan is active, replace the system prompt with the strix one.
  pi.on("before_agent_start", async (event) => {
    if (!strix.active || !strix.systemPrompt) return;
    void event;
    return { systemPrompt: strix.systemPrompt };
  });

  // Route bash calls into the sandbox while a scan is active.
  pi.on("tool_call", async (event) => {
    if (!strix.active) return;
    if (event.toolName !== "bash") return;
    const rewritten = rewriteBashInput(event.input as Record<string, unknown>);
    if (rewritten) return { input: rewritten };
  });

  pi.on("session_shutdown", async () => {
    if (strix.active || activeScan()) {
      strix.active = false;
      markSandboxActive(false);
      await stopSandbox();
    }
  });
}
