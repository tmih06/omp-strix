/**
 * Sandbox-aware `bash` replacement. Registered under the builtin name so the
 * transcript shows the agent's original command — the docker exec wrapper
 * lives inside execute(), not in the displayed/persisted input.
 *
 * When the strix sandbox is active the command runs via `docker exec` into
 * the shared container; otherwise it falls back to host `bash -c`. Commands
 * that already start with `docker` always run on the host (the container has
 * no docker client).
 */

import { spawn } from "node:child_process";
import { join } from "node:path";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { activeSandbox, WORKSPACE } from "./sandbox";

type Json = Record<string, unknown>;
type ThemeLike = { fg(color: string, text: string): string };

const MAX_OUTPUT = 200 * 1024; // tail-kept
const DEFAULT_TIMEOUT_S = 300;

function text(s: string): { content: { type: string; text: string }[] } {
  return { content: [{ type: "text", text: s }] };
}

function run(
  argv: string[],
  opts: { cwd?: string; timeoutS: number; signal?: AbortSignal },
): Promise<{ code: number; output: string; timedOut: boolean }> {
  return new Promise((resolve) => {
    const child = spawn(argv[0]!, argv.slice(1), {
      cwd: opts.cwd,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let timedOut = false;
    const append = (chunk: Buffer) => {
      out += chunk.toString("utf8");
      if (out.length > MAX_OUTPUT) out = out.slice(out.length - MAX_OUTPUT);
    };
    child.stdout.on("data", append);
    child.stderr.on("data", append);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, opts.timeoutS * 1000);
    const onAbort = () => {
      timedOut = true;
      child.kill("SIGKILL");
    };
    opts.signal?.addEventListener("abort", onAbort, { once: true });
    child.on("error", (err) => {
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
      resolve({ code: 127, output: `spawn failed: ${err.message}`, timedOut: false });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
      resolve({ code: code ?? 1, output: out, timedOut });
    });
  });
}

/** Map a host-side cwd into the container's /workspace mount. */
function containerCwd(requested: string | undefined, workspaceRoot: string): string {
  if (!requested) return WORKSPACE;
  if (requested === workspaceRoot) return WORKSPACE;
  if (requested.startsWith(`${workspaceRoot}/`)) {
    return join(WORKSPACE, requested.slice(workspaceRoot.length));
  }
  return WORKSPACE;
}

export function strixBash(pi: ExtensionAPI) {
  const { Text, highlightCode } = pi.pi as {
    Text: new (
      text: string,
      paddingX?: number,
      paddingY?: number,
    ) => {
      render(width: number): readonly string[];
    };
    highlightCode?: (code: string, lang?: string, theme?: unknown) => string[];
  };

  /** `$ cmd` / `▣ cmd` preview with bash syntax highlighting. */
  const commandLines = (cmd: string, sandboxed: boolean, theme: ThemeLike): string[] => {
    const icon = sandboxed ? "▣" : "$";
    const prefix = theme.fg("dim", `${icon} `);
    const highlighted = highlightCode?.(cmd, "bash", theme) ?? cmd.split("\n");
    return highlighted.map((l, i) => (i === 0 ? `${prefix}${l}` : `   ${l}`));
  };

  return {
    name: "bash",
    label: "Bash",
    description:
      "Execute a bash command. While strix mode is sandboxed the command runs inside the shared container (mounted at /workspace); otherwise it runs on the host.",
    parameters: {
      type: "object",
      properties: {
        command: { type: "string", description: "command to execute" },
        timeout: { type: "number", description: "timeout in seconds (default 300)" },
        cwd: { type: "string", description: "working directory" },
      },
      required: ["command"],
    },
    // Renders the call as `▣ <command>` when the sandbox is active — the
    // icon marks container execution; `$` prefix on the host path.
    renderCall(args: Record<string, unknown>, _opts: unknown, theme: ThemeLike) {
      const cmd = typeof args?.command === "string" ? args.command : "";
      const sandboxed = activeSandbox() !== null && !/^\s*docker\s/.test(cmd);
      return new Text(commandLines(cmd, sandboxed, theme).join("\n"), 1, 0);
    },
    renderResult(
      result: { content?: { type: string; text?: string }[]; details?: Json; isError?: boolean },
      _opts: unknown,
      theme: ThemeLike,
      args?: Record<string, unknown>,
    ) {
      const cmd = typeof args?.command === "string" ? args.command : "";
      const sandboxed = result.details?.sandboxed === true;
      const out = result.content?.find((c) => c.type === "text")?.text ?? "";
      const exitCode = typeof result.details?.exitCode === "number" ? result.details.exitCode : undefined;
      const ms = typeof result.details?.durationMs === "number" ? result.details.durationMs : undefined;
      const footerBits = [
        exitCode !== undefined ? `exit ${exitCode}` : undefined,
        ms !== undefined ? `${(ms / 1000).toFixed(1)}s` : undefined,
        result.details?.timedOut === true ? "timed out" : undefined,
      ].filter(Boolean);
      const footer = footerBits.length ? theme.fg("dim", `\n${footerBits.join(" · ")}`) : "";
      const head = commandLines(cmd, sandboxed, theme).join("\n");
      const body = `${head}\n${out}${footer}`;
      return new Text(body, 1, 0);
    },
    async execute(
      _id: string,
      params: Record<string, unknown>,
      signal: AbortSignal | undefined,
      _onUpdate: unknown,
      _ctx: unknown,
    ): Promise<{ content: { type: string; text: string }[]; details?: Json }> {
      const command = typeof params.command === "string" ? params.command : "";
      if (!command.trim()) return text("bash: empty command");
      const timeoutS =
        typeof params.timeout === "number" && params.timeout > 0 ? params.timeout : DEFAULT_TIMEOUT_S;
      const cwd = typeof params.cwd === "string" ? params.cwd : undefined;

      const sb = activeSandbox();
      const isDockerCall = /^\s*docker\s/.test(command);
      const started = Date.now();

      if (sb && !isDockerCall) {
        // umask 000: the container runs as root — files it writes into the
        // /workspace mount must stay world-writable for the host user.
        const inner = `umask 000; cd ${JSON.stringify(containerCwd(cwd, sb.workspaceRoot))} && ${command}`;
        const res = await run(["docker", "exec", "omp-strix-sandbox", "sh", "-c", inner], {
          timeoutS,
          signal,
        });
        const suffix = res.timedOut ? `\n\n[command timed out after ${timeoutS}s]` : "";
        return {
          content: [{ type: "text", text: (res.output || "(no output)") + suffix }],
          details: {
            exitCode: res.code,
            timedOut: res.timedOut,
            sandboxed: true,
            durationMs: Date.now() - started,
          },
        };
      }

      // Host path: no sandbox, or the agent deliberately issued a docker command.
      const res = await run(["bash", "-c", command], { cwd, timeoutS, signal });
      const suffix = res.timedOut ? `\n\n[command timed out after ${timeoutS}s]` : "";
      return {
        content: [{ type: "text", text: (res.output || "(no output)") + suffix }],
        details: {
          exitCode: res.code,
          timedOut: res.timedOut,
          sandboxed: false,
          durationMs: Date.now() - started,
        },
      };
    },
  };
}
