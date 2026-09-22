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
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { activeSandbox, WORKSPACE } from "./sandbox";
import { scanDir } from "./state";

type Json = Record<string, unknown>;
type ThemeLike = {
  fg(color: string, text: string): string;
  styledSymbol?(key: string, color?: string): string;
};

const MAX_OUTPUT = 200 * 1024; // tail-kept

const ESC = String.fromCharCode(27);
const ANSI_RE = new RegExp(`${ESC}\\[[0-9;]*[a-zA-Z]`, "g");
const ANSI_PREFIX_RE = new RegExp(`^${ESC}\\[[0-9;]*[a-zA-Z]`);
const RESET = `${ESC}[0m`;
const visWidth = (s: string): number => [...s.replace(ANSI_RE, "")].length;
const truncateVis = (s: string, w: number): string => {
  if (visWidth(s) <= w) return s;
  let out = "";
  let n = 0;
  let i = 0;
  while (i < s.length && n < w) {
    const m = s.slice(i).match(ANSI_PREFIX_RE);
    if (m) {
      out += m[0];
      i += m[0].length;
      continue;
    }
    const cp = s.codePointAt(i)!;
    const ch = String.fromCodePoint(cp);
    out += ch;
    i += ch.length;
    n++;
  }
  return out + RESET;
};
const padVis = (s: string, w: number): string => s + " ".repeat(Math.max(0, w - visWidth(s)));
/** Wrap a possibly-styled line to `w` visible columns (hard break, ANSI-safe). */
const wrapVis = (s: string, w: number): string[] => {
  if (visWidth(s) <= w) return [s];
  const lines: string[] = [];
  let cur = "";
  let n = 0;
  let i = 0;
  while (i < s.length) {
    const m = s.slice(i).match(ANSI_PREFIX_RE);
    if (m) {
      cur += m[0];
      i += m[0].length;
      continue;
    }
    const cp = s.codePointAt(i)!;
    const ch = String.fromCodePoint(cp);
    if (n >= w) {
      lines.push(cur + RESET);
      cur = "";
      n = 0;
    }
    cur += ch;
    i += ch.length;
    n++;
  }
  if (cur) lines.push(cur);
  return lines;
};
const DEFAULT_TIMEOUT_S = 300;

function text(s: string): { content: { type: string; text: string }[] } {
  return { content: [{ type: "text", text: s }] };
}

export function run(
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

/** Save oversized output to the scan dir and return a bounded tail. */
const CONTEXT_OUTPUT_CAP = 32 * 1024; // what the agent actually sees

/** Detect minified JS/CSS (long single lines, no whitespace structure). */
function isMinified(raw: string): boolean {
  const lines = raw.split("\n");
  if (lines.length > 50) return false;
  const longLines = lines.filter((l) => l.length > 500);
  return longLines.length > 0 && longLines.length >= lines.length * 0.5;
}

/** Detect binary content (null bytes, high control-char ratio). */
function isBinary(raw: string): boolean {
  if (raw.includes("\0")) return true;
  const sample = raw.slice(0, 4096);
  const ctrl = [...sample].filter((c) => {
    const code = c.charCodeAt(0);
    return code < 9 || (code > 13 && code < 32);
  }).length;
  return ctrl / Math.max(1, sample.length) > 0.05;
}

/** Hex preview for binary content. */
function hexPreview(raw: string, maxBytes = 256): string {
  const bytes = Buffer.from(raw.slice(0, maxBytes), "utf8");
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.subarray(i, i + 16);
    const hex = [...chunk].map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = [...chunk].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return lines.join("\n");
}

/** Wrap untrusted command output so the model treats it as data, not instructions. */
function sanitizeOutput(raw: string): string {
  // Strip sequences that could be interpreted as prompt boundaries or
  // instructions embedded in target-side output (HTTP responses, banners, etc.).
  return raw
    .replace(/={10,}/g, "===")
    .replace(/-{10,}/g, "---")
    .replace(/\[SYSTEM[^\]]*\]/gi, "[FILTERED]")
    .replace(/\[INST[^\]]*\]/gi, "[FILTERED]")
    .replace(/<\|[^|]*\|>/g, "[FILTERED]");
}

export function boundOutput(
  raw: string,
  timedOut: boolean,
  timeoutS: number,
): { text: string; savedTo?: string } {
  const suffix = timedOut ? `\n\n[command timed out after ${timeoutS}s — partial output shown]` : "";
  const sanitized = sanitizeOutput(raw);

  // Binary content → hex preview, never raw bytes into context.
  if (isBinary(sanitized)) {
    const dir = scanDir();
    let savedTo: string | undefined;
    if (dir) {
      const outDir = join(dir, "raw-output");
      mkdirSync(outDir, { recursive: true });
      const name = `cmd-${Date.now().toString(36)}.bin`;
      writeFileSync(join(outDir, name), raw, "utf8");
      savedTo = join(outDir, name);
    }
    return {
      text: `[BINARY OUTPUT — ${raw.length} bytes${savedTo ? `, saved to ${savedTo}` : ""}]\n${hexPreview(raw)}${suffix}`,
      savedTo,
    };
  }

  // Minified JS/CSS → dense preview + save full.
  if (isMinified(sanitized) && sanitized.length > CONTEXT_OUTPUT_CAP) {
    const dir = scanDir();
    let savedTo: string | undefined;
    if (dir) {
      const outDir = join(dir, "raw-output");
      mkdirSync(outDir, { recursive: true });
      const name = `cmd-${Date.now().toString(36)}.min`;
      writeFileSync(join(outDir, name), raw, "utf8");
      savedTo = join(outDir, name);
    }
    const preview = sanitized.slice(0, 2048);
    return {
      text: `[MINIFIED CONTENT — ${raw.length} chars${savedTo ? `, saved to ${savedTo}` : ""}]\n${preview}\n[… use grep/read on the saved file for details …]${suffix}`,
      savedTo,
    };
  }

  if (sanitized.length <= CONTEXT_OUTPUT_CAP) {
    return { text: (sanitized || "(no output)") + suffix };
  }
  let savedTo: string | undefined;
  const dir = scanDir();
  if (dir) {
    const outDir = join(dir, "raw-output");
    mkdirSync(outDir, { recursive: true });
    const name = `cmd-${Date.now().toString(36)}.log`;
    writeFileSync(join(outDir, name), raw, "utf8");
    savedTo = join(outDir, name);
  }
  const head = sanitized.slice(0, 4 * 1024);
  const tail = sanitized.slice(-CONTEXT_OUTPUT_CAP + 4 * 1024);
  const omitted = sanitized.length - head.length - tail.length;
  const note = savedTo
    ? `full output saved to ${savedTo} — grep/read it for details`
    : "output too large to save";
  return {
    text: `${head}\n\n[… ${Math.round(omitted / 1024)}KB omitted — ${note} …]\n\n${tail}${suffix}`,
    savedTo,
  };
}

/** Detect missing-tool failures and append an install hint. */
const NOT_FOUND_RES = [
  /(?:^|\s)([A-Za-z0-9._-]+):\s*(?:command )?not found/im,
  /bash:\s*([A-Za-z0-9._-]+):\s*No such file or directory/i,
  /No module named ['"]?([A-Za-z0-9._-]+)['"]?/im,
  /ModuleNotFoundError:\s*No module named ['"]?([A-Za-z0-9._-]+)['"]?/im,
];

const INSTALL_HINTS: Record<string, string> = {
  nuclei: "should be preinstalled — check PATH or reinstall image",
  ffuf: "should be preinstalled — check PATH or reinstall image",
  subfinder: "should be preinstalled — check PATH or reinstall image",
  katana: "should be preinstalled — check PATH or reinstall image",
  naabu: "should be preinstalled — check PATH or reinstall image",
  semgrep: "pip3 install semgrep",
  trivy: "should be preinstalled — check PATH or reinstall image",
  gitleaks: "should be preinstalled — check PATH or reinstall image",
  trufflehog: "should be preinstalled — check PATH or reinstall image",
  nxc: "pip3 install netexec",
  netexec: "pip3 install netexec",
  impacket: "pip3 install impacket",
  jwt_tool: "pip3 install jwt_tool",
  dalfox: "should be preinstalled — check PATH or reinstall image",
  feroxbuster: "should be preinstalled — check PATH or reinstall image",
  rustscan: "should be preinstalled — check PATH or reinstall image",
  gau: "should be preinstalled — check PATH or reinstall image",
  waybackurls: "should be preinstalled — check PATH or reinstall image",
  paramspider: "python3 /opt/paramspider/paramspider.py",
  interactsh: "interactsh-client",
  sg: "ast-grep binary is `sg`",
  hurl: "should be preinstalled — check PATH or reinstall image",
  prowler: "pip3 install prowler",
  checkov: "pip3 install checkov",
  hashcat: "apt-get install -y hashcat",
  nikto: "apt-get install -y nikto",
  wpscan: "apt-get install -y wpscan || gem install wpscan",
  amass: "apt-get install -y amass || go install github.com/owasp-amass/amass/v4/...@latest",
  x8: "cargo install x8 || download from github.com/Sh1Yo/x8/releases",
};

function missingToolHint(output: string): string | null {
  for (const re of NOT_FOUND_RES) {
    const m = re.exec(output);
    if (!m?.[1]) continue;
    const name = m[1].replace(/^['"]|['"]$/g, "");
    const hint = INSTALL_HINTS[name] ?? `apt-get install -y ${name} || pip3 install ${name}`;
    return `\n\n[tool missing: ${name} — ${hint}]`;
  }
  return null;
}

export function strixBash(pi: ExtensionAPI) {
  const { highlightCode } = pi.pi as {
    highlightCode?: (code: string, lang?: string, theme?: unknown) => string[];
  };

  type BoxChars = {
    topLeft: string;
    topRight: string;
    bottomLeft: string;
    bottomRight: string;
    horizontal: string;
    vertical: string;
    teeRight: string;
    teeLeft: string;
  };
  type FullTheme = ThemeLike & {
    boxRound: BoxChars;
    sep: { dot: string };
    bold(s: string): string;
    styledSymbol?(key: string, color?: string): string;
  };

  /** `$ cmd` / `🐳 cmd` preview with bash syntax highlighting. */
  const commandLines = (cmd: string, sandboxed: boolean, theme: FullTheme): string[] => {
    // lang.docker resolves to 🐳 (unicode), the nerd-font whale, or "docker"
    // (ascii) depending on the active symbol preset.
    const icon = sandboxed ? (theme.styledSymbol?.("lang.docker", "accent") ?? "▣") : "$";
    const prefix = theme.fg("dim", `${icon} `);
    const highlighted = highlightCode?.(cmd, "bash", theme) ?? cmd.split("\n");
    return highlighted.map((l, i) => (i === 0 ? `${prefix}${l}` : `   ${l}`));
  };

  /** Status header line: `<icon> <title>` matching renderStatusLine's shape. */
  const statusHeader = (
    theme: FullTheme,
    opts: { icon?: string; title: string; meta?: string[] },
  ): string => {
    const title = theme.fg("accent", opts.title);
    let line = opts.icon ? `${opts.icon} ${title}` : title;
    const meta = (opts.meta ?? []).filter((m) => m.trim().length > 0);
    if (meta.length) line += ` ${theme.fg("dim", meta.join(theme.sep.dot))}`;
    return line;
  };

  /**
   * Bordered output card mirroring pi-tui's renderOutputBlock: rounded frame,
   * status-colored border, `╭─── Title ───╮` header bar, `├─── Output` section
   * divider, `╰───╯` footer. pi.pi doesn't re-export the real one, so this is a
   * faithful local replica.
   */
  const frameCard = (
    theme: FullTheme,
    opts: {
      width: number;
      header?: string;
      state?: "success" | "error" | "warning" | "running" | "pending";
      sections: { label?: string; lines: string[] }[];
      footer?: string;
    },
  ): string[] => {
    const b = theme.boxRound;
    const w = Math.max(0, opts.width);
    const borderColor =
      opts.state === "error"
        ? "error"
        : opts.state === "warning"
          ? "warning"
          : opts.state === "running" || opts.state === "pending"
            ? "accent"
            : "dim";
    const border = (s: string) => theme.fg(borderColor, s);
    const padL = " ";
    const padR = " ";
    const contentW = Math.max(1, w - 2 - 1 - 1); // borders + padding

    const bar = (left: string, right: string, label?: string): string => {
      const cap = b.horizontal.repeat(3);
      const leftG = `${left}${cap}`;
      if (!label) {
        const fill = Math.max(0, w - visWidth(leftG) - visWidth(right));
        return `${border(leftG)}${border(b.horizontal.repeat(fill))}${border(right)}`;
      }
      const raw = ` ${label} `;
      const maxLabel = Math.max(0, w - visWidth(leftG) - visWidth(right));
      const trimmed = truncateVis(raw, maxLabel);
      const fill = Math.max(0, w - visWidth(leftG) - visWidth(trimmed) - visWidth(right));
      return `${border(leftG)}${trimmed}${border(b.horizontal.repeat(fill))}${border(right)}`;
    };

    const rows: string[] = [bar(b.topLeft, b.topRight, opts.header)];
    opts.sections.forEach((sec, i) => {
      if (sec.label) rows.push(bar(b.teeRight, b.teeLeft, sec.label));
      else if (i > 0) rows.push(bar(b.teeRight, b.teeLeft));
      for (const line of sec.lines) {
        for (const wrapped of wrapVis(line.trimEnd(), contentW)) {
          rows.push(`${border(b.vertical)}${padL}${padVis(wrapped, contentW)}${padR}${border(b.vertical)}`);
        }
      }
    });
    if (opts.footer) {
      rows.push(bar(b.teeRight, b.teeLeft));
      for (const wrapped of wrapVis(opts.footer, contentW)) {
        rows.push(`${border(b.vertical)}${padL}${padVis(wrapped, contentW)}${padR}${border(b.vertical)}`);
      }
    }
    rows.push(bar(b.bottomLeft, b.bottomRight));
    return rows;
  };

  return {
    name: "bash",
    label: "Bash",
    description:
      "Execute a bash command. While strix mode is sandboxed the command runs inside the shared container (mounted at /workspace); otherwise it runs on the host.",
    // Result component replaces the call component in-place (native bash
    // behavior) — without this the finished card renders below the running
    // one, duplicating the command.
    mergeCallAndResult: true,
    parameters: {
      type: "object",
      properties: {
        command: { type: "string", description: "command to execute" },
        timeout: { type: "number", description: "timeout in seconds (default 300)" },
        cwd: { type: "string", description: "working directory" },
      },
      required: ["command"],
    },
    renderCall(args: Record<string, unknown>, opts: { spinnerFrame?: number }, theme: FullTheme) {
      const cmd = typeof args?.command === "string" ? args.command : "";
      const sandboxed = activeSandbox() !== null && !/^\s*docker\s/.test(cmd);
      const running = opts?.spinnerFrame !== undefined;
      const icon = running
        ? theme.styledSymbol?.("status.running", "accent")
        : theme.styledSymbol?.("status.pending", "muted");
      return {
        render: (width: number) =>
          frameCard(theme, {
            width,
            header: statusHeader(theme, { icon, title: "Bash" }),
            state: running ? "running" : "pending",
            sections: [{ lines: commandLines(cmd, sandboxed, theme) }],
          }),
      };
    },
    renderResult(
      result: { content?: { type: string; text?: string }[]; details?: Json; isError?: boolean },
      _opts: unknown,
      theme: FullTheme,
      args?: Record<string, unknown>,
    ) {
      const cmd = typeof args?.command === "string" ? args.command : "";
      const sandboxed = result.details?.sandboxed === true;
      const out = result.content?.find((c) => c.type === "text")?.text ?? "";
      const exitCode = typeof result.details?.exitCode === "number" ? result.details.exitCode : undefined;
      const ms = typeof result.details?.durationMs === "number" ? result.details.durationMs : undefined;
      const timedOut = result.details?.timedOut === true;
      const isError = result.isError === true;
      const state = timedOut ? "warning" : isError ? "error" : "success";
      const icon = isError
        ? theme.styledSymbol?.("status.error", "error")
        : timedOut
          ? theme.styledSymbol?.("status.warning", "warning")
          : theme.styledSymbol?.("tool.bash", "accent");
      const meta = [
        exitCode !== undefined ? `exit ${exitCode}` : undefined,
        ms !== undefined ? `${(ms / 1000).toFixed(1)}s` : undefined,
        timedOut ? "timed out" : undefined,
      ].filter((x): x is string => Boolean(x));
      return {
        render: (width: number) =>
          frameCard(theme, {
            width,
            header: statusHeader(theme, { icon, title: "Bash", meta }),
            state,
            sections: [
              { lines: commandLines(cmd, sandboxed, theme) },
              { label: "Output", lines: out.split("\n") },
            ],
          }),
      };
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
        // bash -lc: login shell so user-installed tools (~/.local/bin,
        // ~/go/bin, pipx) resolve — plain `sh -c` skips profile PATH.
        const inner = `umask 000; cd ${JSON.stringify(containerCwd(cwd, sb.workspaceRoot))} && ${command}`;
        const res = await run(["docker", "exec", "omp-strix-sandbox", "bash", "-lc", inner], {
          timeoutS,
          signal,
        });
        const bounded = boundOutput(res.output, res.timedOut, timeoutS);
        const hint = res.code !== 0 ? (missingToolHint(res.output) ?? "") : "";
        return {
          content: [{ type: "text", text: bounded.text + hint }],
          details: {
            exitCode: res.code,
            timedOut: res.timedOut,
            sandboxed: true,
            durationMs: Date.now() - started,
            ...(bounded.savedTo ? { savedTo: bounded.savedTo } : {}),
          },
        };
      }

      // Host path: no sandbox, or the agent deliberately issued a docker command.
      const res = await run(["bash", "-c", command], { cwd, timeoutS, signal });
      const bounded = boundOutput(res.output, res.timedOut, timeoutS);
      const hint = res.code !== 0 ? (missingToolHint(res.output) ?? "") : "";
      return {
        content: [{ type: "text", text: bounded.text + hint }],
        details: {
          exitCode: res.code,
          timedOut: res.timedOut,
          sandboxed: false,
          durationMs: Date.now() - started,
          ...(bounded.savedTo ? { savedTo: bounded.savedTo } : {}),
        },
      };
    },
  };
}
