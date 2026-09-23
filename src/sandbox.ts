/**
 * Sandboxed execution for strix mode — replaces strix's dedicated sandbox
 * image with a locally built one (sandbox/Dockerfile, essential pentest
 * tools preinstalled). STRIX_SANDBOX_IMAGE overrides the image name; when
 * set to anything other than the default it is pulled instead of built.
 *
 * While a scan is active, `bash` tool calls are rewritten to `docker exec`
 * into the container. The session cwd is mounted at /workspace so file
 * tools and shell commands see the same tree — same model as strix's
 * shared container. STRIX_SANDBOX=off disables sandboxing entirely.
 */

import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const NAME = "omp-strix-sandbox";
export const WORKSPACE = "/workspace";
const DEFAULT_IMAGE = "ghcr.io/tmih06/omp-strix-sandbox:latest";
const STATE_DIR = join(homedir(), ".omp", "agent", "strix");
const ACTIVE_FILE = join(STATE_DIR, "active.json");
const DOCKERFILE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "sandbox");

export function sandboxImage(): string {
  return process.env.STRIX_SANDBOX_IMAGE?.trim() || DEFAULT_IMAGE;
}

function run(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  const { promise, resolve } = Promise.withResolvers<{
    code: number;
    stdout: string;
    stderr: string;
  }>();
  execFile("docker", args, { timeout: 900_000 }, (err, stdout, stderr) => {
    const code = err && typeof err.code === "number" ? err.code : err ? 1 : 0;
    resolve({ code, stdout: String(stdout), stderr: String(stderr) });
  });
  return promise;
}

export async function dockerAvailable(): Promise<boolean> {
  if (process.env.STRIX_SANDBOX === "off") return false;
  const res = await run(["version", "--format", "{{.Server.Version}}"]);
  return res.code === 0;
}

export async function containerRunning(): Promise<boolean> {
  const res = await run(["inspect", "-f", "{{.State.Running}}", NAME]);
  return res.code === 0 && res.stdout.trim() === "true";
}

/**
 * Ensure the sandbox container exists and is running, with `cwd` mounted
 * at /workspace. Returns an error string on failure.
 */
export async function ensureSandbox(cwd: string): Promise<string | null> {
  if (await containerRunning()) {
    // A surviving container may still mount a previous session's cwd —
    // verify the bind source matches before reusing it.
    const mounts = await run([
      "inspect",
      "-f",
      "{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}",
      NAME,
    ]);
    if (mounts.stdout.includes(`${cwd}:${WORKSPACE}`)) return null;
  }
  await run(["rm", "-f", NAME]); // stale or wrong-mount container: recreate

  const image = sandboxImage();
  // Always try to pull — when the local image is current this is a cheap
  // manifest check (~1s); when GHCR has a newer :latest it updates. If the
  // pull fails (offline, auth) fall back to whatever is already local, and
  // only when nothing is local AND a Dockerfile exists, build from source.
  const pull = await run(["pull", image]);
  if (pull.code !== 0) {
    const inspect = await run(["image", "inspect", image]);
    if (inspect.code !== 0) {
      if (!existsSync(join(DOCKERFILE_DIR, "Dockerfile"))) {
        return `docker pull ${image} failed: ${pull.stderr.trim() || pull.stdout.trim()}`;
      }
      const build = await run(["build", "-t", image, DOCKERFILE_DIR]);
      if (build.code !== 0) {
        return `docker build ${image} failed: ${build.stderr.trim() || build.stdout.trim()}`;
      }
    }
    // else: pull failed but a local image exists — use it (offline/stale ok).
  }

  const res = await run([
    "run",
    "-d",
    "--name",
    NAME,
    "--cap-add",
    "NET_RAW",
    "--network",
    "host",
    // Container runs as root; the exec wrapper sets umask 000 so files it
    // writes in /workspace are world-writable for the host user.
    // Container /tmp is invisible to the host — redirect it into the mount.
    "-e",
    `TMPDIR=${WORKSPACE}/.tmp`,
    "-v",
    `${cwd}:${WORKSPACE}`,
    "-w",
    WORKSPACE,
    image,
    "sh",
    "-c",
    "umask 000; mkdir -p /workspace/.tmp; exec sleep infinity",
  ]);
  if (res.code !== 0) {
    return `docker run failed: ${res.stderr.trim() || res.stdout.trim()}`;
  }
  return null;
}

export async function stopSandbox(): Promise<void> {
  await run(["rm", "-f", NAME]);
}

export function markSandboxActive(on: boolean): void {
  try {
    const active = JSON.parse(readFileSync(ACTIVE_FILE, "utf8")) as Record<string, unknown>;
    active.sandbox = on;
    mkdirSync(STATE_DIR, { recursive: true });
    writeFileSync(ACTIVE_FILE, JSON.stringify(active, null, 2));
  } catch {
    /* no active scan file yet */
  }
}

interface ActiveSandbox {
  workspaceRoot: string; // host path mounted at /workspace
}

export function activeSandbox(): ActiveSandbox | null {
  try {
    const active = JSON.parse(readFileSync(ACTIVE_FILE, "utf8")) as {
      sandbox?: boolean;
      workspaceRoot?: string;
    };
    if (!active.sandbox) return null;
    return { workspaceRoot: active.workspaceRoot ?? "" };
  } catch {
    return null;
  }
}

export function recordSandbox(workspaceRoot: string): void {
  try {
    const active = JSON.parse(readFileSync(ACTIVE_FILE, "utf8")) as Record<string, unknown>;
    active.sandbox = true;
    active.workspaceRoot = workspaceRoot;
    writeFileSync(ACTIVE_FILE, JSON.stringify(active, null, 2));
  } catch {
    /* no active scan file yet */
  }
}

/**
 * Rewrite a bash tool call that directly invokes `docker exec` on the
 * sandbox (subagents sometimes bypass the routing): inject umask so files
 * stay host-writable. Plain commands need no rewrite — the shadow bash
 * tool executes them inside the container itself. Returns the new input
 * object, or null when the call shouldn't be rewritten.
 */
export function rewriteBashInput(input: Record<string, unknown>): Record<string, unknown> | null {
  if (!activeSandbox()) return null;
  const command = input.command;
  if (typeof command !== "string" || command.trim() === "") return null;
  const directExec = command.match(/docker\s+exec\s+(?:-\S+\s+)*omp-strix-sandbox\s+sh\s+-c\s+'/);
  if (!directExec || command.includes("umask")) return null;
  const out: Record<string, unknown> = {
    ...input,
    command: command.replace(directExec[0], `${directExec[0]}umask 000; `),
  };
  delete out.cwd;
  return out;
}

/**
 * Rewrite a file-tool call's `path` arg so `/workspace/...` (the container
 * path agents see in the prompt) maps to the host-side mounted root.
 * Returns the new input object, or null when nothing needs rewriting.
 */
export function rewritePathInput(input: Record<string, unknown>): Record<string, unknown> | null {
  const sb = activeSandbox();
  if (!sb?.workspaceRoot) return null;
  const path = input.path;
  if (typeof path !== "string") return null;
  if (path === WORKSPACE || path.startsWith(`${WORKSPACE}/`)) {
    return { ...input, path: join(sb.workspaceRoot, path.slice(WORKSPACE.length)) };
  }
  return null;
}
