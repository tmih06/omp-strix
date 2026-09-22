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
const WORKSPACE = "/workspace";
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

async function containerRunning(): Promise<boolean> {
  const res = await run(["inspect", "-f", "{{.State.Running}}", NAME]);
  return res.code === 0 && res.stdout.trim() === "true";
}

/**
 * Ensure the sandbox container exists and is running, with `cwd` mounted
 * at /workspace. Returns an error string on failure.
 */
export async function ensureSandbox(cwd: string): Promise<string | null> {
  if (await containerRunning()) return null;
  await run(["rm", "-f", NAME]); // stale container: recreate so mount matches cwd

  const image = sandboxImage();
  const inspect = await run(["image", "inspect", image]);
  if (inspect.code !== 0) {
    // Pull first — the default image is prebuilt on GHCR. Fall back to a
    // local build only when the pull fails AND a Dockerfile is present
    // (source checkout / offline dev).
    const pull = await run(["pull", image]);
    if (pull.code !== 0) {
      if (!existsSync(join(DOCKERFILE_DIR, "Dockerfile"))) {
        return `docker pull ${image} failed: ${pull.stderr.trim() || pull.stdout.trim()}`;
      }
      const build = await run(["build", "-t", image, DOCKERFILE_DIR]);
      if (build.code !== 0) {
        return `docker build ${image} failed: ${build.stderr.trim() || build.stdout.trim()}`;
      }
    }
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
 * Rewrite a bash tool call to run inside the sandbox container.
 * Returns the new input object, or null when the call shouldn't be rewritten.
 */
export function rewriteBashInput(input: Record<string, unknown>): Record<string, unknown> | null {
  const sb = activeSandbox();
  if (!sb) return null;

  const command = input.command;
  if (typeof command !== "string" || command.trim() === "") return null;
  // Already sandboxed (e.g. agent deliberately nesting docker calls).
  if (/^\s*docker\s/.test(command)) return null;

  // Map the requested cwd into the /workspace mount. Paths outside the
  // mounted root fall back to the mount root.
  const requested = typeof input.cwd === "string" ? input.cwd : sb.workspaceRoot;
  const inside = requested === sb.workspaceRoot || requested.startsWith(`${sb.workspaceRoot}/`);
  const innerCwd = inside ? join(WORKSPACE, requested.slice(sb.workspaceRoot.length)) : WORKSPACE;
  // The whole inner command (cd + user command) is base64'd, so no quoting
  // survives into the host shell — apostrophes/spaces in paths are inert.
  const inner = `cd ${JSON.stringify(innerCwd)} && ${command}`;
  const b64 = Buffer.from(inner, "utf8").toString("base64");
  // umask 000: the container runs as root, so files it writes into the
  // /workspace mount must be world-writable for the host user to touch them.
  const wrapped = `umask 000; eval "$(echo ${b64} | base64 -d)"`;
  // If the container is gone, recreate it before exec. This is a sync
  // rewrite so we can't await ensureSandbox; instead we prepend a
  // conditional start that is a no-op when the container is already up.
  // stdout is redirected too — `docker start` echoes the container name.
  const ensure = `docker start ${NAME} >/dev/null 2>&1 || docker run -d --name ${NAME} --cap-add NET_RAW --network host -e TMPDIR=${WORKSPACE}/.tmp -v "${sb.workspaceRoot}:${WORKSPACE}" -w ${WORKSPACE} ${sandboxImage()} sh -c 'umask 000; mkdir -p ${WORKSPACE}/.tmp; exec sleep infinity'`;
  const execArgs = ["docker", "exec", NAME, "sh", "-c", `'${wrapped}'`];

  const out: Record<string, unknown> = { ...input, command: `${ensure} && ${execArgs.join(" ")}` };
  delete out.cwd; // key must be absent, not undefined — schema rejects undefined
  return out;
}
