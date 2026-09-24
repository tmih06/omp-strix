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

import { execFile, spawn } from "node:child_process";
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

/** Repo digest of the local image ("ghcr.io/…@sha256:…"), or null. */
async function localImageDigest(image: string): Promise<string | null> {
  const res = await run(["image", "inspect", image, "-f", "{{range .RepoDigests}}{{.}} {{end}}"]);
  if (res.code !== 0) return null;
  const repo = image.split(":")[0];
  const hit = res.stdout.split(/\s+/).find((d) => d.startsWith(`${repo}@`));
  return hit?.split("@")[1] ?? null;
}

/** Digest of the remote manifest for `image` on GHCR, or null when unknown. */
async function remoteImageDigest(image: string): Promise<string | null> {
  const [repo, tag] = image.split(":");
  try {
    const tokRes = await fetch(`https://ghcr.io/token?scope=repository:${repo}:pull`);
    const { token } = (await tokRes.json()) as { token?: string };
    if (!token) return null;
    const res = await fetch(`https://ghcr.io/v2/${repo}/manifests/${tag ?? "latest"}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept:
          "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json",
      },
    });
    if (!res.ok) return null;
    return res.headers.get("docker-content-digest");
  } catch {
    return null; // offline / registry hiccup — treat as "no update info"
  }
}

/**
 * Format a compact ASCII progress bar: `[████░░░░░░] 42%`.
 */
export function renderProgressBar(pct: number, width = 10): string {
  const clamped = Math.min(100, Math.max(0, Math.round(pct)));
  const filled = Math.min(width, Math.max(0, Math.round((clamped / 100) * width)));
  return `[${"█".repeat(filled)}${"░".repeat(width - filled)}] ${clamped}%`;
}

/**
 * Pull an image with streaming line-by-line progress reporting.
 * Layer download + extract milestones yield a 0–100% progress bar.
 */
export function pullImage(
  image: string,
  onProgress?: (msg: string) => void,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const { promise, resolve } = Promise.withResolvers<{
    code: number;
    stdout: string;
    stderr: string;
  }>();
  onProgress?.("pulling image…");
  const child = spawn("docker", ["pull", image], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let remainder = "";
  const layerScores = new Map<string, number>();

  const parseLines = (text: string) => {
    remainder += text;
    const lines = remainder.split(/\r?\n/);
    remainder = lines.pop() ?? "";
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.includes("Image is up to date")) {
        onProgress?.("image up to date");
        continue;
      }
      if (trimmed.includes("Downloaded newer image")) {
        onProgress?.(`pull complete ${renderProgressBar(100)}`);
        continue;
      }
      const m = trimmed.match(/^([a-f0-9]{8,12}):\s*(.*)$/i);
      if (m) {
        const [, id, action] = m;
        let score = 0;
        if (action.includes("Already exists") || action.includes("Pull complete")) score = 2;
        else if (action.includes("Download complete")) score = 1;
        layerScores.set(id, Math.max(layerScores.get(id) ?? 0, score));
        const totalPoints = layerScores.size * 2;
        const currentPoints = [...layerScores.values()].reduce((a, b) => a + b, 0);
        if (totalPoints > 0) {
          const pct = Math.round((currentPoints / totalPoints) * 100);
          onProgress?.(`pulling ${renderProgressBar(pct)}`);
        }
      }
    }
  };

  child.stdout.on("data", (chunk: Buffer) => {
    const text = chunk.toString("utf8");
    stdout += text;
    parseLines(text);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });
  child.on("close", (code) => {
    if (remainder) parseLines("\n");
    resolve({ code: code ?? 1, stdout, stderr });
  });
  child.on("error", (err) => {
    resolve({ code: 1, stdout, stderr: err.message });
  });
  return promise;
}

/**
 * Build an image from a local context dir with step-by-step progress reporting.
 */
export function buildImage(
  image: string,
  contextDir: string,
  onProgress?: (msg: string) => void,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const { promise, resolve } = Promise.withResolvers<{
    code: number;
    stdout: string;
    stderr: string;
  }>();
  onProgress?.("building image from Dockerfile…");
  const child = spawn("docker", ["build", "-t", image, contextDir], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let remainder = "";

  const parseLines = (text: string) => {
    remainder += text;
    const lines = remainder.split(/\r?\n/);
    remainder = lines.pop() ?? "";
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const stepMatch = trimmed.match(/Step\s+(\d+)\/(\d+)/i) ?? trimmed.match(/\[\s*(\d+)\/(\d+)\s*\]/);
      if (stepMatch) {
        const step = Number(stepMatch[1]);
        const total = Number(stepMatch[2]);
        if (total > 0) {
          const pct = Math.round((step / total) * 100);
          onProgress?.(`building ${renderProgressBar(pct)} (${step}/${total})`);
        }
      }
    }
  };

  child.stdout.on("data", (chunk: Buffer) => {
    const text = chunk.toString("utf8");
    stdout += text;
    parseLines(text);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });
  child.on("close", (code) => {
    if (remainder) parseLines("\n");
    resolve({ code: code ?? 1, stdout, stderr });
  });
  child.on("error", (err) => {
    resolve({ code: 1, stdout, stderr: err.message });
  });
  return promise;
}

/**
 * Ensure the sandbox container exists and is running, with `cwd` mounted
 * at /workspace. Returns an error string on failure.
 */
export async function ensureSandbox(cwd: string, onProgress?: (msg: string) => void): Promise<string | null> {
  const image = sandboxImage();
  if (await containerRunning()) {
    // A surviving container may still mount a previous session's cwd —
    // verify the bind source matches before reusing it.
    const mounts = await run([
      "inspect",
      "-f",
      "{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}",
      NAME,
    ]);
    if (mounts.stdout.includes(`${cwd}:${WORKSPACE}`)) {
      // Container is up — but check whether GHCR has a newer :latest.
      // Cheap digest compare (~1s); only pull when it actually differs.
      onProgress?.("checking for image updates…");
      const [local, remote] = await Promise.all([localImageDigest(image), remoteImageDigest(image)]);
      if (!remote || remote === local) {
        onProgress?.(remote ? "image up to date" : "container ready");
        return null;
      }
      onProgress?.("image update available — pulling…");
      const pull = await pullImage(image, onProgress);
      if (pull.code !== 0) {
        // Pull failed (offline/auth) — keep the running container.
        onProgress?.("update pull failed; keeping current container");
        return null;
      }
      onProgress?.("recreating container on updated image…");
      await run(["rm", "-f", NAME]);
      // fall through to container creation below
    } else {
      await run(["rm", "-f", NAME]); // stale or wrong-mount container: recreate
    }
  } else {
    await run(["rm", "-f", NAME]); // stale or wrong-mount container: recreate
  }

  // Always try to pull — when the local image is current this is a cheap
  // manifest check (~1s); when GHCR has a newer :latest it updates. If the
  // pull fails (offline, auth) fall back to whatever is already local, and
  // only when nothing is local AND a Dockerfile exists, build from source.
  const pull = await pullImage(image, onProgress);
  if (pull.code !== 0) {
    const inspect = await run(["image", "inspect", image]);
    if (inspect.code !== 0) {
      if (!existsSync(join(DOCKERFILE_DIR, "Dockerfile"))) {
        return `docker pull ${image} failed: ${pull.stderr.trim() || pull.stdout.trim()}`;
      }
      onProgress?.("pull failed; building image from Dockerfile…");
      const build = await buildImage(image, DOCKERFILE_DIR, onProgress);
      if (build.code !== 0) {
        return `docker build ${image} failed: ${build.stderr.trim() || build.stdout.trim()}`;
      }
    }
    // else: pull failed but a local image exists — use it (offline/stale ok).
  }

  onProgress?.("starting container…");
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
  onProgress?.("container ready");
  return null;
}

export async function stopSandbox(): Promise<void> {
  await run(["rm", "-f", NAME]);
}

// ── Lazy startup orchestration ────────────────────────────────────────────
// Event handlers (tool_call) are killed after ~30s — a first-run image pull
// exceeds that, and a timed-out handler drops its result so the call falls
// through to HOST execution. Startup therefore lives in tool execute()
// paths (bounded by the tool timeout): armSandbox() records intent at
// activation, ensureSandboxRunning() does the work on first exec.

let desiredRoot: string | null = null;
let starting: Promise<string | null> | null = null;

/** Arm lazy sandbox startup with `root` mounted at /workspace. */
export function armSandbox(root: string): void {
  if (desiredRoot !== root) starting = null;
  desiredRoot = root;
}

/** Disarm: subsequent execs run on the host; an in-flight start is orphaned. */
export function disarmSandbox(): void {
  desiredRoot = null;
  starting = null;
}

/** Host dir mounted at /workspace while armed, or null when sandboxing is off. */
export function sandboxRoot(): string | null {
  return desiredRoot;
}

/**
 * Ensure the armed sandbox is running. Returns null on success or when
 * disarmed, an error string on failure (callers fall back to host exec).
 * Memoized: concurrent callers share one pull/run, and a container that
 * died mid-scan is recreated. Call from tool execute() — never a handler.
 */
export function ensureSandboxRunning(onProgress?: (msg: string) => void): Promise<string | null> {
  const root = desiredRoot;
  if (!root) return Promise.resolve(null);
  starting ??= (async () => {
    if (!(await dockerAvailable())) return "docker not available";
    const err = await ensureSandbox(root, onProgress);
    if (!err) {
      recordSandbox(root);
      markSandboxActive(true);
    }
    return err;
  })();
  return starting.then(async (err) => {
    if (err) return err;
    if (desiredRoot !== root) {
      await stopSandbox(); // disarmed mid-start — clean up orphaned container
      return null;
    }
    // The container can die mid-scan (OOM, manual rm, a subagent's own
    // docker call). Recreate it so execs never hit a dead name.
    if (!(await containerRunning())) {
      const restartErr = await ensureSandbox(root, onProgress);
      if (restartErr) return restartErr;
      recordSandbox(root);
      markSandboxActive(true);
    }
    return null;
  });
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
  if (!sandboxRoot()) return null;
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
  const root = sandboxRoot();
  if (!root) return null;
  const path = input.path;
  if (typeof path !== "string") return null;
  if (path === WORKSPACE || path.startsWith(`${WORKSPACE}/`)) {
    return { ...input, path: join(root, path.slice(WORKSPACE.length)) };
  }
  return null;
}
