/**
 * Shared strix execution container. The scan target is mounted read-only;
 * only /scratch is writable. Startup and state recording fail closed.
 */

import { execFile, spawn } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const NAME = "omp-strix-sandbox";
export const WORKSPACE = "/workspace";
export const SCRATCH = "/scratch";
const DEFAULT_IMAGE = "ghcr.io/tmih06/omp-strix-sandbox:latest";
function hostUid(): number | null {
  return process.getuid?.() ?? null;
}
function hostIdentity(): string {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) {
    throw new Error("Docker sandbox requires a POSIX user identity");
  }
  return `${uid}:${gid}`;
}
/** All mounted host directories and scan artifacts live under the project.
 *  POSIX ownership/mode checks apply where the platform exposes them; on
 *  Windows (no getuid, no real chmod) only the directory check is possible —
 *  the container itself still enforces the isolation boundary. */
function privateDirectory(dir: string): string {
  if (!existsSync(dir)) mkdirSync(dir, { mode: 0o700 });
  const stat = lstatSync(dir);
  const uid = hostUid();
  if (!stat.isDirectory() || (uid !== null && (stat.uid !== uid || (stat.mode & 0o077) !== 0))) {
    throw new Error(`${dir} must be a private, owner-owned directory (mode 0700)`);
  }
  return dir;
}

export function localStateRoot(root: string): string {
  const dir = privateDirectory(join(realpathSync(root), ".strix"));
  const ignore = join(dir, ".gitignore");
  if (!existsSync(ignore)) writeFileSync(ignore, "*\n", { mode: 0o600, flag: "wx" });
  return dir;
}
const scratchDir = (root: string) => join(localStateRoot(root), "scratch");
const activeFile = (root: string) => join(localStateRoot(root), "sandbox.json");
function ensureScratchDir(root: string): string {
  return privateDirectory(scratchDir(root));
}
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
    // A surviving container may be user-created or from an older, unsafe
    // configuration. Never trust its name without inspecting its mounts.
    if (await containerIsolated(cwd)) {
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
  ensureScratchDir(cwd);
  const res = await run([
    "run",
    "-d",
    "--name",
    NAME,
    "--user",
    hostIdentity(),
    "--cap-drop",
    "ALL",
    "--cap-add",
    "NET_RAW",
    "--security-opt",
    "no-new-privileges",
    "--pids-limit",
    "512",
    "--network",
    "bridge",
    // Run as the host project owner so /scratch can stay private (0700);
    // the container has no root capabilities or host-network namespace.
    // /workspace is mounted READ-ONLY — the scan target's source must not be
    // modified. Writable scratch (clones, temp files, tool output) goes to
    // /scratch, a dedicated directory in the project at ./.strix/scratch.
    "-e",
    `TMPDIR=${SCRATCH}/tmp`,
    "-e",
    `HOME=${SCRATCH}`,
    "-v",
    `${cwd}:${WORKSPACE}:ro`,
    "-v",
    `${scratchDir(cwd)}:${SCRATCH}`,
    "-w",
    WORKSPACE,
    image,
    "sh",
    "-c",
    "umask 077; mkdir -p /scratch/tmp; exec sleep infinity",
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
// Image pulls happen in tool execute()/interactive command handlers, not
// short-lived tool_call hooks. A failure must never execute the call on host.

let desiredRoot: string | null = null;
let contextRoot: string | null = null;
/** Session cwd, including in independently initialized subagent runners. */
export function setSandboxContext(root: string): void {
  contextRoot = realpathSync(root);
}
let starting: Promise<string | null> | null = null;

/** Arm lazy sandbox startup with `root` mounted at /workspace. */
export function armSandbox(root: string): void {
  const canonical = realpathSync(root);
  contextRoot = canonical;
  if (desiredRoot !== canonical) starting = null;
  desiredRoot = canonical;
}

/** Disarm the requested root; a persisted sandboxed scan can still deny host execs. */
export function disarmSandbox(): void {
  desiredRoot = null;
  starting = null;
}

/** Host dir mounted at /workspace while armed, or null when sandboxing is off. */
export function sandboxRoot(): string | null {
  return desiredRoot;
}

/** Verify actual isolation settings, not a matching container name. */
async function containerIsolated(root: string): Promise<boolean> {
  const res = await run([
    "inspect",
    "-f",
    "{{json .Mounts}}|{{json .HostConfig}}|{{.State.Running}}|{{.Config.User}}",
    NAME,
  ]);
  if (res.code !== 0) return false;
  try {
    const [mountsJson, configJson, running, user] = res.stdout.trim().split("|");
    if (running !== "true" || user !== hostIdentity()) return false;
    const mounts: unknown = JSON.parse(mountsJson);
    const config: unknown = JSON.parse(configJson);
    if (!Array.isArray(mounts) || mounts.length !== 2 || !config || typeof config !== "object") return false;
    const hasMount = (source: string, destination: string, writable: boolean) =>
      mounts.some(
        (mount: unknown) =>
          !!mount &&
          typeof mount === "object" &&
          "Source" in mount &&
          mount.Source === source &&
          "Destination" in mount &&
          mount.Destination === destination &&
          "RW" in mount &&
          mount.RW === writable,
      );
    return (
      hasMount(root, WORKSPACE, false) &&
      hasMount(scratchDir(root), SCRATCH, true) &&
      "NetworkMode" in config &&
      config.NetworkMode === "bridge" &&
      "Privileged" in config &&
      config.Privileged === false &&
      "CapDrop" in config &&
      Array.isArray(config.CapDrop) &&
      config.CapDrop.length === 1 &&
      config.CapDrop[0] === "ALL" &&
      "CapAdd" in config &&
      Array.isArray(config.CapAdd) &&
      config.CapAdd.length === 1 &&
      config.CapAdd[0] === "CAP_NET_RAW" &&
      "SecurityOpt" in config &&
      Array.isArray(config.SecurityOpt) &&
      config.SecurityOpt.length === 1 &&
      config.SecurityOpt[0] === "no-new-privileges" &&
      "PidMode" in config &&
      config.PidMode !== "host" &&
      "IpcMode" in config &&
      config.IpcMode !== "host" &&
      "Devices" in config &&
      Array.isArray(config.Devices) &&
      config.Devices.length === 0
    );
  } catch {
    return false;
  }
}

/** Start and verify the sandbox; child runners read the parent's state. */
export function ensureSandboxRunning(onProgress?: (msg: string) => void): Promise<string | null> {
  const root = desiredRoot ?? activeSandbox()?.workspaceRoot;
  if (!root) return Promise.resolve(null);
  starting ??= (async () => {
    if (!(await dockerAvailable())) return "docker not available";
    const err = await ensureSandbox(root, onProgress);
    if (err) return err;
    recordSandbox(root);
    return null;
  })().catch((e) => `sandbox startup failed: ${String(e)}`);
  return starting.then(async (err) => {
    if (err) return err;
    if (desiredRoot && desiredRoot !== root) return "sandbox root changed";
    if (!(await containerIsolated(root))) {
      const restartErr = await ensureSandbox(root, onProgress);
      if (restartErr || !(await containerIsolated(root)))
        return restartErr ?? "container isolation check failed";
      recordSandbox(root);
    }
    return null;
  });
}

export function markSandboxActive(on: boolean): void {
  const root = desiredRoot ?? contextRoot ?? process.cwd();
  if (!on) {
    const state = join(root, ".strix");
    if (!existsSync(state)) return;
    // Verify the parent before removing the marker; never follow a symlink.
    rmSync(join(localStateRoot(root), "sandbox.json"), { force: true });
    return;
  }
  recordSandbox(root);
}

interface ActiveSandbox {
  workspaceRoot: string; // host path mounted at /workspace
}

export function activeSandbox(): ActiveSandbox | null {
  try {
    const root = desiredRoot ?? contextRoot ?? realpathSync(process.cwd());
    const file = join(root, ".strix", "sandbox.json");
    if (!lstatSync(file).isFile()) return null;
    localStateRoot(root);
    const active: unknown = JSON.parse(readFileSync(file, "utf8"));
    if (
      !active ||
      typeof active !== "object" ||
      !("sandbox" in active) ||
      active.sandbox !== true ||
      !("workspaceRoot" in active) ||
      active.workspaceRoot !== root
    )
      return null;
    return { workspaceRoot: root };
  } catch {
    return null;
  }
}

export function recordSandbox(workspaceRoot: string): void {
  const file = activeFile(workspaceRoot);
  localStateRoot(workspaceRoot);
  const tmp = `${file}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify({ sandbox: true, workspaceRoot }), { mode: 0o600 });
  renameSync(tmp, file);
}
