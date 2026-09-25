import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";
import { runSandboxed, spawnSandboxed } from "../src/bash-tool";
import registerStrix from "../src/index";
import { activeSandbox, markSandboxActive, setSandboxContext } from "../src/sandbox";
import {
  activeScan,
  addNote,
  beginScan,
  deleteFile,
  endScan,
  getProjectDir,
  scanDir,
  setProjectDir,
} from "../src/state";
import { STRIX_TOOLS } from "../src/tools";

function strixTool(name: string) {
  const tool = STRIX_TOOLS.find((t) => t.name === name);
  if (!tool) throw new Error(`missing strix tool ${name}`);
  return tool;
}

async function runTool(name: string, params: Record<string, unknown>) {
  const res = await strixTool(name).execute("t", params, undefined, undefined, undefined);
  return JSON.parse(res.content[0]!.text) as { success: boolean; error?: string };
}

const originalProject = getProjectDir();
const dirs: string[] = [];
function tmp(): string {
  const dir = mkdtempSync(join(tmpdir(), "strix-boundary-"));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  setProjectDir(originalProject);
  setSandboxContext(originalProject);
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("project-local scan state boundary", () => {
  test("inactive lookups do not create state in an untouched project", () => {
    const project = tmp();
    setProjectDir(project);
    setSandboxContext(project);

    expect(activeScan()).toBeNull();
    expect(activeSandbox()).toBeNull();
    markSandboxActive(false);
    expect(existsSync(join(project, ".strix"))).toBe(false);
  });

  test("a symlinked .strix root cannot redirect state writes outside the project", () => {
    const project = tmp();
    const outside = tmp();
    symlinkSync(outside, join(project, ".strix"), "dir");
    setProjectDir(project);

    expect(() => beginScan("example.org", "standard", true)).toThrow();
    expect(readdirSync(outside)).toEqual([]);
  });

  test("a symlinked .strix root cannot supply forged scans or rename outside files", () => {
    const project = tmp();
    const outside = tmp();
    const file = join(outside, "active.json");
    writeFileSync(
      file,
      JSON.stringify({
        scanId: "scan-valid-abcdef",
        dir: join(project, ".strix", "scans", "scan-valid-abcdef"),
        target: "example.org",
        scanMode: "standard",
        sandboxed: true,
        startedAt: "2026-01-01T00:00:00Z",
      }),
    );
    symlinkSync(outside, join(project, ".strix"), "dir");
    setProjectDir(project);

    expect(activeScan()).toBeNull();
    expect(() => endScan()).toThrow();
    expect(existsSync(file)).toBe(true);
  });

  test("a forged active scan cannot write its end marker outside scans", () => {
    const project = tmp();
    const outside = tmp();
    setProjectDir(project);
    const scan = beginScan("example.org", "standard", true);
    writeFileSync(join(project, ".strix", "active.json"), JSON.stringify({ ...scan, dir: outside }));

    expect(activeScan()).toBeNull();
    expect(scanDir()).toBeNull();
    endScan();
    expect(existsSync(join(outside, "ended.json"))).toBe(false);
  });

  test("a symlinked scan bucket cannot receive notes or delete files outside the scan", () => {
    const project = tmp();
    const outside = tmp();
    setProjectDir(project);
    const scan = beginScan("example.org", "standard", true);
    writeFileSync(join(outside, "note-0001.json"), "keep");
    symlinkSync(outside, join(scan.dir, "notes"), "dir");

    expect(() =>
      addNote(scan.dir, { title: "proof", content: "proof", category: "general", tags: [], agent: "a" }),
    ).toThrow();
    deleteFile(scan.dir, "notes", "note-0001");
    expect(readFileSync(join(outside, "note-0001.json"), "utf8")).toBe("keep");
  });
  test("a forged or missing marker cannot turn a sandboxed scan into host execution", async () => {
    const project = tmp();
    const outside = tmp();
    setProjectDir(project);
    setSandboxContext(project);
    beginScan("example.org", "standard", true);
    writeFileSync(
      join(project, ".strix", "sandbox.json"),
      JSON.stringify({ sandbox: true, workspaceRoot: outside }),
    );
    expect(activeSandbox()).toBeNull();

    const escaped = join(outside, "escaped");
    await expect(runSandboxed(["bash", "-c", `touch ${escaped}`], { timeoutS: 2 })).rejects.toThrow(
      "sandbox unavailable",
    );
    await expect(spawnSandboxed(`touch ${escaped}`, {})).rejects.toThrow("sandbox unavailable");
    expect(existsSync(escaped)).toBe(false);
  });

  test("strix script tools fail closed without a sandbox — no host execution", async () => {
    const project = tmp();
    const outside = tmp();
    setProjectDir(project);
    setSandboxContext(project);
    beginScan("example.org", "standard", true);
    // Sandboxed scan with no marker and no armed root: every script entry
    // point must refuse instead of running argv on the host.
    const escaped = join(outside, "escaped");
    await expect(runSandboxed(["touch", escaped], { timeoutS: 2 })).rejects.toThrow("sandbox unavailable");
    await expect(spawnSandboxed(`touch ${escaped}`, {})).rejects.toThrow("sandbox unavailable");

    const py = await runTool("python", { code: `open('${escaped}','w').write('x')` });
    expect(py.success).toBe(false);
    expect(py.error).toContain("sandbox unavailable");
    const term = await runTool("terminal", { action: "spawn", command: `touch ${escaped}` });
    expect(term.success).toBe(false);
    expect(term.error).toContain("sandbox unavailable");
    const sc = await runTool("scan", { mode: "nmap", target: "127.0.0.1" });
    expect(sc.success).toBe(false);
    expect(sc.error).toContain("sandbox unavailable");
    expect(existsSync(escaped)).toBe(false);
  });

  test("strix HTTP tools fail closed without a sandbox — no host network", async () => {
    const project = tmp();
    setProjectDir(project);
    setSandboxContext(project);
    beginScan("example.org", "standard", true);
    let hits = 0;
    const server = createServer((_req, res) => {
      hits++;
      res.end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("missing HTTP listen port");
      const url = `http://127.0.0.1:${address.port}/?q=1`;
      // verify_* and diff_probe have no SSRF pre-check: if any of them used
      // the host network the local server would record a hit.
      for (const name of [
        "verify_sqli",
        "verify_ssti",
        "verify_path_traversal",
        "verify_timing",
        "diff_probe",
      ]) {
        const res = await runTool(name, { url, param: "q", payload: "x" });
        expect(res.success).toBe(false);
        expect(res.error).toContain("sandbox unavailable");
      }
      // fetch_url SSRF-guards loopback before the sandbox path; a public URL
      // fails the same way without ever opening a socket.
      const res = await runTool("fetch_url", { url: "https://example.com/" });
      expect(res.success).toBe(false);
      expect(res.error).toContain("sandbox unavailable");
      expect(hits).toBe(0);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test("login_and_save_session is unsupported — never a host browser", async () => {
    const project = tmp();
    setProjectDir(project);
    setSandboxContext(project);
    beginScan("example.org", "standard", true);
    const res = await runTool("login_and_save_session", {
      url: "https://example.com/login",
      username: "u",
      password: "p",
    });
    expect(res.success).toBe(false);
    expect(res.error).toContain("refusing host execution");
  });
});

describe("sandbox tool dispatch", () => {
  function sandboxGuard() {
    const project = tmp();
    setProjectDir(project);
    setSandboxContext(project);
    // Independent subagent runner: /strix was never activated locally.
    beginScan("example.org", "standard", true);
    let guard: ((event: ToolCallEvent, ctx: ExtensionContext) => unknown) | undefined;
    registerStrix({
      pi: {},
      registerTool() {},
      registerCommand() {},
      on(name: string, handler: typeof guard) {
        if (name === "tool_call") guard = handler;
      },
    } as unknown as ExtensionAPI);
    if (!guard) throw new Error("missing tool_call guard");
    const hook = guard;
    return (toolName: string, input: Record<string, unknown> = {}) =>
      hook({ type: "tool_call", toolName, input }, { cwd: project } as ExtensionContext);
  }

  test("subagents can submit structured results and manage session context", () => {
    const dispatch = sandboxGuard();
    expect(dispatch("yield", { data: { verdict: "CONFIRMED", evidence: "proof" } })).toBeUndefined();
    expect(dispatch("yield", { error: "Target unavailable" })).toBeUndefined();
    expect(dispatch("context_notes", { text: "Continue validating candidate A" })).toBeUndefined();
    expect(dispatch("context_notes")).toBeUndefined();
    expect(dispatch("new_context")).toBeUndefined();
  });

  test("scan tools and reviewed orchestration remain available", () => {
    const dispatch = sandboxGuard();
    for (const tool of STRIX_TOOLS) {
      expect(dispatch(tool.name)).toBeUndefined();
    }
    for (const name of ["wait", "todo", "ask"]) {
      expect(dispatch(name)).toBeUndefined();
    }
    expect(dispatch("bash", { command: "pwd" })).toBeUndefined();
    for (const agent of [
      "strix-recon",
      "strix-hunter",
      "strix-validator",
      "strix-reporter",
      "strix-privesc",
      "strix-pivot",
    ]) {
      expect(dispatch("task", { tasks: [{ agent, task: "Inspect target" }] })).toBeUndefined();
    }
  });

  test("host access and unreviewed tools remain denied", () => {
    const dispatch = sandboxGuard();
    for (const name of [
      "read",
      "write",
      "edit",
      "grep",
      "glob",
      "find",
      "eval",
      "browser",
      "debug",
      "lsp",
      "web_search",
      "ast_grep",
      "ast_edit",
      "github",
      "checkpoint",
      "rewind",
      "unknown_plugin_tool",
    ]) {
      expect(dispatch(name)).toMatchObject({ block: true });
    }
    for (const tasks of [
      [],
      [{ task: "Generic child" }],
      [{ agent: "scout" }],
      [{ agent: "strix-recon", tools: ["eval"] }],
      [{ agent: "strix-recon" }, { agent: "custom" }],
    ]) {
      expect(dispatch("task", { tasks })).toMatchObject({ block: true });
    }
    expect(dispatch("bash", { command: "dd if=/dev/zero of=/dev/sda" })).toMatchObject({
      block: true,
    });
  });
});
