/**
 * Scan-state store for strix mode.
 *
 * Layout (mirrors strix's per-scan shared state, file-backed so every agent
 * session in the process sees the same data regardless of module instance):
 *
 *   <agentDir>/strix/
 *     active.json                      -> { scanId, dir, target, scanMode, startedAt }
 *     scans/<scanId>/
 *       notes/<id>.json                -> one file per note (append-only, no RMW races)
 *       coverage/<id>.json             -> one file per coverage entry
 *       threat-models/<slug>.json      -> { target, model, amendments[] }
 *       reports/vuln-NNNN.json         -> one file per filed report (+ .md sibling)
 *       final-report.json              -> finish_scan payload (+ final-report.md)
 */

import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { type FinalReportPayload, renderFinalReportMarkdown, renderReportMarkdown } from "./report";

export interface ActiveScan {
  scanId: string;
  dir: string;
  target: string;
  scanMode: string;
  startedAt: string;
}

const STRIX_ROOT = join(homedir(), ".omp", "agent", "strix");
const ACTIVE_FILE = join(STRIX_ROOT, "active.json");
const SCANS_DIR = join(STRIX_ROOT, "scans");

function atomicWrite(path: string, data: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  writeFileSync(tmp, data, "utf8");
  renameSync(tmp, path);
}

function readJson<T>(path: string): T | null {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return null;
  }
}

function listJson<T>(dir: string): T[] {
  if (!existsSync(dir)) return [];
  const out: T[] = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    const parsed = readJson<T>(join(dir, name));
    if (parsed !== null) out.push(parsed);
  }
  return out;
}

export function beginScan(target: string, scanMode: string): ActiveScan {
  const scanId = `scan-${Date.now().toString(36)}-${randomBytes(3).toString("hex")}`;
  const dir = join(SCANS_DIR, scanId);
  const scan: ActiveScan = {
    scanId,
    dir,
    target,
    scanMode,
    startedAt: new Date().toISOString(),
  };
  for (const sub of ["notes", "coverage", "threat-models", "reports"]) {
    mkdirSync(join(dir, sub), { recursive: true });
  }
  atomicWrite(ACTIVE_FILE, JSON.stringify(scan, null, 2));
  return scan;
}

export function endScan(): void {
  try {
    if (existsSync(ACTIVE_FILE)) {
      const scan = readJson<ActiveScan>(ACTIVE_FILE);
      if (scan) {
        atomicWrite(join(scan.dir, "ended.json"), JSON.stringify({ endedAt: new Date().toISOString() }));
      }
    }
  } finally {
    try {
      renameSync(ACTIVE_FILE, `${ACTIVE_FILE}.last`);
    } catch {
      /* already gone */
    }
  }
}

/** Resolve the scan dir for a tool call. Falls back to the last active scan. */
export function scanDir(): string | null {
  const active = readJson<ActiveScan>(ACTIVE_FILE);
  if (active?.dir) return active.dir;
  const last = readJson<ActiveScan>(`${ACTIVE_FILE}.last`);
  return last?.dir ?? null;
}

export function activeScan(): ActiveScan | null {
  return readJson<ActiveScan>(ACTIVE_FILE);
}

/**
 * Resume an interrupted scan: returns the live ActiveScan when active.json
 * exists and its scan dir has no ended.json marker (i.e. the previous
 * session died before finish_scan/deactivate ran).
 */
export function resumableScan(): ActiveScan | null {
  const scan = readJson<ActiveScan>(ACTIVE_FILE);
  if (!scan?.dir) return null;
  try {
    if (existsSync(join(scan.dir, "ended.json"))) return null;
  } catch {
    return null;
  }
  return scan;
}

// ---- scan metrics (subagent usage) -----------------------------------------

export interface UsageTotals {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  totalTokens: number;
  /** input+output+cacheWrite — excludes cacheRead, matching the agent hub's
   *  per-message accounting (cacheRead re-reads full context each turn). */
  effectiveTokens: number;
  costTotal: number;
}

export interface ScanMetrics {
  /** Aggregated usage across subagent session transcripts. */
  subagentUsage: UsageTotals;
  subagentRuns: number;
  subagentDurationMs: number;
}

const emptyUsage = (): UsageTotals => ({
  input: 0,
  output: 0,
  cacheRead: 0,
  cacheWrite: 0,
  totalTokens: 0,
  effectiveTokens: 0,
  costTotal: 0,
});

/**
 * Sum token usage across subagent session transcripts. `task` tool results
 * fire at spawn time with no usage; completions arrive as steers without
 * usage either — the only durable record is each subagent session's own
 * jsonl, which lives in a subdirectory named after the parent session file.
 */
export function collectSubagentMetrics(sessionFile: string | undefined): ScanMetrics {
  const metrics: ScanMetrics = { subagentUsage: emptyUsage(), subagentRuns: 0, subagentDurationMs: 0 };
  if (!sessionFile) return metrics;
  const dir = sessionFile.replace(/\.jsonl$/, "");
  let files: string[];
  try {
    files = readdirSync(dir)
      .filter((f) => f.endsWith(".jsonl"))
      .map((f) => join(dir, f));
  } catch {
    return metrics;
  }
  for (const file of files) {
    metrics.subagentRuns += 1;
    let first: number | null = null;
    let last: number | null = null;
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n")) {
      if (!line) continue;
      let e: { timestamp?: string; message?: { role?: string; usage?: Record<string, unknown> } };
      try {
        e = JSON.parse(line);
      } catch {
        continue;
      }
      const ts = e.timestamp ? Date.parse(e.timestamp) : Number.NaN;
      if (!Number.isNaN(ts)) {
        if (first === null || ts < first) first = ts;
        if (last === null || ts > last) last = ts;
      }
      const u = e.message?.role === "assistant" ? e.message.usage : undefined;
      if (u && typeof u === "object") {
        const num = (k: string) => (typeof u[k] === "number" ? (u[k] as number) : 0);
        metrics.subagentUsage.input += num("input");
        metrics.subagentUsage.output += num("output");
        metrics.subagentUsage.cacheRead += num("cacheRead");
        metrics.subagentUsage.cacheWrite += num("cacheWrite");
        metrics.subagentUsage.totalTokens += num("totalTokens");
        metrics.subagentUsage.effectiveTokens += num("input") + num("output") + num("cacheWrite");
        const cost = u.cost as Record<string, unknown> | undefined;
        if (cost && typeof cost.total === "number") metrics.subagentUsage.costTotal += cost.total;
      }
    }
    if (first !== null && last !== null) metrics.subagentDurationMs += last - first;
  }
  return metrics;
}

function newId(prefix: string): string {
  return `${prefix}-${randomBytes(4).toString("hex")}`;
}

function writeEntry(dir: string, prefix: string, value: { id: string }): string {
  const id = newId(prefix);
  value.id = id; // assign BEFORE serialize — the file must carry its own id
  atomicWrite(join(dir, `${id}.json`), JSON.stringify(value, null, 2));
  return id;
}

// ---- notes ---------------------------------------------------------------

export interface Note {
  id: string;
  title: string;
  content: string;
  category: string;
  tags: string[];
  agent: string;
  createdAt: string;
  updatedAt: string;
}

export function addNote(dir: string, note: Omit<Note, "id" | "createdAt" | "updatedAt">): Note {
  const now = new Date().toISOString();
  const full: Note = { ...note, id: "", createdAt: now, updatedAt: now };
  writeEntry(join(dir, "notes"), "note", full);
  return full;
}

export function listNotes(dir: string): Note[] {
  return listJson<Note>(join(dir, "notes")).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

export function getNote(dir: string, id: string): Note | null {
  return readJson<Note>(join(dir, "notes", `${id}.json`));
}

export function putNote(dir: string, note: Note): void {
  atomicWrite(join(dir, "notes", `${note.id}.json`), JSON.stringify(note, null, 2));
}

// ---- coverage --------------------------------------------------------------

export interface CoverageEntry {
  id: string;
  surface: string;
  riskArea: string;
  outcome: string;
  evidence: string;
  agent: string;
  createdAt: string;
  updatedAt: string;
  history: { outcome: string; evidence: string; at: string; agent: string }[];
}

export function findCoverage(dir: string, surface: string, riskArea: string): CoverageEntry | null {
  const s = surface.trim().toLowerCase();
  const r = riskArea.trim().toLowerCase();
  for (const entry of listJson<CoverageEntry>(join(dir, "coverage"))) {
    if (entry.surface.trim().toLowerCase() === s && entry.riskArea.trim().toLowerCase() === r) {
      return entry;
    }
  }
  return null;
}

export function addCoverage(
  dir: string,
  entry: Omit<CoverageEntry, "id" | "createdAt" | "updatedAt" | "history">,
): CoverageEntry {
  const now = new Date().toISOString();
  const full: CoverageEntry = { ...entry, id: "", createdAt: now, updatedAt: now, history: [] };
  writeEntry(join(dir, "coverage"), "cov", full);
  return full;
}

export function putCoverage(dir: string, entry: CoverageEntry): void {
  atomicWrite(join(dir, "coverage", `${entry.id}.json`), JSON.stringify(entry, null, 2));
}

export function listCoverage(dir: string): CoverageEntry[] {
  return listJson<CoverageEntry>(join(dir, "coverage")).sort((a, b) =>
    a.createdAt.localeCompare(b.createdAt),
  );
}
export function deleteFile(dir: string, bucket: string, id: string): void {
  try {
    rmSync(join(dir, bucket, `${id}.json`));
  } catch {
    /* already gone */
  }
}

// ---- threat model ----------------------------------------------------------

export interface ThreatModel {
  target: string;
  model: string;
  agent: string;
  updatedAt: string;
  amendments: { agent: string; at: string; text: string }[];
}

export function threatSlug(target: string): string {
  const slug = target
    .trim()
    .toLowerCase()
    .replace(/^[a-z]+:\/\//, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return slug || "target";
}

export function getThreatModel(dir: string, target: string): ThreatModel | null {
  return readJson<ThreatModel>(join(dir, "threat-models", `${threatSlug(target)}.json`));
}

export function listThreatModels(dir: string): ThreatModel[] {
  return listJson<ThreatModel>(join(dir, "threat-models"));
}

export function putThreatModel(dir: string, model: ThreatModel): void {
  atomicWrite(join(dir, "threat-models", `${threatSlug(model.target)}.json`), JSON.stringify(model, null, 2));
}

// ---- reports ---------------------------------------------------------------

export interface Report {
  id: string;
  findingClass: "dynamic" | "dependency_cve";
  agent: string;
  createdAt: string;
  updatedAt: string;
  revisions: { at: string; agent: string; reason: string; fields: string[] }[];
  [key: string]: unknown;
}

export function nextReportId(dir: string, prefix: string): string {
  const reportsDir = join(dir, "reports");
  let max = 0;
  if (existsSync(reportsDir)) {
    for (const name of readdirSync(reportsDir)) {
      const m = name.match(new RegExp(`^${prefix}-(\\d+)\\.json$`));
      if (m) max = Math.max(max, Number.parseInt(m[1], 10));
    }
  }
  return `${prefix}-${String(max + 1).padStart(4, "0")}`;
}

export function addReport(dir: string, prefix: string, report: Omit<Report, "id">): Report {
  const id = nextReportId(dir, prefix);
  const full = { ...report, id } as Report;
  atomicWrite(join(dir, "reports", `${id}.json`), JSON.stringify(full, null, 2));
  atomicWrite(join(dir, "reports", `${id}.md`), renderReportMarkdown(full));
  return full;
}

export function getReport(dir: string, id: string): Report | null {
  return readJson<Report>(join(dir, "reports", `${id}.json`));
}

export function putReport(dir: string, report: Report): void {
  atomicWrite(join(dir, "reports", `${report.id}.json`), JSON.stringify(report, null, 2));
  atomicWrite(join(dir, "reports", `${report.id}.md`), renderReportMarkdown(report));
}

export function listReports(dir: string): Report[] {
  return listJson<Report>(join(dir, "reports")).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

// ---- final report ------------------------------------------------------------
export function writeFinalReport(dir: string, payload: unknown): void {
  atomicWrite(join(dir, "final-report.json"), JSON.stringify(payload, null, 2));
  atomicWrite(join(dir, "final-report.md"), renderFinalReportMarkdown(payload as FinalReportPayload));
}

/** Derive a stable agent identity from the calling session's file path. */
export function callerAgent(ctx: unknown): string {
  const file = sessionFileOf(ctx);
  if (!file) return "agent";
  const base = file.replace(/\\/g, "/").split("/").pop() ?? "agent";
  return base.replace(/\.jsonl$/, "");
}

export function sessionFileOf(ctx: unknown): string | null {
  if (ctx && typeof ctx === "object" && "sessionManager" in ctx) {
    const sm = (ctx as { sessionManager?: { getSessionFile?: () => string | null } }).sessionManager;
    const file = sm?.getSessionFile?.();
    if (typeof file === "string" && file.length > 0) return file;
  }
  return null;
}
