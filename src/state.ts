/**
 * Scan-state store for strix mode.
 *
 * Layout: only ./.strix/ in the target checkout is writable by the trusted
 * extension for scan metadata; /scratch is mounted from ./.strix/scratch.
 *
 *   <projectDir>/.strix/
 *     active.json                      -> { scanId, dir, target, scanMode, startedAt }
 *     scans/<scanId>/
 *       notes/<id>.json                -> one file per note (append-only, no RMW races)
 *       coverage/<id>.json             -> one file per coverage entry
 *       threat-models/<slug>.json      -> { target, model, amendments[] }
 *       reports/vuln-NNNN.json         -> one file per filed report (+ .md sibling)
 *       final-report.json              -> finish_scan payload (+ final-report.md)
 */

import { randomBytes } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import {
  type FinalReportPayload,
  renderFinalReportMarkdown,
  renderReportMarkdown,
  renderSarif,
} from "./report";
import { localStateRoot } from "./sandbox";

export interface ActiveScan {
  scanId: string;
  dir: string;
  target: string;
  scanMode: string;
  sandboxed: boolean;
  startedAt: string;
}

/** Per-project store under ./.strix; scan targets remain read-only in-container. */
let projectDir = process.cwd();
export function setProjectDir(dir: string): void {
  projectDir = realpathSync(dir);
}
export function getProjectDir(): string {
  return projectDir;
}
const strixRoot = () => join(projectDir, ".strix");
const activeFile = () => join(strixRoot(), "active.json");
const scansDir = () => join(strixRoot(), "scans");

/** Reject repository-supplied symlinks in the control-plane directory tree. */
function ensureWriteDir(dir: string): void {
  const root = join(projectDir, ".strix");
  const rel = relative(root, dir);
  if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    // Public state helpers also accept unrelated caller-owned temp dirs.
    mkdirSync(dir, { recursive: true });
    return;
  }
  localStateRoot(projectDir);
  let current = root;
  for (const part of rel.split(sep).filter(Boolean)) {
    current = join(current, part);
    if (existsSync(current)) {
      if (!lstatSync(current).isDirectory()) throw new Error(`Unsafe scan directory: ${current}`);
    } else {
      mkdirSync(current, { mode: 0o700 });
    }
  }
}

function atomicWrite(path: string, data: string): void {
  ensureWriteDir(dirname(path));
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  writeFileSync(tmp, data, { encoding: "utf8", mode: 0o600 });
  renameSync(tmp, path);
}

/** Never follow a repository-supplied symlink through scan-state reads. */
function safeStatePath(path: string, directory: boolean): boolean {
  const root = join(projectDir, ".strix");
  const rel = relative(root, path);
  if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return true;
  if (!lstatSync(root).isDirectory()) return false;
  localStateRoot(projectDir);
  let current = root;
  const parts = rel.split(sep).filter(Boolean);
  for (let i = 0; i < parts.length; i++) {
    current = join(current, parts[i]);
    const stat = lstatSync(current);
    if (!(i === parts.length - 1 && !directory ? stat.isFile() : stat.isDirectory())) return false;
  }
  return true;
}

function readJson<T>(path: string): T | null {
  try {
    if (!safeStatePath(path, false)) return null;
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return null;
  }
}

function listJson<T>(dir: string): T[] {
  try {
    if (!safeStatePath(dir, true)) return [];
  } catch {
    return [];
  }
  const out: T[] = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    const parsed = readJson<T>(join(dir, name));
    if (parsed !== null) out.push(parsed);
  }
  return out;
}

/** IDs are single filename components, never paths or regex fragments. */
function validId(id: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(id);
}
/** Ignore forged active records pointing outside the current scan store. */
function readActiveScan(path: string): ActiveScan | null {
  try {
    if (!lstatSync(path).isFile()) return null;
    const scan = readJson<ActiveScan>(path);
    if (
      !scan ||
      typeof scan.scanId !== "string" ||
      !/^scan-[a-z0-9]+-[a-f0-9]{6}$/.test(scan.scanId) ||
      typeof scan.sandboxed !== "boolean"
    ) {
      return null;
    }
    return scan.dir === join(scansDir(), scan.scanId) && safeStatePath(scan.dir, true) ? scan : null;
  } catch {
    return null;
  }
}

export function beginScan(target: string, scanMode: string, sandboxed: boolean): ActiveScan {
  const scanId = `scan-${Date.now().toString(36)}-${randomBytes(3).toString("hex")}`;
  const dir = join(scansDir(), scanId);
  ensureWriteDir(dir);
  const scan: ActiveScan = {
    scanId,
    dir,
    target,
    scanMode,
    sandboxed,
    startedAt: new Date().toISOString(),
  };
  atomicWrite(activeFile(), JSON.stringify(scan, null, 2));
  return scan;
}

export function endScan(): void {
  const file = activeFile();
  if (!existsSync(file)) return;
  localStateRoot(projectDir);
  try {
    const scan = readActiveScan(file);
    if (scan) {
      atomicWrite(join(scan.dir, "ended.json"), JSON.stringify({ endedAt: new Date().toISOString() }));
    }
  } finally {
    try {
      renameSync(file, `${file}.last`);
    } catch {
      /* already gone */
    }
  }
}

/** Resolve only validated scan dirs; never follow a forged active.json dir. */
export function scanDir(): string | null {
  const active = readActiveScan(activeFile());
  if (active) return active.dir;
  return readActiveScan(`${activeFile()}.last`)?.dir ?? null;
}

export function activeScan(): ActiveScan | null {
  return readActiveScan(activeFile());
}

/** Resume a validated interrupted scan without an ended.json marker. */
export function resumableScan(): ActiveScan | null {
  const scan = activeScan();
  if (!scan) return null;
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
  return validId(id) ? readJson<Note>(join(dir, "notes", `${id}.json`)) : null;
}

export function putNote(dir: string, note: Note): void {
  if (!validId(note.id)) throw new Error("Invalid note id");
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
  if (!validId(entry.id)) throw new Error("Invalid coverage id");
  atomicWrite(join(dir, "coverage", `${entry.id}.json`), JSON.stringify(entry, null, 2));
}

export function listCoverage(dir: string): CoverageEntry[] {
  return listJson<CoverageEntry>(join(dir, "coverage")).sort((a, b) =>
    a.createdAt.localeCompare(b.createdAt),
  );
}
export function deleteFile(dir: string, bucket: string, id: string): void {
  if (!validId(bucket) || !validId(id)) return;
  try {
    const bucketDir = join(dir, bucket);
    if (!safeStatePath(bucketDir, true)) return;
    rmSync(join(bucketDir, `${id}.json`));
  } catch {
    /* already gone or unsafe directory */
  }
}

// ---- artifacts — harvested credentials, tokens, and object references ------

export interface Artifact {
  id: string;
  /** credential | object_ref | session | token | key | other */
  kind: string;
  /** The value: password, hash, JWT, cookie, UUID, numeric id, … */
  value: string;
  /** Where it was captured: endpoint, file, response, note id. */
  source: string;
  /** What it authenticates or identifies: user, role, tenant, endpoint scope. */
  scope: string;
  agent: string;
  createdAt: string;
}

export function addArtifact(dir: string, artifact: Omit<Artifact, "id" | "createdAt">): Artifact {
  const full: Artifact = { ...artifact, id: "", createdAt: new Date().toISOString() };
  writeEntry(join(dir, "artifacts"), "art", full);
  return full;
}

export function listArtifacts(dir: string, kind?: string): Artifact[] {
  return listJson<Artifact>(join(dir, "artifacts"))
    .filter((a) => !kind || a.kind === kind)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

/** Dedupe: same kind+value+scope is one artifact. */
export function findArtifact(dir: string, kind: string, value: string, scope: string): Artifact | null {
  const v = value.trim();
  const sc = scope.trim().toLowerCase();
  for (const a of listArtifacts(dir, kind)) {
    if (a.value.trim() === v && a.scope.trim().toLowerCase() === sc) return a;
  }
  return null;
}

// ---- attack path — directed graph of exploit hops across the engagement ----

export interface AttackHop {
  id: string;
  /** Node types: surface | vulnerability | credential | access | objective */
  from: string;
  to: string;
  /** How the hop was made: exploit, auth, pivot, escalate, exfiltrate. */
  via: string;
  /** Evidence: report id, artifact id, or command output reference. */
  evidence: string;
  agent: string;
  createdAt: string;
}

export function addAttackHop(dir: string, hop: Omit<AttackHop, "id" | "createdAt">): AttackHop {
  const full: AttackHop = { ...hop, id: "", createdAt: new Date().toISOString() };
  writeEntry(join(dir, "attack-path"), "hop", full);
  return full;
}

export function listAttackPath(dir: string): AttackHop[] {
  return listJson<AttackHop>(join(dir, "attack-path")).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

// ---- plan — structured task decomposition for the scan ---------------------

export interface PlanTask {
  id: string;
  content: string;
  status: "pending" | "in_progress" | "completed" | "blocked";
  agent: string;
  createdAt: string;
  updatedAt: string;
}

export function putPlan(dir: string, tasks: PlanTask[]): void {
  atomicWrite(join(dir, "plan.json"), JSON.stringify(tasks, null, 2));
}

export function getPlan(dir: string): PlanTask[] {
  return readJson<PlanTask[]>(join(dir, "plan.json")) ?? [];
}

// ---- witness schemas — typed fields required per vulnerability class --------

/** Required witness fields for each vulnerability class. */
export const WITNESS_SCHEMAS: Record<string, string[]> = {
  INJECTION: [
    "slot_type",
    "sanitization_observed",
    "concat_occurrences",
    "witness_payload",
    "mismatch_reason",
  ],
  XSS: ["render_context", "encoding_observed", "witness_payload"],
  AUTH: [
    "source_endpoint",
    "vulnerable_code_location",
    "missing_defense",
    "exploitation_hypothesis",
    "suggested_exploit_technique",
  ],
  AUTHZ: ["role_context", "guard_evidence", "side_effect", "minimal_witness"],
  SSRF: ["target_url", "callback_received", "redirect_chain", "server_side_proof"],
  MISC: ["observed_behavior", "expected_behavior", "impact"],
};

/** Validate that a candidate has all required witness fields for its class. */
export function validateWitness(
  cls: string,
  witness: Record<string, unknown>,
): { valid: boolean; missing: string[] } {
  const required = WITNESS_SCHEMAS[cls] ?? WITNESS_SCHEMAS.MISC;
  const missing = required.filter(
    (f) =>
      !(f in witness) || witness[f] === undefined || witness[f] === null || String(witness[f]).trim() === "",
  );
  return { valid: missing.length === 0, missing };
}

// ---- candidates — structured vulnerability queue with stable IDs ----------

export interface Candidate {
  id: string;
  /** Vulnerability class: INJECTION | XSS | AUTH | AUTHZ | SSRF | MISC */
  class: string;
  /** Current status: pending | exploited | blocked | false_positive */
  status: "pending" | "exploited" | "blocked" | "false_positive";
  /** Witness fields per WITNESS_SCHEMAS[class]. */
  witness: Record<string, unknown>;
  /** Evidence references — note ids, artifact ids, command output. */
  evidence_refs: string[];
  /** Agent that recorded the candidate. */
  created_by: string;
  createdAt: string;
  updatedAt: string;
}

/** Mint the next candidate id for a class: {CLASS}-NN. */
export function nextCandidateId(dir: string, cls: string): string {
  const prefix =
    cls
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, "")
      .slice(0, 4) || "MISC";
  const candidatesDir = join(dir, "candidates");
  let max = 0;
  if (existsSync(candidatesDir) && safeStatePath(candidatesDir, true)) {
    for (const name of readdirSync(candidatesDir)) {
      const m = name.match(new RegExp(`^${prefix}-(\\d+)\\.json$`));
      if (m) max = Math.max(max, Number.parseInt(m[1], 10));
    }
  }
  return `${prefix}-${String(max + 1).padStart(2, "0")}`;
}

export function addCandidate(
  dir: string,
  candidate: Omit<Candidate, "id" | "createdAt" | "updatedAt">,
): Candidate {
  const id = nextCandidateId(dir, candidate.class);
  const now = new Date().toISOString();
  const full: Candidate = { ...candidate, id, createdAt: now, updatedAt: now };
  atomicWrite(join(dir, "candidates", `${id}.json`), JSON.stringify(full, null, 2));
  return full;
}

export function getCandidate(dir: string, id: string): Candidate | null {
  return validId(id) ? readJson<Candidate>(join(dir, "candidates", `${id}.json`)) : null;
}

export function putCandidate(dir: string, candidate: Candidate): void {
  if (!validId(candidate.id)) throw new Error("Invalid candidate id");
  atomicWrite(join(dir, "candidates", `${candidate.id}.json`), JSON.stringify(candidate, null, 2));
}

export function listCandidates(dir: string, status?: string): Candidate[] {
  return listJson<Candidate>(join(dir, "candidates"))
    .filter((c) => !status || c.status === status)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

// ---- verdicts — validator decisions on candidates --------------------------

export interface Verdict {
  id: string;
  candidate_id: string;
  verdict: "confirmed" | "rejected" | "inconclusive";
  /** Proof-of-Exploitation level 1-4 (shannon). */
  poe_level: number;
  /** Baseline control evidence — what the unmodified request returned. */
  baseline_control: string;
  /** What the validator tried that failed (for rejected/inconclusive). */
  what_we_tried: string;
  agent: string;
  createdAt: string;
}

export function addVerdict(dir: string, verdict: Omit<Verdict, "id" | "createdAt">): Verdict {
  const full: Verdict = { ...verdict, id: "", createdAt: new Date().toISOString() };
  writeEntry(join(dir, "verdicts"), "verdict", full);
  return full;
}

export function listVerdicts(dir: string, candidateId?: string): Verdict[] {
  return listJson<Verdict>(join(dir, "verdicts"))
    .filter((v) => !candidateId || v.candidate_id === candidateId)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

// ---- signals — reactive dispatch feed (swarm pattern) ----------------------

export interface Signal {
  id: string;
  /** Signal type: new_endpoint | new_param | auth_required | error | info */
  kind: string;
  /** What was observed. */
  detail: string;
  /** Suggested next agent or action. */
  suggested_action: string;
  /** Whether a root agent has consumed this signal. */
  acked: boolean;
  agent: string;
  createdAt: string;
}

export function addSignal(dir: string, signal: Omit<Signal, "id" | "createdAt" | "acked">): Signal {
  const full: Signal = { ...signal, id: "", acked: false, createdAt: new Date().toISOString() };
  writeEntry(join(dir, "signals"), "sig", full);
  return full;
}

export function listSignals(dir: string, acked?: boolean): Signal[] {
  return listJson<Signal>(join(dir, "signals"))
    .filter((s) => acked === undefined || s.acked === acked)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

export function ackSignal(dir: string, id: string): void {
  if (!validId(id)) return;
  const s = readJson<Signal>(join(dir, "signals", `${id}.json`));
  if (s) {
    s.acked = true;
    atomicWrite(join(dir, "signals", `${id}.json`), JSON.stringify(s, null, 2));
  }
}

// ---- finding keys — canonical dedup (artiphishell) --------------------------

/** Normalize a URL path for dedup: replace numeric/UUID segments with {id}. */
export function normalizePath(path: string): string {
  return path
    .replace(/\/\d+/g, "/{id}")
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "/{uuid}")
    .replace(/\/[0-9a-f]{24}/g, "/{oid}");
}

/** Canonical finding key: method + normalized path + param + CWE. */
export function findingKey(method: string, endpoint: string, param: string, cwe: string): string {
  const m = method.toUpperCase().trim() || "GET";
  const p = normalizePath(endpoint.trim().toLowerCase());
  const prm = param.trim().toLowerCase();
  const c = cwe.trim().toUpperCase();
  return `${m} ${p} ${prm} ${c}`.trim();
}

/** Jaccard similarity on token sets — for fuzzy title dedup. */
export function jaccard(a: string, b: string): number {
  const sa = new Set(a.toLowerCase().split(/\s+/).filter(Boolean));
  const sb = new Set(b.toLowerCase().split(/\s+/).filter(Boolean));
  const inter = [...sa].filter((x) => sb.has(x)).length;
  const union = new Set([...sa, ...sb]).size;
  return union === 0 ? 0 : inter / union;
}

// ---- degradation — closed reason codes for partial coverage -----------------

export type DegradationReason =
  | "agent_timeout"
  | "tool_error"
  | "endpoint_unreachable"
  | "auth_failed"
  | "rate_limited"
  | "scope_excluded"
  | "sast_failed"
  | "reconciliation_failed"
  | "report_omitted";

export interface Degradation {
  id: string;
  reason: DegradationReason;
  detail: string;
  agent: string;
  createdAt: string;
}

export function addDegradation(dir: string, deg: Omit<Degradation, "id" | "createdAt">): Degradation {
  const now = new Date().toISOString();
  const full: Degradation = { ...deg, id: "", createdAt: now };
  writeEntry(join(dir, "degradation"), "deg", full);
  return full;
}

export function listDegradation(dir: string): Degradation[] {
  return listJson<Degradation>(join(dir, "degradation")).sort((a, b) =>
    a.createdAt.localeCompare(b.createdAt),
  );
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
  /** Lifecycle: confirmed findings count toward the report; disproven/superseded stay on file for audit. */
  status?: "confirmed" | "disproven" | "superseded";
  /** When status=disproven/superseded: why, and which report replaces it. */
  status_reason?: string;
  superseded_by?: string;
  [key: string]: unknown;
}

export function nextReportId(dir: string, prefix: string): string {
  if (!validId(prefix)) throw new Error("Invalid report prefix");
  const reportsDir = join(dir, "reports");
  let max = 0;
  if (existsSync(reportsDir) && safeStatePath(reportsDir, true)) {
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
  return validId(id) ? readJson<Report>(join(dir, "reports", `${id}.json`)) : null;
}

export function putReport(dir: string, report: Report): void {
  if (!validId(report.id)) throw new Error("Invalid report id");
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
  atomicWrite(join(dir, "final-report.sarif"), renderSarif(payload as FinalReportPayload));
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
