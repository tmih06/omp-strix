/**
 * Markdown renderers for scan artifacts.
 *
 * JSON under scans/<id>/ is the canonical machine state (append-only files,
 * atomic writes, tool-readable). These renderers produce the human layer on
 * top — a sibling .md next to every report .json, and final-report.md at
 * finish_scan — mirroring upstream strix's report/writer.py output
 * (vulnerabilities/*.md + penetration_test_report.md). Field names follow our
 * Report shape: `revisions` (upstream `update_history`), `createdAt`
 * (upstream `timestamp`), `dependency_metadata` nested under the report.
 */

import type { CoverageEntry, Report } from "./state";

// ── fence helpers (port of writer.py) ───────────────────────────────────────

const BACKTICK_RUN = /`+/g;
const FENCE_RE = /^`{3,}([^\n`]*)\n([\s\S]*?)\n?`{3,}\s*$/;

/** Fence one backtick longer than the longest run inside content (min 3). */
function safeFence(content: string): string {
  let longest = 0;
  for (const m of content.matchAll(BACKTICK_RUN)) longest = Math.max(longest, m[0].length);
  return "`".repeat(Math.max(3, longest + 1));
}

/** Split an optionally fenced code string into (language, code). */
function parseFencedCode(raw: string): [string | null, string] {
  const m = FENCE_RE.exec(raw.trim());
  if (!m) return [null, raw];
  const info = (m[1] ?? "").trim();
  const language = info ? info.split(/\s+/)[0] : null;
  return [language || null, m[2] ?? ""];
}

/** Cheap language guess for unfenced PoC code; defaults to python. */
function guessLanguageName(code: string): string {
  const c = code.trimStart();
  if (/^#!.*\b(bash|sh|zsh)\b/.test(c)) return "bash";
  if (/\b(function|const|let|=>|require\(|import\s.*from)\b/.test(c)) return "javascript";
  if (/\b(def |import |print\(|if __name__)/.test(c)) return "python";
  if (/\b(package main|func |fmt\.)/.test(c)) return "go";
  if (/^\s*<(html|!doctype|div|script)/i.test(c)) return "html";
  if (/^\s*(SELECT|INSERT|UPDATE|DELETE)\b/im.test(c)) return "sql";
  if (/^\s*[{[]/.test(c)) return "json";
  return "python";
}

// ── field accessors (Report carries [key: string]: unknown) ────────────────

function s(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}
function n(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}
function rec(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}
function title(v: unknown): string | null {
  const t = s(v);
  return t ? t[0].toUpperCase() + t.slice(1) : null;
}

// ── vulnerability report → markdown ─────────────────────────────────────────

export function renderReportMarkdown(report: Report): string {
  const dep = rec(report.dependency_metadata);
  const lines: string[] = [
    `# ${s(report.title) ?? "Untitled Vulnerability"}`,
    "",
    `**ID:** ${s(report.id) ?? "unknown"}`,
    `**Severity:** ${(s(report.severity) ?? "unknown").toUpperCase()}`,
    `**Found:** ${s(report.createdAt) ?? "unknown"}`,
  ];

  const cvss = n(report.cvss);
  const advisoryCvss = dep ? n(dep.advisory_cvss) : null;
  const metadata: [string, unknown][] = [
    ["Target", s(report.target)],
    ["Package", dep ? s(dep.package_name) : null],
    ["Ecosystem", dep ? s(dep.package_ecosystem) : null],
    ["Installed Version", dep ? s(dep.installed_version) : null],
    ["Fixed Version", dep ? s(dep.fixed_version) : null],
    ["Introduced By", dep ? s(dep.introduced_by) : null],
    ["Dependency Chain", dep ? s(dep.dependency_path) : null],
    ["Manifest", dep ? s(dep.manifest_path) : null],
    ["Reachability", dep ? s(dep.reachability) : null],
    ["Endpoint", s(report.endpoint)],
    ["Method", s(report.method)],
    ["CVE", s(report.cve)],
    ["CWE", s(report.cwe)],
  ];
  if (cvss !== null) metadata.push(["CVSS", cvss]);
  if (advisoryCvss !== null && advisoryCvss !== cvss) metadata.push(["Advisory CVSS", advisoryCvss]);
  if (dep && s(dep.contextual_cvss_vector)) metadata.push(["Contextual CVSS Vector", dep.contextual_cvss_vector]);
  const confidence = title(report.confidence);
  if (confidence) metadata.push(["Confidence", confidence]);
  const fixEffort = title(report.fix_effort);
  if (fixEffort) metadata.push(["Fix Effort", fixEffort]);
  for (const [label, value] of metadata) {
    if (value !== null && value !== undefined && value !== "") lines.push(`**${label}:** ${value}`);
  }

  lines.push("", "## Description", "", s(report.description) ?? "No description provided.", "");

  const section = (heading: string, value: unknown): void => {
    const v = s(value);
    if (!v) return;
    lines.push(`## ${heading}`, "", v, "");
  };
  section("Evidence", report.evidence);
  section("Impact", report.impact);
  section("Counterevidence", report.counterevidence);
  section("Confidence Rationale", report.confidence_rationale);
  section("What Would Change This Severity", report.severity_change_conditions);
  section("Technical Analysis", report.technical_analysis);
  if (dep) section("Contextual CVSS", dep.contextual_cvss_reasoning);

  const pocDesc = s(report.poc_description);
  const pocCode = s(report.poc_script_code);
  if (pocDesc || pocCode) {
    lines.push("## Proof of Concept", "");
    if (pocDesc) lines.push(pocDesc, "");
    if (pocCode) {
      const [lang, code] = parseFencedCode(pocCode);
      const fence = safeFence(code);
      lines.push(`${fence}${lang ?? guessLanguageName(code)}`, code, fence, "");
    }
  }

  const locations = Array.isArray(report.code_locations) ? report.code_locations : [];
  if (locations.length > 0) {
    lines.push("## Code Analysis", "");
    locations.forEach((raw, i) => {
      const loc = rec(raw) ?? {};
      const file = s(loc.file) ?? "unknown";
      const start = n(loc.start_line);
      const end = n(loc.end_line);
      const lineRef =
        start !== null ? (end !== null && end !== start ? ` (lines ${start}-${end})` : ` (line ${start})`) : "";
      lines.push(`**Location ${i + 1}:** \`${file}\`${lineRef}`);
      if (s(loc.label)) lines.push(`  ${loc.label}`);
      const snippet = s(loc.snippet);
      if (snippet) {
        const fence = safeFence(snippet);
        lines.push(`  ${fence}`, ...snippet.split("\n").map((ln) => `  ${ln}`), `  ${fence}`);
      }
      if (s(loc.fix_before) || s(loc.fix_after)) {
        lines.push("", "  **Suggested Fix:**", "```diff");
        if (s(loc.fix_before)) lines.push(...String(loc.fix_before).split("\n").map((ln) => `- ${ln}`));
        if (s(loc.fix_after)) lines.push(...String(loc.fix_after).split("\n").map((ln) => `+ ${ln}`));
        lines.push("```");
      }
      lines.push("");
    });
  }

  section("Remediation", report.remediation_steps);
  section("Fix Verification", report.fix_verification);
  section("Assumptions", report.assumptions);

  // Update history — our `revisions` carry { at, agent, reason, fields }.
  if (Array.isArray(report.revisions) && report.revisions.length > 0) {
    lines.push("## Update History", "");
    for (const raw of report.revisions) {
      const entry = rec(raw) ?? {};
      const author = s(entry.agent) ?? "an agent";
      const fields = Array.isArray(entry.fields) ? entry.fields.map(String).join(", ") : "";
      lines.push(`**${s(entry.at) ?? "unknown"}** — ${author} updated: ${fields}`);
      if (s(entry.reason)) lines.push(`  Reason: ${entry.reason}`);
      lines.push("");
    }
  }

  return lines.join("\n");
}

// ── final report → markdown ─────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  informational: 4,
};

export interface FinalReportPayload {
  scan_id?: string | null;
  target?: string | null;
  scan_mode?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  executive_summary?: string;
  findings?: Report[];
  coverage?: CoverageEntry[];
  open_follow_ups?: CoverageEntry[];
}

export function renderFinalReportMarkdown(payload: FinalReportPayload): string {
  const findings = payload.findings ?? [];
  const sorted = [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[(s(a.severity) ?? "").toLowerCase()] ?? 5) -
        (SEVERITY_ORDER[(s(b.severity) ?? "").toLowerCase()] ?? 5) ||
      (s(a.createdAt) ?? "").localeCompare(s(b.createdAt) ?? ""),
  );
  const lines: string[] = [
    "# Security Penetration Test Report",
    "",
    `**Target:** ${payload.target ?? "unknown"}`,
    `**Scan ID:** ${payload.scan_id ?? "unknown"}`,
    `**Mode:** ${payload.scan_mode ?? "unknown"}`,
    `**Started:** ${payload.started_at ?? "unknown"}`,
    `**Finished:** ${payload.finished_at ?? "unknown"}`,
    "",
    "## Executive Summary",
    "",
    payload.executive_summary ?? "",
    "",
    `## Findings (${sorted.length})`,
    "",
  ];
  if (sorted.length === 0) {
    lines.push("No findings filed.", "");
  } else {
    lines.push("| ID | Severity | Title | File |", "| --- | --- | --- | --- |");
    for (const r of sorted) {
      const id = s(r.id) ?? "?";
      const sev = (s(r.severity) ?? "unknown").toUpperCase();
      const t = (s(r.title) ?? "untitled").replace(/\|/g, "\\|");
      lines.push(`| ${id} | ${sev} | ${t} | [reports/${id}.md](reports/${id}.md) |`);
    }
    lines.push("");
  }

  const open = payload.open_follow_ups ?? [];
  if (open.length > 0) {
    lines.push(`## Open Follow-ups (${open.length})`, "");
    for (const e of open) {
      lines.push(`- **${e.surface}** (${e.riskArea}) — ${e.evidence}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
