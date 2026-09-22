import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  addCoverage,
  addReport,
  findCoverage,
  getReport,
  listCoverage,
  listReports,
  nextReportId,
  putCoverage,
  putReport,
} from "../src/state";

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "strix-state-"));
  dirs.push(d);
  return d;
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const reportFields = {
  findingClass: "dynamic" as const,
  agent: "a",
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  revisions: [],
  title: "t",
};

describe("reports", () => {
  test("addReport assigns sequential ids and writes json+md siblings", () => {
    const dir = tmp();
    const r1 = addReport(dir, "vuln", reportFields);
    const r2 = addReport(dir, "vuln", reportFields);
    expect(r1.id).toBe("vuln-0001");
    expect(r2.id).toBe("vuln-0002");
    const files = readdirSync(join(dir, "reports")).sort();
    expect(files).toEqual(["vuln-0001.json", "vuln-0001.md", "vuln-0002.json", "vuln-0002.md"]);
  });

  test("putReport updates an existing report and its md", () => {
    const dir = tmp();
    const r = addReport(dir, "vuln", reportFields);
    putReport(dir, { ...r, title: "updated" });
    expect(getReport(dir, r.id)?.title).toBe("updated");
  });

  test("listReports sorts by createdAt", () => {
    const dir = tmp();
    addReport(dir, "vuln", { ...reportFields, createdAt: "2026-01-02T00:00:00Z" });
    addReport(dir, "vuln", { ...reportFields, createdAt: "2026-01-01T00:00:00Z" });
    const ids = listReports(dir).map((r) => r.createdAt);
    expect(ids).toEqual([...ids].sort());
  });

  test("nextReportId ignores other prefixes", () => {
    const dir = tmp();
    addReport(dir, "dep", reportFields);
    expect(nextReportId(dir, "vuln")).toBe("vuln-0001");
    expect(nextReportId(dir, "dep")).toBe("dep-0002");
  });
});

describe("coverage", () => {
  test("findCoverage matches surface+riskArea case-insensitively", () => {
    const dir = tmp();
    addCoverage(dir, {
      surface: "/Login",
      riskArea: "AuthN",
      outcome: "tested",
      evidence: "ok",
      agent: "a",
    });
    expect(findCoverage(dir, "/login", "authn")?.surface).toBe("/Login");
    expect(findCoverage(dir, "/other", "authn")).toBeNull();
  });

  test("listCoverage returns entries sorted by createdAt", () => {
    const dir = tmp();
    const older = addCoverage(dir, {
      surface: "b",
      riskArea: "r",
      outcome: "tested",
      evidence: "",
      agent: "a",
    });
    const newer = addCoverage(dir, {
      surface: "a",
      riskArea: "r",
      outcome: "tested",
      evidence: "",
      agent: "a",
    });
    // Force distinct timestamps so the ordering contract is observable.
    newer.createdAt = new Date(Date.parse(older.createdAt) + 1000).toISOString();
    putCoverage(dir, newer);
    expect(listCoverage(dir).map((e) => e.surface)).toEqual(["b", "a"]);
  });
});
