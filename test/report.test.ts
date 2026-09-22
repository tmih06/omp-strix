import { describe, expect, test } from "bun:test";
import { renderFinalReportMarkdown, renderReportMarkdown } from "../src/report";
import type { Report } from "../src/state";

function baseReport(over: Partial<Report> = {}): Report {
  return {
    id: "vuln-0001",
    findingClass: "dynamic",
    agent: "recon-1",
    createdAt: "2026-09-22T10:00:00Z",
    updatedAt: "2026-09-22T10:00:00Z",
    revisions: [],
    title: "SQLi in /login",
    severity: "high",
    target: "https://example.com",
    description: "Injectable username field.",
    ...over,
  } as Report;
}

describe("renderReportMarkdown", () => {
  test("renders title, severity, and metadata header", () => {
    const md = renderReportMarkdown(baseReport({ endpoint: "/login", method: "POST", cvss: 8.1 }));
    expect(md).toContain("# SQLi in /login");
    expect(md).toContain("**Severity:** HIGH");
    expect(md).toContain("**Endpoint:** /login");
    expect(md).toContain("**CVSS:** 8.1");
  });

  test("omits empty optional sections", () => {
    const md = renderReportMarkdown(baseReport());
    expect(md).not.toContain("## Evidence");
    expect(md).not.toContain("## Proof of Concept");
    expect(md).not.toContain("## Update History");
  });

  test("renders PoC with a fence longer than embedded backticks", () => {
    const md = renderReportMarkdown(baseReport({ poc_script_code: "print('```nested```')" }));
    // fence must be >3 backticks so the embedded ``` doesn't close it
    expect(md).toMatch(/`{4,}\w*\nprint\('```nested```'\)\n`{4,}/);
  });

  test("renders code locations with diff fix", () => {
    const md = renderReportMarkdown(
      baseReport({
        code_locations: [
          { file: "auth.py", start_line: 40, end_line: 45, fix_before: "old", fix_after: "new" },
        ] as never,
      }),
    );
    expect(md).toContain("## Code Analysis");
    expect(md).toContain("`auth.py` (lines 40-45)");
    expect(md).toContain("```diff");
    expect(md).toContain("- old");
    expect(md).toContain("+ new");
  });

  test("renders revision history", () => {
    const md = renderReportMarkdown(
      baseReport({
        revisions: [{ at: "2026-09-22T11:00:00Z", agent: "hunter", reason: "added PoC", fields: ["poc"] }],
      }),
    );
    expect(md).toContain("## Update History");
    expect(md).toContain("hunter updated: poc");
  });
});

describe("renderFinalReportMarkdown", () => {
  test("sorts findings by severity and links report files", () => {
    const md = renderFinalReportMarkdown({
      target: "t",
      findings: [
        baseReport({ id: "vuln-0002", severity: "low", title: "minor" }),
        baseReport({ id: "vuln-0001", severity: "critical", title: "severe" }),
      ],
    });
    expect(md).toContain("# Security Penetration Test Report");
    const crit = md.indexOf("vuln-0001");
    const low = md.indexOf("vuln-0002");
    expect(crit).toBeGreaterThan(-1);
    expect(crit).toBeLessThan(low);
    expect(md).toContain("[reports/vuln-0001.md](reports/vuln-0001.md)");
  });

  test("escapes pipes in titles inside the table", () => {
    const md = renderFinalReportMarkdown({
      findings: [baseReport({ title: "a | b" })],
    });
    expect(md).toContain("a \\| b");
  });

  test("lists open follow-ups", () => {
    const md = renderFinalReportMarkdown({
      open_follow_ups: [
        {
          id: "cov-1",
          surface: "/admin",
          riskArea: "authz",
          outcome: "needs_follow_up",
          evidence: "untested",
          agent: "a",
          createdAt: "",
          updatedAt: "",
          history: [],
        },
      ],
    });
    expect(md).toContain("## Open Follow-ups (1)");
    expect(md).toContain("**/admin** (authz)");
  });
});
