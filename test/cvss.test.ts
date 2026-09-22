import { describe, expect, test } from "bun:test";
import { cvssBaseScore, cvssSeverity } from "../src/cvss";

// Reference vectors from the CVSS v3.1 spec examples.
const FULL = { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" };

describe("cvssBaseScore", () => {
  test("full-impact network vector scores 9.8 critical", () => {
    const r = cvssBaseScore(FULL);
    expect(typeof r).not.toBe("string");
    if (typeof r === "string") return;
    expect(r.score).toBe(9.8);
    expect(r.severity).toBe("critical");
    expect(r.vector).toContain("CVSS:3.1");
  });

  test("zero-impact vector scores 0.0 none", () => {
    const r = cvssBaseScore({ ...FULL, C: "N", I: "N", A: "N" });
    if (typeof r === "string") throw new Error(r);
    expect(r.score).toBe(0);
    expect(r.severity).toBe("none");
  });

  test("scope-changed vector uses changed-scope PR weights", () => {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
    const r = cvssBaseScore({ ...FULL, S: "C" });
    if (typeof r === "string") throw new Error(r);
    expect(r.score).toBe(10.0);
  });

  test("local high-priv vector scores lower than network", () => {
    const r = cvssBaseScore({ AV: "L", AC: "H", PR: "H", UI: "R", S: "U", C: "L", I: "L", A: "L" });
    if (typeof r === "string") throw new Error(r);
    expect(r.score).toBeGreaterThan(0);
    expect(r.score).toBeLessThan(5);
  });

  test("missing metric returns an error string", () => {
    const { AV: _drop, ...partial } = FULL;
    expect(typeof cvssBaseScore(partial)).toBe("string");
  });

  test("invalid metric value returns an error string", () => {
    expect(typeof cvssBaseScore({ ...FULL, AV: "X" })).toBe("string");
  });
});

describe("cvssSeverity", () => {
  test("bands match the spec", () => {
    expect(cvssSeverity(0)).toBe("none");
    expect(cvssSeverity(3.9)).toBe("low");
    expect(cvssSeverity(4.0)).toBe("medium");
    expect(cvssSeverity(6.9)).toBe("medium");
    expect(cvssSeverity(7.0)).toBe("high");
    expect(cvssSeverity(8.9)).toBe("high");
    expect(cvssSeverity(9.0)).toBe("critical");
  });
});
