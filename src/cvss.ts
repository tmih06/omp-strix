/**
 * CVSS 3.1 base score — port of strix's `cvss` library usage.
 * Deterministic; no deps. Spec: https://www.first.org/cvss/v3.1/specification-document
 */

const METRIC_VALUES: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { N: 0.85, L: 0.62, H: 0.27 }, // scope U
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0.0 },
};

const PR_SCOPE_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

export interface CvssResult {
  score: number;
  severity: string;
  vector: string;
}

/** Round up to one decimal per CVSS 3.1 spec (integer-arithmetic roundup). */
function roundup(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvssSeverity(score: number): string {
  if (score <= 0) return "none";
  if (score < 4.0) return "low";
  if (score < 7.0) return "medium";
  if (score < 9.0) return "high";
  return "critical";
}

const REQUIRED_KEYS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"] as const;

/**
 * Compute base score from a metric breakdown like
 * `{ AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }`.
 * Returns an error string on invalid input, else the result.
 */
export function cvssBaseScore(breakdown: Record<string, string>): CvssResult | string {
  const b: Record<string, string> = {};
  for (const key of REQUIRED_KEYS) {
    const raw = breakdown[key];
    if (typeof raw !== "string" || raw.trim() === "") {
      return `cvss_breakdown missing metric ${key}`;
    }
    b[key] = raw.trim().toUpperCase();
  }
  if (b.S !== "U" && b.S !== "C") return `cvss_breakdown S must be U or C (got ${b.S})`;
  for (const key of ["AV", "AC", "UI"] as const) {
    if (!(b[key] in METRIC_VALUES[key])) return `cvss_breakdown ${key} invalid: ${b[key]}`;
  }
  const prTable = b.S === "C" ? PR_SCOPE_C : METRIC_VALUES.PR;
  if (!(b.PR in prTable)) return `cvss_breakdown PR invalid: ${b.PR}`;
  for (const key of ["C", "I", "A"] as const) {
    if (!(b[key] in METRIC_VALUES.CIA)) return `cvss_breakdown ${key} invalid: ${b[key]}`;
  }

  const iss = 1 - (1 - METRIC_VALUES.CIA[b.C]) * (1 - METRIC_VALUES.CIA[b.I]) * (1 - METRIC_VALUES.CIA[b.A]);
  const impact = b.S === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const exploitability =
    8.22 * METRIC_VALUES.AV[b.AV] * METRIC_VALUES.AC[b.AC] * prTable[b.PR] * METRIC_VALUES.UI[b.UI];

  let score: number;
  if (impact <= 0) {
    score = 0;
  } else if (b.S === "U") {
    score = roundup(Math.min(impact + exploitability, 10));
  } else {
    score = roundup(Math.min(1.08 * (impact + exploitability), 10));
  }

  const vector = `CVSS:3.1/AV:${b.AV}/AC:${b.AC}/PR:${b.PR}/UI:${b.UI}/S:${b.S}/C:${b.C}/I:${b.I}/A:${b.A}`;
  return { score, severity: cvssSeverity(score), vector };
}
