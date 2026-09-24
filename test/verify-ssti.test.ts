import { expect, test } from "bun:test";
import { sstiVerdict } from "../src/tools";

// The SSTI verdict is a pure boundary predicate: confirmed only when the
// probe echoes the evaluated expression between unique markers AND the
// baseline does not. A status/length difference alone must never confirm —
// that was the false-positive regression. Strix HTTP tools never run on the
// host, so the verdict is exercised here without any network.

test("SSTI verdict rejects response-size differences but accepts an evaluated witness", () => {
  const marker = "abc123def456";
  const witness = `${marker}49${marker}`;

  // False-positive regression: probe differs in status AND body length, but
  // the witness is absent — no template evaluation happened.
  expect(
    sstiVerdict(
      witness,
      { status: 200, body: "ok" },
      { status: 404, body: "a longer error response unrelated to template evaluation" },
    ).verdict,
  ).toBe("rejected");

  // Real SSTI: the probe evaluated {{7*7}} → 49 between the markers.
  expect(
    sstiVerdict(witness, { status: 200, body: "ok" }, { status: 200, body: `value: ${witness}` }).verdict,
  ).toBe("confirmed");
});

test("SSTI verdict rejects reflection of the raw payload and pre-existing witnesses", () => {
  const marker = "abc123def456";
  const witness = `${marker}49${marker}`;

  // Payload reflected verbatim but never evaluated — no '49' between markers.
  expect(
    sstiVerdict(
      witness,
      { status: 200, body: "ok" },
      { status: 200, body: `value: ${marker}{{7*7}}${marker}` },
    ).verdict,
  ).toBe("rejected");

  // Witness already present in the baseline — the probe proves nothing.
  expect(
    sstiVerdict(
      witness,
      { status: 200, body: `page contains ${witness}` },
      { status: 200, body: `value: ${witness}` },
    ).verdict,
  ).toBe("rejected");

  // Identical responses — nothing injected.
  expect(sstiVerdict(witness, { status: 200, body: "same" }, { status: 200, body: "same" }).verdict).toBe(
    "rejected",
  );
});
