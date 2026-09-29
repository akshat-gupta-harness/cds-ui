import assert from "node:assert/strict";
import test from "node:test";
import { diffValues, pickPackage } from "./diff.mjs";

test("identical payloads produce no diffs", () => {
  const pkg = { purl: "pkg:npm/left-pad@1.0.0", licenses: ["MIT"], cves: [] };
  assert.deepEqual(diffValues(pkg, structuredClone(pkg)), []);
});

test("null versus empty list is shape, not a value change", () => {
  const diffs = diffValues({ licenses: null }, { licenses: [] });
  assert.equal(diffs.length, 1);
  assert.equal(diffs[0].kind, "shape");
  assert.equal(diffs[0].path, "licenses");
});

test("license order does not count; membership does", () => {
  assert.deepEqual(
    diffValues({ licenses: ["MIT", "Apache-2.0"] }, { licenses: ["Apache-2.0", "MIT"] }),
    [],
  );
  const diffs = diffValues({ licenses: ["MIT"] }, { licenses: ["Apache-2.0"] });
  assert.equal(diffs.length, 1);
  assert.equal(diffs[0].kind, "value");
});

test("cves are keyed by id", () => {
  const left = {
    cves: [
      { id: "CVE-1", impact: { score: 1 } },
      { id: "CVE-2", impact: { score: 5 } },
    ],
  };
  const right = {
    cves: [
      { id: "CVE-1", impact: { score: 9 } },
      { id: "CVE-3", impact: { score: 4 } },
    ],
  };
  const diffs = diffValues(left, right);
  const paths = diffs.map((d) => d.path).sort();
  assert.deepEqual(paths, ["cves[CVE-1].impact.score", "cves[CVE-2]", "cves[CVE-3]"]);
  const onlyLeft = diffs.find((d) => d.path === "cves[CVE-2]");
  assert.equal(onlyLeft.rightMissing, true);
  assert.equal(onlyLeft.kind, "value");
});

test("qwiet { ok, response } envelope unwraps to the package", () => {
  const pkg = { purl: "pkg:npm/left-pad@1.0.0", licenses: ["MIT"] };
  assert.equal(pickPackage({ ok: true, response: [pkg] }, pkg.purl), pkg);
});

test("enrichment vulnerabilities are keyed by _id", () => {
  const diffs = diffValues(
    { vulnerabilitydetails: { vulnerabilities: [{ _id: "CVE-1", impact: { baseScore: 1 } }] } },
    { vulnerabilitydetails: { vulnerabilities: [{ _id: "CVE-1", impact: { baseScore: 9 } }, { _id: "CVE-2" }] } },
  );
  assert.deepEqual(
    diffs.map((d) => d.path).sort(),
    ["vulnerabilitydetails.vulnerabilities[CVE-1].impact.baseScore", "vulnerabilitydetails.vulnerabilities[CVE-2]"],
  );
});

test("dependency graph nodes are keyed, not compared by index", () => {
  const node = (name) => ({ system: "maven", name, version: "1", relation: "DIRECT" });
  const diffs = diffValues(
    { dependencyGraph: { nodes: [node("a"), node("b")] } },
    { dependencyGraph: { nodes: [node("b")] } },
  );
  assert.equal(diffs.length, 1);
  assert.equal(diffs[0].path, "dependencyGraph.nodes[maven|a|1|DIRECT]");
});
