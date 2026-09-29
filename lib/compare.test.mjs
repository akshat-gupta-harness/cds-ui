import assert from "node:assert/strict";
import test from "node:test";
import { compareMongoQwiet, hasMongoQwietDiff } from "./compare.mjs";

test("compareMongoQwiet reports license and vuln drift", () => {
  const mongo = {
    licenses: ["MIT"],
    vulnerabilitydetails: {
      vulnerabilities: [{ _id: "GHSA-1" }, { _id: "CVE-2024-1" }],
    },
  };
  const qwiet = {
    licenses: ["Apache-2.0"],
    cves: [{ id: "CVE-2024-1" }, { id: "CVE-2024-2" }],
  };
  const diff = compareMongoQwiet(mongo, qwiet);
  assert.equal(diff.licenses.match, false);
  assert.deepEqual(diff.cveIds.onlyMongo, []);
  assert.deepEqual(diff.cveIds.onlyQwiet, ["CVE-2024-2"]);
  assert.deepEqual(diff.vulnerabilityIds.onlyMongo, ["GHSA-1"]);
  assert.deepEqual(diff.vulnerabilityIds.onlyQwiet, ["CVE-2024-2"]);
  assert.equal(hasMongoQwietDiff(diff), true);
});

test("hasMongoQwietDiff is false when both sides align", () => {
  const mongo = {
    licenses: ["MIT"],
    vulnerabilitydetails: { vulnerabilities: [{ _id: "CVE-2024-1" }] },
  };
  const qwiet = { licenses: ["MIT"], cves: [{ id: "CVE-2024-1" }] };
  const diff = compareMongoQwiet(mongo, qwiet);
  assert.equal(hasMongoQwietDiff(diff), false);
});
