import assert from "node:assert/strict";
import test from "node:test";
import { cleanDoc, cveIds, licenseList, packageCveIds, packageVulnerabilityIds, vulnerabilityIds } from "./enrichment.mjs";

test("cleanDoc drops identity, timestamps, and mongo class markers", () => {
  const cleaned = cleanDoc({
    _id: { toHexString: () => "abc" },
    uuid: "u",
    createdat: 1,
    lastmodifiedat: 2,
    purl: "pkg:npm/left-pad@1.0.0",
    vulnerabilitydetails: {
      _class: "bean",
      vulnerabilities: [{ _id: "GHSA-1", _class: "vuln" }],
    },
  });
  assert.deepEqual(cleaned, {
    purl: "pkg:npm/left-pad@1.0.0",
    vulnerabilitydetails: { vulnerabilities: [{ _id: "GHSA-1" }] },
  });
});

test("vulnerability ids stay distinct from canonical CVE ids", () => {
  const doc = {
    vulnerabilitydetails: {
      vulnerabilities: [
        { _id: "GHSA-1", referenceIdentifiers: [{ _id: "2024-1", type: "cve" }] },
        { _id: "CVE-2024-2" },
        { _id: "MAL-1" },
      ],
    },
  };
  assert.deepEqual(vulnerabilityIds(doc), ["CVE-2024-2", "GHSA-1", "MAL-1"]);
  assert.deepEqual(cveIds(doc), ["CVE-2024-1", "CVE-2024-2"]);
});

test("package CVE ids ignore non-CVE identifiers", () => {
  assert.deepEqual(packageCveIds({ cves: [{ id: "CVE-1" }, { id: "GHSA-1" }, { id: "" }] }), ["CVE-1"]);
});

test("package vulnerability ids include GHSA entries", () => {
  assert.deepEqual(packageVulnerabilityIds({ cves: [{ id: "GHSA-1" }, { id: "CVE-1" }] }), ["CVE-1", "GHSA-1"]);
});

test("licenseList normalizes string arrays", () => {
  assert.deepEqual(licenseList(["MIT", "", "BSD-3-Clause"]), ["BSD-3-Clause", "MIT"]);
});
