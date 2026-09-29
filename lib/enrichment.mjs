const ROOT_DROP = new Set(["_id", "uuid", "createdat", "lastmodifiedat"]);

export function cleanDoc(doc) {
  return walk(doc, true);
}

function walk(value, root) {
  if (Array.isArray(value)) return value.map((item) => walk(item, false));
  if (value instanceof Date) return value.toISOString();
  if (!value || typeof value !== "object") return value;
  if (typeof value.toHexString === "function") return undefined;
  const out = {};
  for (const [key, child] of Object.entries(value)) {
    if (key === "_class") continue;
    if (root && ROOT_DROP.has(key)) continue;
    const next = walk(child, false);
    if (next !== undefined) out[key] = next;
  }
  return out;
}

export function vulnerabilityIds(doc) {
  const vulns = doc?.vulnerabilitydetails?.vulnerabilities;
  if (!Array.isArray(vulns)) return [];
  return [...new Set(vulns.map((vuln) => vuln?._id).filter((id) => typeof id === "string" && id))].sort();
}

export function cveIds(doc) {
  const vulns = doc?.vulnerabilitydetails?.vulnerabilities;
  if (!Array.isArray(vulns)) return [];
  const out = new Set();
  for (const vuln of vulns) {
    addCve(out, vuln?._id);
    for (const ref of vuln?.referenceIdentifiers || []) {
      if (String(ref?.type || "").toLowerCase() === "cve") addCve(out, ref?._id);
    }
  }
  return [...out].sort();
}

export function packageCveIds(pkg) {
  const out = new Set();
  for (const cve of pkg?.cves || []) addCve(out, cve?.id);
  return [...out].sort();
}

export function packageVulnerabilityIds(pkg) {
  const out = new Set();
  for (const cve of pkg?.cves || []) {
    const id = cve?.id;
    if (typeof id === "string" && id) out.add(id);
  }
  return [...out].sort();
}

export function licenseList(value) {
  if (!Array.isArray(value)) return [];
  return [...value].filter((item) => typeof item === "string" && item).sort();
}

function addCve(out, raw) {
  if (raw == null || raw === "") return;
  let id = String(raw).toUpperCase();
  if (!id.startsWith("CVE-")) {
    if (/^\d{4}-\d+$/.test(id)) id = `CVE-${id}`;
    else return;
  }
  out.add(id);
}
