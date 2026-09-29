import { cleanDoc, cveIds, licenseList, packageCveIds, packageVulnerabilityIds, vulnerabilityIds } from "./enrichment.mjs";

export function idSetDiff(leftIds, rightIds) {
  const left = new Set(leftIds || []);
  const right = new Set(rightIds || []);
  return {
    left: left.size,
    right: right.size,
    shared: [...left].filter((id) => right.has(id)).length,
    onlyMongo: [...left].filter((id) => !right.has(id)).sort(),
    onlyQwiet: [...right].filter((id) => !left.has(id)).sort(),
  };
}

export function compareMongoQwiet(mongoBody, qwietPkg, { checkLicenses = true, checkCves = true } = {}) {
  const mongo = mongoBody ? cleanDoc(mongoBody) : null;
  const out = { licenses: null, cveIds: null, vulnerabilityIds: null };

  if (checkLicenses) {
    const mongoLicenses = licenseList(mongo?.licenses);
    const qwietLicenses = licenseList(qwietPkg?.licenses);
    const match = stableList(mongoLicenses) === stableList(qwietLicenses);
    out.licenses = {
      match,
      mongo: mongoLicenses,
      qwiet: qwietLicenses,
    };
  }

  if (checkCves) {
    out.cveIds = idSetDiff(cveIds(mongo), packageCveIds(qwietPkg));
    out.vulnerabilityIds = idSetDiff(vulnerabilityIds(mongo), packageVulnerabilityIds(qwietPkg));
  }

  return out;
}

export function hasMongoQwietDiff(compare, { checkLicenses = true, checkCves = true } = {}) {
  if (checkLicenses && compare.licenses && !compare.licenses.match) return true;
  if (!checkCves) return false;
  if (compare.cveIds?.onlyMongo.length || compare.cveIds?.onlyQwiet.length) return true;
  if (compare.vulnerabilityIds?.onlyMongo.length || compare.vulnerabilityIds?.onlyQwiet.length) return true;
  return false;
}

function stableList(list) {
  return JSON.stringify(list);
}
