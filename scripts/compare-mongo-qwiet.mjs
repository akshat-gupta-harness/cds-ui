#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { compareMongoQwiet, hasMongoQwietDiff } from "../lib/compare.mjs";
import { loadEnv } from "../lib/env.mjs";
import { pickPackage } from "../lib/diff.mjs";
import { loadMongoV1 } from "../lib/mongo.mjs";
import { callQwiet } from "../lib/upstream.mjs";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const FLAG_NAMES = [
  "include_latest_version",
  "include_eol",
  "include_dependency_graph",
  "include_package_score",
  "refresh_cache",
  "refresh_package_score",
];

const { values } = parseArgs({
  options: {
    suite: { type: "string", default: "all" },
    fixture: { type: "string" },
    purl: { type: "string" },
    json: { type: "boolean", default: false },
    verbose: { type: "boolean", short: "v", default: false },
    "all-rows": { type: "boolean", default: false },
    concurrency: { type: "string", default: "2" },
    help: { type: "boolean", short: "h", default: false },
  },
  allowPositionals: false,
});

if (values.help) {
  console.log(usage());
  process.exit(0);
}

loadEnv(path.join(root, ".env"));

const missing = ["MONGO_URI", "QWIET_URL", "QWIET_TOKEN"].filter((key) => !process.env[key]);
if (missing.length) {
  console.error(`missing in .env: ${missing.join(", ")}`);
  process.exit(2);
}

const suite = values.suite;
if (!["all", "cves", "licenses"].includes(suite)) {
  console.error(`unknown --suite ${suite} (use all, cves, licenses)`);
  process.exit(2);
}

const checkCves = suite === "all" || suite === "cves";
const checkLicenses = suite === "all" || suite === "licenses";
const purls = values.purl ? [values.purl.trim()] : loadFixturePurls(values.fixture, suite);
const concurrency = Math.max(1, Number(values.concurrency) || 2);
const flags = {};
for (const name of FLAG_NAMES) flags[name] = false;

const qwietHeaders = {
  "Content-Type": "application/json",
  Accept: "application/json",
  "X-Harness-Token": process.env.QWIET_TOKEN,
  ...(process.env.QWIET_COOKIE ? { Cookie: process.env.QWIET_COOKIE } : {}),
};

const rows = await mapPool(purls, concurrency, async (purl) => await compareOne(purl, { checkCves, checkLicenses, flags, qwietHeaders }));

const summary = {
  suite,
  purls: purls.length,
  mongoMissing: rows.filter((r) => !r.mongo.found).length,
  qwietFailed: rows.filter((r) => !r.qwiet.ok).length,
  licenseDiffs: rows.filter((r) => r.diff?.licenses && !r.diff.licenses.match).length,
  cveDiffs: rows.filter((r) => r.diff?.cveIds && (r.diff.cveIds.onlyMongo.length || r.diff.cveIds.onlyQwiet.length)).length,
  vulnIdDiffs: rows.filter(
    (r) => r.diff?.vulnerabilityIds && (r.diff.vulnerabilityIds.onlyMongo.length || r.diff.vulnerabilityIds.onlyQwiet.length),
  ).length,
};

if (values.json) {
  console.log(JSON.stringify({ summary, rows }, null, 2));
} else {
  printText(summary, rows, { verbose: values.verbose, allRows: values["all-rows"], checkCves, checkLicenses });
}

const anyDiff = rows.some((r) => r.diff && hasMongoQwietDiff(r.diff, { checkCves, checkLicenses }));
const anyError = rows.some((r) => !r.mongo.ok || !r.mongo.found || !r.qwiet.ok);
process.exit(anyError ? 2 : anyDiff ? 1 : 0);

async function compareOne(purl, { checkCves, checkLicenses, flags, qwietHeaders }) {
  const [mongo, qwiet] = await Promise.all([
    loadMongoV1(purl),
    callQwiet(process.env.QWIET_URL, flags, purl, qwietHeaders),
  ]);
  const qwietPkg = qwiet.body == null ? null : pickPackage(qwiet.body, purl);
  const diff =
    mongo.found && qwiet.ok && qwietPkg
      ? compareMongoQwiet(mongo.body, qwietPkg, { checkCves, checkLicenses })
      : null;
  return { purl, mongo, qwiet, qwietPkg, diff };
}

function loadFixturePurls(fixturePath, suite) {
  const file =
    fixturePath ||
    process.env.ENRICHMENT_PURLS_FIXTURE ||
    path.join(root, "fixtures", "enrichment-report-purls.json");
  const raw = JSON.parse(fs.readFileSync(file, "utf8"));
  const cves = raw.suites?.cves || [];
  const licenses = raw.suites?.licenses || [];
  if (suite === "cves") return cves;
  if (suite === "licenses") return licenses;
  return [...new Set([...cves, ...licenses])];
}

function printText(summary, rows, { verbose, allRows, checkCves, checkLicenses }) {
  console.log(`Mongo v1 (componentEnrichment) vs Qwiet — suite=${summary.suite}, ${summary.purls} purls\n`);
  console.log(
    `mongo missing ${summary.mongoMissing} · qwiet errors ${summary.qwietFailed} · license diffs ${summary.licenseDiffs} · CVE diffs ${summary.cveDiffs} · vuln-id diffs ${summary.vulnIdDiffs}\n`,
  );

  for (const row of rows) {
    const show =
      allRows ||
      verbose ||
      !row.mongo.found ||
      !row.qwiet.ok ||
      (row.diff && hasMongoQwietDiff(row.diff, { checkCves, checkLicenses }));
    if (!show) continue;

    console.log(row.purl);
    if (!row.mongo.found) console.log(`  mongo: ${row.mongo.error || "not found"} (${row.mongo.ms} ms)`);
    if (!row.qwiet.ok) console.log(`  qwiet: ${row.qwiet.error || `HTTP ${row.qwiet.status}`} (${row.qwiet.ms} ms)`);
    if (!row.diff) {
      console.log("");
      continue;
    }

    if (checkLicenses && row.diff.licenses && !row.diff.licenses.match) {
      console.log(`  licenses mongo: ${fmtList(row.diff.licenses.mongo)}`);
      console.log(`  licenses qwiet: ${fmtList(row.diff.licenses.qwiet)}`);
    } else if (verbose && checkLicenses && row.diff.licenses?.match) {
      console.log(`  licenses: match (${fmtList(row.diff.licenses.mongo)})`);
    }

    if (checkCves) {
      printIdDiff("CVE ids", row.diff.cveIds, verbose);
      printIdDiff("vuln ids (CVE/GHSA/MAL)", row.diff.vulnerabilityIds, verbose);
    }
    console.log("");
  }
}

function printIdDiff(label, diff, verbose) {
  if (!diff) return;
  const changed = diff.onlyMongo.length || diff.onlyQwiet.length;
  if (!changed && !verbose) return;
  if (!changed) {
    console.log(`  ${label}: match (${diff.left})`);
    return;
  }
  console.log(`  ${label}: mongo ${diff.left}, qwiet ${diff.right}, shared ${diff.shared}`);
  if (diff.onlyMongo.length) console.log(`    only mongo: ${diff.onlyMongo.join(", ")}`);
  if (diff.onlyQwiet.length) console.log(`    only qwiet: ${diff.onlyQwiet.join(", ")}`);
}

function fmtList(list) {
  return list.length ? list.join(", ") : "(empty)";
}

async function mapPool(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
  return out;
}

function usage() {
  return `compare Mongo componentEnrichment (v1) with live Qwiet package_info

Usage:
  node scripts/compare-mongo-qwiet.mjs [options]

Options:
  --suite all|cves|licenses   PURL set from fixtures (default all)
  --fixture <path>            JSON fixture (default fixtures/enrichment-report-purls.json)
  --purl <purl>               Single PURL instead of fixture
  --concurrency <n>           Parallel qwiet/mongo fetches (default 2)
  --json                      Machine-readable output
  --verbose, -v               Print matches too
  --all-rows                  Print every PURL row
  --help, -h

Exit codes: 0 match, 1 diff, 2 setup/request/mongo error

Env (.env): MONGO_URI, MONGO_DB (optional), QWIET_URL, QWIET_TOKEN, QWIET_COOKIE (optional)
Fixture source: component-data-service docs enrichment-v1-v2-cves.md / licenses.md
`;
}
