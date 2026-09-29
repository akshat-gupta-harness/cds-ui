import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { diffValues, pickPackage } from "./lib/diff.mjs";
import { loadEnv } from "./lib/env.mjs";
import { cleanDoc, cveIds, packageCveIds, vulnerabilityIds } from "./lib/enrichment.mjs";
import { loadEnrichment } from "./lib/mongo.mjs";
import { callQwiet } from "./lib/upstream.mjs";

const root = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(root, "public");

loadEnv(path.join(root, ".env"));

const port = Number(process.env.PORT || 4173);
const cdsURL = process.env.CDS_URL;
const qwietURL = process.env.QWIET_URL;
const V1_COLLECTION = "componentEnrichment";
const V2_COLLECTION = "componentEnrichmentV2";
const FLAG_NAMES = [
  "include_latest_version",
  "include_eol",
  "include_dependency_graph",
  "include_package_score",
  "refresh_cache",
  "refresh_package_score",
];

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === "POST" && url.pathname === "/api/compare") {
      await compare(req, res);
      return;
    }
    if (req.method === "GET") {
      serveStatic(url.pathname, res);
      return;
    }
    sendJSON(res, 405, { error: "method not allowed" });
  } catch (err) {
    sendJSON(res, 500, { error: err instanceof Error ? err.message : "server error" });
  }
});

server.requestTimeout = 200_000;
server.listen(port, "127.0.0.1", () => {
  console.log(`PURL compare  listening on ${port}`);
});

async function compare(req, res) {
  const raw = await readBody(req);
  let payload;
  try {
    payload = JSON.parse(raw || "{}");
  } catch {
    sendJSON(res, 400, { error: "body must be JSON" });
    return;
  }

  const purl = String(payload.purl || "").trim();
  if (!purl.startsWith("pkg:")) {
    sendJSON(res, 400, { error: "purl must start with pkg:" });
    return;
  }

  const wantV1 = payload.v1 !== false;
  const wantV2 = payload.v2 !== false;
  const wantCds = Boolean(payload.cds);
  const wantQwiet = Boolean(payload.qwiet);
  if (!wantV1 && !wantV2 && !wantCds && !wantQwiet) {
    sendJSON(res, 400, { error: "pick at least one source" });
    return;
  }
  const missing = [];
  if ((wantV1 || wantV2) && !process.env.MONGO_URI) missing.push("MONGO_URI");
  if (wantCds) missing.push(...["CDS_URL", "CDS_API_KEY"].filter((key) => !process.env[key]));
  if (wantQwiet) missing.push(...["QWIET_URL", "QWIET_TOKEN"].filter((key) => !process.env[key]));
  if (missing.length) {
    sendJSON(res, 500, { error: `missing ${missing.join(", ")} in .env` });
    return;
  }

  const flags = {};
  for (const name of FLAG_NAMES) flags[name] = Boolean(payload.flags?.[name]);

  const [v1, v2, cds, qwiet] = await Promise.all([
    wantV1 ? loadEnrichmentForApi(V1_COLLECTION, purl) : null,
    wantV2 ? loadEnrichmentForApi(V2_COLLECTION, purl) : null,
    wantCds
      ? callQwiet(cdsURL, flags, purl, {
          "Content-Type": "application/json",
          Accept: "application/json",
          "x-api-key": process.env.CDS_API_KEY,
        })
      : null,
    wantQwiet
      ? callQwiet(qwietURL, flags, purl, {
          "Content-Type": "application/json",
          Accept: "application/json",
          "X-Harness-Token": process.env.QWIET_TOKEN,
          ...(process.env.QWIET_COOKIE ? { Cookie: process.env.QWIET_COOKIE } : {}),
        })
      : null,
  ]);
  const cdsPackage = cds?.body == null ? null : pickPackage(cds.body, purl);
  const qwietPackage = qwiet?.body == null ? null : pickPackage(qwiet.body, purl);
  const diffs = v1?.body != null && v2?.body != null ? diffValues(v1.body, v2.body) : null;

  sendJSON(res, 200, {
    purl,
    flags,
    v1,
    v2,
    diffs,
    cds,
    qwiet,
    cdsPackage,
    qwietPackage,
    ids: {
      v1: wantV1 ? vulnerabilityIds(v1.body) : null,
      v2: wantV2 ? vulnerabilityIds(v2.body) : null,
      v1Cve: wantV1 ? cveIds(v1.body) : null,
      v2Cve: wantV2 ? cveIds(v2.body) : null,
      cds: wantCds ? packageCveIds(cdsPackage) : null,
      qwiet: wantQwiet ? packageCveIds(qwietPackage) : null,
    },
  });
}

async function loadEnrichmentForApi(collection, purl) {
  const result = await loadEnrichment(collection, purl);
  if (!result.ok) return result;
  const modified = Number(result.body?.lastmodifiedat);
  return {
    ...result,
    lastModifiedAt: Number.isFinite(modified) ? modified : null,
    body: result.body ? cleanDoc(result.body) : null,
  };
}

function serveStatic(pathname, res) {
  const rel = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const file = path.normalize(path.join(publicDir, rel));
  if (!file.startsWith(publicDir + path.sep) && file !== path.join(publicDir, "index.html")) {
    sendJSON(res, 404, { error: "not found" });
    return;
  }
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    sendJSON(res, 404, { error: "not found" });
    return;
  }
  const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };
  res.writeHead(200, {
    "Content-Type": types[path.extname(file)] || "application/octet-stream",
    "Cache-Control": "no-store",
  });
  fs.createReadStream(file).pipe(res);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 1_000_000) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJSON(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(json);
}

