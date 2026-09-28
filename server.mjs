import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { diffValues, pickPackage } from "./lib/diff.mjs";

const root = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(root, "public");

loadEnv(path.join(root, ".env"));

const port = Number(process.env.PORT || 4173);
const cdsURL = process.env.CDS_URL;
const qwietURL = process.env.QWIET_URL;
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
  const missing = ["CDS_URL", "CDS_API_KEY", "QWIET_URL", "QWIET_TOKEN"].filter((key) => !process.env[key]);
  if (missing.length) {
    sendJSON(res, 500, { error: `missing ${missing.join(", ")} in .env` });
    return;
  }

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

  const flags = {};
  for (const name of FLAG_NAMES) flags[name] = Boolean(payload.flags?.[name]);

  const [cds, qwiet] = await Promise.all([
    callUpstream(cdsURL, flags, purl, {
      "Content-Type": "application/json",
      Accept: "application/json",
      "x-api-key": process.env.CDS_API_KEY,
    }),
    callUpstream(qwietURL, flags, purl, {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Harness-Token": process.env.QWIET_TOKEN,
      ...(process.env.QWIET_COOKIE ? { Cookie: process.env.QWIET_COOKIE } : {}),
    }),
  ]);

  const cdsPackage = cds.body == null ? null : pickPackage(cds.body, purl);
  const qwietPackage = qwiet.body == null ? null : pickPackage(qwiet.body, purl);
  const diffs = cdsPackage != null && qwietPackage != null ? diffValues(cdsPackage, qwietPackage) : null;

  sendJSON(res, 200, { purl, flags, cds, qwiet, cdsPackage, qwietPackage, diffs });
}

async function callUpstream(base, flags, purl, headers) {
  const url = new URL(base);
  for (const [name, on] of Object.entries(flags)) {
    if (on) url.searchParams.set(name, "true");
  }
  const started = performance.now();
  try {
    // ponytail: Node fetch fails here with UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    // curl uses the macOS trust store and succeeds. Upgrade: switch back to
    // fetch once Node trusts the same issuers.
    const response = await curlPost(url, headers, JSON.stringify({ purls: [purl] }));
    let body = response.text;
    try {
      body = JSON.parse(response.text);
    } catch {
      body = { raw: response.text.slice(0, 4000) };
    }
    return {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      ms: Math.round(performance.now() - started),
      body,
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      ms: Math.round(performance.now() - started),
      error: err instanceof Error ? err.message : "request failed",
      body: null,
    };
  }
}

function curlPost(url, headers, body) {
  const args = ["-sS", "--max-time", "180", "-X", "POST", "-w", "\n__CDS_UI_STATUS__%{http_code}", String(url)];
  for (const [key, value] of Object.entries(headers)) {
    if (/[\r\n]/.test(key) || /[\r\n]/.test(value)) throw new Error("invalid header");
    args.push("-H", `${key}: ${value}`);
  }
  args.push("--data-binary", "@-");
  return new Promise((resolve, reject) => {
    const child = spawn("curl", args, { stdio: ["pipe", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    child.stdin.end(body);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(Buffer.concat(stderr).toString("utf8").trim() || `curl exited ${code}`));
        return;
      }
      const text = Buffer.concat(stdout).toString("utf8");
      const marker = "\n__CDS_UI_STATUS__";
      const at = text.lastIndexOf(marker);
      if (at < 0) {
        reject(new Error("curl response missing status"));
        return;
      }
      resolve({ status: Number(text.slice(at + marker.length)), text: text.slice(0, at) });
    });
  });
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

function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}
