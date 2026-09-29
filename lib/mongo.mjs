import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));

export function loadMongoV1(purl) {
  return loadEnrichment("componentEnrichment", purl);
}

export function loadEnrichment(collection, purl) {
  const started = performance.now();
  return new Promise((resolve) => {
    const child = spawn("python3", [path.join(root, "mongo_fetch.py")], {
      env: {
        ...process.env,
        PYTHONWARNINGS: "ignore",
        CDS_UI_COLLECTION: collection,
        CDS_UI_PURL: purl,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", (err) => {
      resolve(mongoFailure(started, err.message));
    });
    child.on("close", (code) => {
      if (code !== 0) {
        resolve(mongoFailure(started, Buffer.concat(stderr).toString("utf8").trim() || `mongo fetch exited ${code}`));
        return;
      }
      try {
        const doc = JSON.parse(Buffer.concat(stdout).toString("utf8") || "null");
        resolve({
          ok: true,
          found: Boolean(doc),
          ms: Math.round(performance.now() - started),
          body: doc,
        });
      } catch (err) {
        resolve(mongoFailure(started, err instanceof Error ? err.message : "bad mongo response"));
      }
    });
  });
}

function mongoFailure(started, error) {
  return {
    ok: false,
    found: false,
    ms: Math.round(performance.now() - started),
    error,
    body: null,
  };
}
