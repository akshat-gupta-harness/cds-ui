import { spawn } from "node:child_process";

export async function callQwiet(base, flags, purl, headers) {
  const url = new URL(base);
  for (const [name, on] of Object.entries(flags)) {
    if (on) url.searchParams.set(name, "true");
  }
  const started = performance.now();
  try {
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
