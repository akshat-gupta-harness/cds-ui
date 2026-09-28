// Deep diff for package_info payloads.
// ponytail: string arrays are compared as sorted multisets, so order-only
// differences (license list order) are hidden. Upgrade: emit an order entry
// when the sorted copies match but the sequences do not.

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isEmptyish(v) {
  if (v == null || v === "") return true;
  if (Array.isArray(v)) return v.length === 0;
  if (isPlainObject(v)) return Object.keys(v).length === 0;
  return false;
}

function stable(v) {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (isPlainObject(v)) {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stable(v[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

function same(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (typeof a !== "object" || typeof b !== "object") return false;
  return stable(a) === stable(b);
}

function itemKey(item) {
  if (!item || typeof item !== "object" || Array.isArray(item)) return null;
  if (typeof item.id === "string" && item.id) return `id:${item.id}`;
  if (item.system && item.name) {
    return `node:${item.system}|${item.name}|${item.version ?? ""}|${item.relation ?? ""}`;
  }
  if ("fromNode" in item && "toNode" in item) {
    return `edge:${item.fromNode}>${item.toNode}:${item.requirement ?? ""}`;
  }
  if (item.url && item.type) return `ref:${item.type}|${item.url}`;
  if (item.lang && item.value) return `desc:${item.lang}|${item.value}`;
  if (item.category && item.message) return `finding:${item.category}|${item.message}`;
  return null;
}

function isKeyable(arr) {
  return Array.isArray(arr) && arr.length > 0 && arr.every((item) => itemKey(item));
}

function isStringArray(arr) {
  return Array.isArray(arr) && arr.every((item) => typeof item === "string");
}

function entry(path, kind, left, right) {
  return {
    path: path || "$",
    kind,
    left: left === undefined ? null : left,
    right: right === undefined ? null : right,
    leftMissing: left === undefined,
    rightMissing: right === undefined,
  };
}

function diffKeyed(left, right, path, out) {
  const lm = new Map();
  const rm = new Map();
  for (const item of left) lm.set(itemKey(item), item);
  for (const item of right) rm.set(itemKey(item), item);
  const keys = [...new Set([...lm.keys(), ...rm.keys()])].sort();
  for (const key of keys) {
    const label = key.slice(key.indexOf(":") + 1);
    const seg = `${path}[${label}]`;
    const l = lm.get(key);
    const r = rm.get(key);
    if (l === undefined || r === undefined) out.push(entry(seg, "value", l, r));
    else walk(l, r, seg, out);
  }
}

function walk(left, right, path, out) {
  if (same(left, right)) return;

  if (isEmptyish(left) && isEmptyish(right)) {
    out.push(entry(path, "shape", left, right));
    return;
  }

  const leftArr = Array.isArray(left) || left == null;
  const rightArr = Array.isArray(right) || right == null;
  if (leftArr && rightArr && (isKeyable(left) || isKeyable(right))) {
    diffKeyed(Array.isArray(left) ? left : [], Array.isArray(right) ? right : [], path, out);
    return;
  }

  if ((isStringArray(left) || left == null) && (isStringArray(right) || right == null)) {
    const ls = Array.isArray(left) ? [...left].sort() : [];
    const rs = Array.isArray(right) ? [...right].sort() : [];
    if (!isEmptyish(left) || !isEmptyish(right)) {
      if (stable(ls) !== stable(rs)) out.push(entry(path, "value", left, right));
    }
    return;
  }

  if (isPlainObject(left) && isPlainObject(right)) {
    const keys = [...new Set([...Object.keys(left), ...Object.keys(right)])].sort();
    for (const key of keys) {
      walk(left[key], right[key], path ? `${path}.${key}` : key, out);
    }
    return;
  }

  out.push(entry(path, "value", left, right));
}

export function diffValues(left, right) {
  const out = [];
  walk(left, right, "", out);
  return out;
}

export function pickPackage(body, purl) {
  if (Array.isArray(body)) {
    return body.find((item) => item && item.purl === purl) ?? body[0] ?? null;
  }
  if (body && typeof body === "object") {
    if (Array.isArray(body.response)) return pickPackage(body.response, purl);
    if (body.purl) return body;
    if (Array.isArray(body.results)) return pickPackage(body.results, purl);
    if (Array.isArray(body.packages)) return pickPackage(body.packages, purl);
  }
  return body ?? null;
}
