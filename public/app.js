const form = document.querySelector("#form");
const purlInput = document.querySelector("#purl");
const go = document.querySelector("#go");
const statusEl = document.querySelector("#status");
const out = document.querySelector("#out");

const FIELD_ORDER = [
  "vulnerabilitydetails",
  "cves",
  "licenses",
  "latestversion",
  "latestversionreleasedate",
  "currentversionreleasedate",
  "isversionoutdated",
  "isversionunmaintained",
  "ismalicious",
  "abandoned",
  "squattedpackage",
  "directdependenciescount",
  "transitivedependenciescount",
  "dependenciesgraph",
  "eoldetails",
  "componentscore",
  "packagename",
  "version",
];

let seq = 0;

for (const button of document.querySelectorAll("[data-purl]")) {
  button.addEventListener("click", () => {
    purlInput.value = button.dataset.purl;
    purlInput.focus();
  });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = ++seq;
  const purl = purlInput.value.trim();
  const v1 = form.v1.checked;
  const v2 = form.v2.checked;
  const qwiet = form.qwiet.checked;
  const cds = form.cds.checked;
  const flags = {};
  for (const box of form.querySelectorAll("#flags input[type='checkbox']")) flags[box.name] = box.checked;
  const parts = [v1 && "Mongo v1", v2 && "Mongo v2", qwiet && "Qwiet", cds && "CDS"].filter(Boolean);
  if (!parts.length) {
    statusEl.className = "error";
    statusEl.textContent = "Pick at least one source.";
    return;
  }

  go.disabled = true;
  statusEl.className = "";
  statusEl.textContent = `Fetching ${parts.join(", ")}…`;
  out.hidden = true;

  try {
    const response = await fetch("/api/compare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ purl, v1, v2, qwiet, cds, flags }),
    });
    const data = await response.json();
    if (id !== seq) return;
    if (!response.ok) throw new Error(data.error || `request failed (${response.status})`);
    render(data);
    statusEl.textContent = "";
  } catch (err) {
    if (id !== seq) return;
    statusEl.className = "error";
    statusEl.textContent = err instanceof Error ? err.message : "request failed";
  } finally {
    if (id === seq) go.disabled = false;
  }
});

function render(data) {
  out.hidden = false;
  out.replaceChildren();

  const sources = el("div", "sources");
  if (data.v1) sources.append(sourceCard("Mongo v1", "v1", data.v1));
  if (data.v2) sources.append(sourceCard("Mongo v2", "v2", data.v2));
  if (data.qwiet) sources.append(sourceCard("Qwiet prod", "qwiet", data.qwiet));
  if (data.cds) sources.append(sourceCard("CDS QA", "cds", data.cds));
  out.append(sources);

  if (data.v1 && data.v2) {
    if (!data.diffs) out.append(el("p", "lede", "Diff needs a document from both Mongo collections."));
    else renderDiff(pairView(data, "mongo"));
  }
  if (data.qwiet && data.cds) {
    if (!data.liveDiffs) out.append(el("p", "lede", "Diff needs a package from both Qwiet and CDS."));
    else renderDiff(pairView(data, "live"));
  }
  if (data.v1 && data.qwiet) out.append(livePanel("Mongo v1 vs Qwiet", "CVE ids. Qwiet is the v1 writer.", data.ids.v1Cve, data.ids.qwiet, data.qwiet));
  if (data.v2 && data.cds) out.append(livePanel("Mongo v2 vs CDS", "CVE ids. CDS is the v2 writer.", data.ids.v2Cve, data.ids.cds, data.cds));
  out.append(rawDetails(data));
}

function pairView(data, kind) {
  if (kind === "mongo") {
    return {
      purl: data.purl,
      leftLabel: "Mongo v1",
      rightLabel: "Mongo v2",
      leftShort: "v1",
      rightShort: "v2",
      left: data.v1.body,
      right: data.v2.body,
      leftMeta: `${data.v1.found ? "found" : "missing"} in ${data.v1.ms}ms`,
      rightMeta: `${data.v2.found ? "found" : "missing"} in ${data.v2.ms}ms`,
      diffs: data.diffs,
      leftIds: data.ids.v1,
      rightIds: data.ids.v2,
    };
  }
  return {
    purl: data.purl,
    leftLabel: "Qwiet",
    rightLabel: "CDS",
    leftShort: "qwiet",
    rightShort: "cds",
    left: data.qwietPackage,
    right: data.cdsPackage,
    leftMeta: `${data.qwiet.ok ? "ok" : "failed"} in ${data.qwiet.ms}ms`,
    rightMeta: `${data.cds.ok ? "ok" : "failed"} in ${data.cds.ms}ms`,
    diffs: data.liveDiffs,
    leftIds: data.ids.qwietIds,
    rightIds: data.ids.cdsIds,
  };
}

function renderDiff(view) {
  const valueDiffs = view.diffs.filter((d) => d.kind === "value");
  const shapeDiffs = view.diffs.filter((d) => d.kind === "shape");
  out.append(cvePanel(view, valueDiffs));
  out.append(headline(view, valueDiffs));

  const block = el("details", "diffs");
  block.open = true;
  const summary = document.createElement("summary");
  summary.append(el("strong", "", `${valueDiffs.length} value difference${valueDiffs.length === 1 ? "" : "s"}`));
  summary.append(document.createTextNode(` · ${shapeDiffs.length} empty-shape`));
  block.append(summary);

  const bar = el("div", "toolbar");
  const controls = el("div");
  controls.style.display = "flex";
  controls.style.gap = "10px";
  controls.style.alignItems = "center";
  const shapeLabel = el("label");
  const shapeBox = document.createElement("input");
  shapeBox.type = "checkbox";
  shapeLabel.append(shapeBox, document.createTextNode("Show null / empty mismatches"));
  const filter = document.createElement("input");
  filter.id = "filter";
  filter.type = "text";
  filter.placeholder = "Filter paths";
  const copy = document.createElement("button");
  copy.type = "button";
  copy.textContent = "Copy diff";
  controls.append(shapeLabel, filter, copy);
  bar.append(controls);
  block.append(bar);

  const list = el("div");
  block.append(list);
  out.append(block);

  const draw = () => {
    const shown = view.diffs.filter((d) => {
      if (!shapeBox.checked && d.kind === "shape") return false;
      const q = filter.value.trim().toLowerCase();
      return !q || d.path.toLowerCase().includes(q);
    });
    drawDiffs(list, shown, view);
  };
  shapeBox.addEventListener("change", draw);
  filter.addEventListener("input", draw);
  copy.addEventListener("click", async () => {
    const shown = view.diffs.filter((d) => shapeBox.checked || d.kind === "value");
    await navigator.clipboard.writeText(markdown(view, shown));
    copy.textContent = "Copied";
    setTimeout(() => {
      copy.textContent = "Copy diff";
    }, 1200);
  });
  draw();
}

function sourceCard(name, cls, source) {
  const failed = source.ok === false || Boolean(source.error);
  const card = el("section", `source ${cls} ${failed || source.found === false ? "bad" : "ok"}`);
  card.append(el("p", "name", name));
  if (source.found === false && !source.error) {
    card.append(el("p", "stat", `not found · ${source.ms} ms`));
    return card;
  }
  const stat = source.status ? `${source.status} · ${source.ms} ms` : source.found ? `found · ${source.ms} ms` : `failed · ${source.ms} ms`;
  card.append(el("p", "stat", stat));
  if (source.lastModifiedAt) card.append(el("p", "", `modified ${when(source.lastModifiedAt)}`));
  if (source.error) card.append(el("p", "", source.error));
  else if (source.status && !source.ok) card.append(el("p", "", snippet(source.body)));
  else if (Array.isArray(source.body) || Array.isArray(source.body?.response)) {
    const list = Array.isArray(source.body) ? source.body : source.body.response;
    card.append(el("p", "", `${list.length} result${list.length === 1 ? "" : "s"}`));
  }
  return card;
}

function headline(view, valueDiffs) {
  const left = view.left;
  const right = view.right;
  const leftMal = maliciousOf(left);
  const rightMal = maliciousOf(right);
  const wrap = el("div", "headline");
  wrap.append(metric(view, "Vulns", countText(left), countText(left) !== countText(right), countText(right)));
  wrap.append(metric(view, "Licenses", join(left?.licenses), !sameList(left?.licenses, right?.licenses), join(right?.licenses)));
  wrap.append(metric(view, "Latest", latestOf(left) || "—", latestOf(left) !== latestOf(right), latestOf(right) || "—"));
  wrap.append(metric(view, "Malicious", leftMal == null ? "—" : String(leftMal), leftMal !== rightMal, rightMal == null ? "—" : String(rightMal)));
  wrap.append(metric(view, "Deps", depText(left), depText(left) !== depText(right), depText(right)));
  const fieldCount = new Set(valueDiffs.map((d) => d.path.split(/[.[]/)[0])).size;
  wrap.append(metric("Fields touched", String(fieldCount), fieldCount > 0, fieldCount ? "value diffs" : "match"));
  return wrap;
}

function cvePanel(view, diffs) {
  const report = idReport(view.leftIds, view.rightIds, diffs);
  const panel = el("section", "cve-panel");
  panel.append(el("h2", "", "Vulnerability ids"));
  panel.append(el("p", "lede", `${report.left} on ${view.leftShort}, ${report.right} on ${view.rightShort}, ${report.shared} on both.`));
  const columns = el("div", "id-lists");
  columns.append(idList(`Only on ${view.leftShort}`, report.onlyLeft), idList(`Only on ${view.rightShort}`, report.onlyRight));
  panel.append(columns);
  appendFieldDiffs(panel, report.fieldDiffs);
  return panel;
}

function livePanel(title, lede, storedIds, liveIds, source) {
  const panel = el("section", "cve-panel live-panel");
  panel.append(el("h2", "", title));
  if (!source.ok) {
    panel.append(el("p", "lede", source.error || `request failed (${source.status || 0})`));
    return panel;
  }
  const report = idReport(storedIds, liveIds, []);
  panel.append(el("p", "lede", `${lede} ${report.left} stored, ${report.right} live, ${report.shared} on both.`));
  const columns = el("div", "id-lists");
  columns.append(idList("Only stored", report.onlyLeft), idList("Only live", report.onlyRight));
  panel.append(columns);
  return panel;
}

function appendFieldDiffs(panel, fieldDiffs) {
  if (!fieldDiffs.size) return;
  const details = document.createElement("details");
  details.append(el("summary", "", `${fieldDiffs.size} shared vulnerabilities differ in other fields`));
  const ul = document.createElement("ul");
  for (const [id, fields] of [...fieldDiffs.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    ul.append(el("li", "mono", `${id} — ${fields.join(", ")}`));
  }
  details.append(ul);
  panel.append(details);
}

function idList(title, ids) {
  const block = el("div", "id-list");
  block.append(el("h3", "", `${title} (${ids.length})`));
  if (!ids.length) {
    block.append(el("p", "muted", "None"));
    return block;
  }
  const ul = document.createElement("ul");
  for (const id of ids) ul.append(el("li", "mono", id));
  block.append(ul);
  return block;
}

function idReport(leftIds, rightIds, diffs) {
  const left = new Set(leftIds || []);
  const right = new Set(rightIds || []);
  const fieldDiffs = new Map();
  for (const diff of diffs) {
    if (diff.kind !== "value") continue;
    const match = diff.path.match(/^vulnerabilitydetails\.vulnerabilities\[([^\]]+)\]\.(.+)$/);
    if (!match) continue;
    const fields = fieldDiffs.get(match[1]) || [];
    fields.push(match[2]);
    fieldDiffs.set(match[1], fields);
  }
  return {
    left: left.size,
    right: right.size,
    shared: [...left].filter((id) => right.has(id)).length,
    onlyLeft: [...left].filter((id) => !right.has(id)).sort(),
    onlyRight: [...right].filter((id) => !left.has(id)).sort(),
    fieldDiffs,
  };
}

function metric(view, label, leftText, differ, rightText) {
  const box = el("div", `metric${differ ? " diff" : ""}`);
  box.append(el("div", "k", label));
  const value = el("div", "v");
  value.append(el("span", "sub", `${view.leftShort}  ${leftText}`));
  value.append(document.createTextNode(`${view.rightShort}  ${rightText}`));
  box.append(value);
  return box;
}

function drawDiffs(container, diffs, view) {
  container.replaceChildren();
  if (!diffs.length) {
    container.append(el("p", "empty", "No differences in this view."));
    return;
  }
  const groups = new Map();
  for (const diff of diffs) {
    const top = diff.path.split(/[.[]/)[0] || "$";
    if (!groups.has(top)) groups.set(top, []);
    groups.get(top).push(diff);
  }
  const names = [...groups.keys()].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
  for (const name of names) {
    const rows = groups.get(name);
    const section = el("details", "group");
    section.open = true;
    const header = document.createElement("summary");
    header.append(el("h2", "", name), el("span", "count", `${rows.length}`));
    section.append(header);
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const hr = document.createElement("tr");
    for (const label of ["Path", view.leftLabel, view.rightLabel]) hr.append(el("th", "", label));
    thead.append(hr);
    table.append(thead);
    const tbody = document.createElement("tbody");
    for (const diff of rows) {
      const tr = document.createElement("tr");
      const path = el("td", "path mono");
      path.append(document.createTextNode(diff.path));
      if (diff.kind === "shape") path.append(el("span", "kind", "shape"));
      tr.append(path, valueCell(diff, "left"), valueCell(diff, "right"));
      tbody.append(tr);
    }
    table.append(tbody);
    section.append(table);
    container.append(section);
  }
}

function valueCell(diff, side) {
  const missing = side === "left" ? diff.leftMissing : diff.rightMissing;
  const value = side === "left" ? diff.left : diff.right;
  const td = el("td", "value mono");
  if (missing) {
    td.classList.add("missing");
    td.textContent = "missing";
    return td;
  }
  const text = value === null ? "null" : typeof value === "string" ? JSON.stringify(value) : JSON.stringify(value, null, 2);
  if (text.length > 280) {
    const details = document.createElement("details");
    details.append(el("summary", "", `${text.slice(0, 180)}…`));
    details.append(el("pre", "", text));
    td.append(details);
  } else {
    td.textContent = text;
  }
  return td;
}

function rawDetails(data) {
  const details = el("details", "raw");
  details.append(el("summary", "", "Raw documents"));
  const split = el("div", "split");
  if (data.v1) split.append(jsonBlock("Mongo v1", data.v1.body));
  if (data.v2) split.append(jsonBlock("Mongo v2", data.v2.body));
  if (data.qwiet) split.append(jsonBlock("Qwiet prod", data.qwiet.body));
  if (data.cds) split.append(jsonBlock("CDS QA", data.cds.body));
  details.append(split);
  return details;
}

function jsonBlock(title, body) {
  const wrap = el("div");
  wrap.append(el("p", "name", title));
  const text = JSON.stringify(body, null, 2) ?? "";
  wrap.append(el("pre", "", text.length > 400_000 ? `${text.slice(0, 400_000)}\n… truncated` : text));
  return wrap;
}

function markdown(view, diffs) {
  const report = idReport(view.leftIds, view.rightIds, diffs);
  const lines = [
    `# ${view.purl}`,
    "",
    `${view.leftLabel}: ${view.leftMeta}`,
    `${view.rightLabel}: ${view.rightMeta}`,
    "",
    `Vulnerability ids: ${report.left} on ${view.leftShort}, ${report.right} on ${view.rightShort}, ${report.shared} on both.`,
    `Only on ${view.leftShort}: ${report.onlyLeft.join(", ") || "none"}`,
    `Only on ${view.rightShort}: ${report.onlyRight.join(", ") || "none"}`,
    "",
    `| Path | ${view.leftLabel} | ${view.rightLabel} |`,
    `| --- | --- | --- |`,
  ];
  for (const diff of diffs) {
    lines.push(`| ${cell(diff.path)} | ${cell(sideText(diff, "left"))} | ${cell(sideText(diff, "right"))} |`);
  }
  if (!diffs.length) lines.push("| — | match | match |");
  return lines.join("\n");
}

function sideText(diff, side) {
  const missing = side === "left" ? diff.leftMissing : diff.rightMissing;
  if (missing) return "missing";
  const value = side === "left" ? diff.left : diff.right;
  const text = JSON.stringify(value);
  return text.length > 300 ? `${text.slice(0, 300)}…` : text;
}

function cell(text) {
  return String(text ?? "").replaceAll("|", "\\|").replaceAll("\n", " ");
}

function join(list) {
  return Array.isArray(list) && list.length ? [...list].sort().join(", ") : "—";
}

function sameList(a, b) {
  return join(a) === join(b);
}

function countText(doc) {
  const counts = doc?.vulnerabilitydetails;
  if (counts && counts.totalCount != null) return String(counts.totalCount);
  if (Array.isArray(doc?.cves)) return String(doc.cves.length);
  return "—";
}

function latestOf(doc) {
  return doc?.latestversion || doc?.latestVersion || "";
}

function maliciousOf(doc) {
  if (!doc) return null;
  if ("ismalicious" in doc) return Boolean(doc.ismalicious);
  if ("isMalicious" in doc) return Boolean(doc.isMalicious);
  return null;
}

function depText(doc) {
  const direct = doc?.directdependenciescount ?? doc?.directDependenciesCount;
  const trans = doc?.transitivedependenciescount ?? doc?.transitiveDependenciesCount;
  if (direct == null && trans == null) return "—";
  return `${direct ?? 0} direct / ${trans ?? 0} transitive`;
}

function when(ms) {
  return `${new Date(ms).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

function rank(name) {
  const key = name.toLowerCase();
  const i = FIELD_ORDER.findIndex((field) => field.toLowerCase() === key);
  return i === -1 ? FIELD_ORDER.length : i;
}

function snippet(body) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return (text || "").slice(0, 240);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}
