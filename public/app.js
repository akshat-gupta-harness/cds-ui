const form = document.querySelector("#form");
const purlInput = document.querySelector("#purl");
const go = document.querySelector("#go");
const statusEl = document.querySelector("#status");
const out = document.querySelector("#out");

const FIELD_ORDER = [
  "error",
  "licenses",
  "cves",
  "isMalicious",
  "maliciousSource",
  "maliciousPackageReports",
  "squattedPackage",
  "abandoned",
  "repoHijackable",
  "publishDate",
  "publishDateEpoch",
  "latestVersion",
  "latestVersionPublishDate",
  "latestVersionPublishDateEpoch",
  "isDeprecated",
  "deprecatedReason",
  "directDependenciesCount",
  "transitiveDependenciesCount",
  "dependenciesSource",
  "dependencyGraph",
  "eolDetails",
  "packageScore",
];

let seq = 0;
let last = null;

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
  const flags = {};
  for (const box of form.querySelectorAll('input[type="checkbox"]')) flags[box.name] = box.checked;

  go.disabled = true;
  statusEl.className = "";
  statusEl.textContent = "Fetching CDS QA and Qwiet prod…";
  out.hidden = true;

  try {
    const response = await fetch("/api/compare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ purl, flags }),
    });
    const data = await response.json();
    if (id !== seq) return;
    if (!response.ok) throw new Error(data.error || `request failed (${response.status})`);
    last = data;
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
  sources.append(sourceCard("CDS QA", "cds", data.cds), sourceCard("Qwiet prod", "qwiet", data.qwiet));
  out.append(sources);

  if (!data.diffs) {
    out.append(el("p", "lede", "Diff needs a package object from both responses."));
    out.append(rawDetails(data));
    return;
  }

  const valueDiffs = data.diffs.filter((d) => d.kind === "value");
  const shapeDiffs = data.diffs.filter((d) => d.kind === "shape");

  out.append(cvePanel(data.cdsPackage, data.qwietPackage, valueDiffs));
  out.append(headline(data.cdsPackage, data.qwietPackage, valueDiffs));

  const bar = el("div", "toolbar");
  const meta = el("div");
  meta.append(el("strong", "", `${valueDiffs.length} value difference${valueDiffs.length === 1 ? "" : "s"}`));
  meta.append(document.createTextNode(` · ${shapeDiffs.length} empty-shape`));
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
  bar.append(meta, controls);
  out.append(bar);

  const list = el("div");
  out.append(list);
  out.append(rawDetails(data));

  const draw = () => {
    const shown = data.diffs.filter((d) => {
      if (!shapeBox.checked && d.kind === "shape") return false;
      const q = filter.value.trim().toLowerCase();
      return !q || d.path.toLowerCase().includes(q);
    });
    drawDiffs(list, shown);
  };
  shapeBox.addEventListener("change", draw);
  filter.addEventListener("input", draw);
  copy.addEventListener("click", async () => {
    const shown = data.diffs.filter((d) => shapeBox.checked || d.kind === "value");
    await navigator.clipboard.writeText(markdown(data, shown));
    copy.textContent = "Copied";
    setTimeout(() => {
      copy.textContent = "Copy diff";
    }, 1200);
  });
  draw();
}

function sourceCard(name, cls, source) {
  const card = el("section", `source ${cls} ${source.ok ? "ok" : "bad"}`);
  card.append(el("p", "name", name));
  const stat = source.status ? `${source.status} · ${source.ms} ms` : `failed · ${source.ms} ms`;
  card.append(el("p", "stat", stat));
  if (source.error) card.append(el("p", "", source.error));
  else if (!source.ok) card.append(el("p", "", snippet(source.body)));
  else {
    const list = Array.isArray(source.body) ? source.body : source.body?.response;
    const count = Array.isArray(list) ? `${list.length} result${list.length === 1 ? "" : "s"}` : "object";
    card.append(el("p", "", count));
  }
  return card;
}

function headline(left, right, valueDiffs) {
  const wrap = el("div", "headline");
  wrap.append(metric("Licenses", join(left?.licenses), !sameList(left?.licenses, right?.licenses), join(right?.licenses)));
  wrap.append(metric("Latest", left?.latestVersion || "—", (left?.latestVersion || "") !== (right?.latestVersion || ""), right?.latestVersion || "—"));
  wrap.append(metric("Malicious", String(Boolean(left?.isMalicious)), Boolean(left?.isMalicious) !== Boolean(right?.isMalicious), String(Boolean(right?.isMalicious))));
  wrap.append(metric("Score", scoreText(left), scoreText(left) !== scoreText(right), scoreText(right)));
  wrap.append(metric("EOL", left?.eolDetails?.riskLevel || "—", (left?.eolDetails?.riskLevel || "") !== (right?.eolDetails?.riskLevel || ""), right?.eolDetails?.riskLevel || "—"));
  wrap.append(metric("Deps", depText(left), depText(left) !== depText(right), depText(right)));
  const fieldCount = new Set(valueDiffs.map((d) => d.path.split(/[.[]/)[0])).size;
  wrap.append(metric("Fields touched", String(fieldCount), fieldCount > 0, fieldCount ? "value diffs" : "match"));
  return wrap;
}

function cvePanel(left, right, diffs) {
  const report = cveReport(left, right, diffs);
  const panel = el("section", "cve-panel");
  panel.append(el("h2", "", "CVE ids"));
  panel.append(
    el(
      "p",
      "lede",
      `${report.cds} on CDS, ${report.qwiet} on Qwiet, ${report.shared} on both.`,
    ),
  );
  const columns = el("div", "id-lists");
  columns.append(idList("Only on CDS", report.onlyCds), idList("Only on Qwiet", report.onlyQwiet));
  panel.append(columns);
  if (report.fieldDiffs.size) {
    const details = document.createElement("details");
    details.append(el("summary", "", `${report.fieldDiffs.size} shared CVEs differ in other fields`));
    const ul = document.createElement("ul");
    for (const [id, fields] of [...report.fieldDiffs.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      ul.append(el("li", "mono", `${id} — ${fields.join(", ")}`));
    }
    details.append(ul);
    panel.append(details);
  }
  return panel;
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

function cveReport(left, right, diffs) {
  const cds = idSet(left?.cves);
  const qwiet = idSet(right?.cves);
  const fieldDiffs = new Map();
  for (const diff of diffs) {
    if (diff.kind !== "value") continue;
    const match = diff.path.match(/^cves\[([^\]]+)\]\.(.+)$/);
    if (!match) continue;
    const fields = fieldDiffs.get(match[1]) || [];
    fields.push(match[2]);
    fieldDiffs.set(match[1], fields);
  }
  return {
    cds: cds.size,
    qwiet: qwiet.size,
    shared: [...cds].filter((id) => qwiet.has(id)).length,
    onlyCds: [...cds].filter((id) => !qwiet.has(id)).sort(),
    onlyQwiet: [...qwiet].filter((id) => !cds.has(id)).sort(),
    fieldDiffs,
  };
}

function metric(label, cdsText, differ, qwietText) {
  const box = el("div", `metric${differ ? " diff" : ""}`);
  box.append(el("div", "k", label));
  const value = el("div", "v");
  value.append(el("span", "sub", `CDS  ${cdsText}`));
  value.append(document.createTextNode(`Qwiet  ${qwietText}`));
  box.append(value);
  return box;
}

function drawDiffs(container, diffs) {
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
    const section = el("section", "group");
    const header = document.createElement("header");
    header.append(el("h2", "", name), el("span", "", `${rows.length}`));
    section.append(header);
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const hr = document.createElement("tr");
    for (const label of ["Path", "CDS QA", "Qwiet prod"]) hr.append(el("th", "", label));
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
  details.append(el("summary", "", "Raw responses"));
  const split = el("div", "split");
  split.append(jsonBlock("CDS QA", data.cds.body), jsonBlock("Qwiet prod", data.qwiet.body));
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

function markdown(data, diffs) {
  const report = cveReport(data.cdsPackage, data.qwietPackage, diffs);
  const lines = [
    `# ${data.purl}`,
    "",
    `CDS QA: ${data.cds.status || "error"} in ${data.cds.ms}ms`,
    `Qwiet prod: ${data.qwiet.status || "error"} in ${data.qwiet.ms}ms`,
    "",
    `CVEs: ${report.cds} on CDS, ${report.qwiet} on Qwiet, ${report.shared} on both.`,
    `Only on CDS: ${report.onlyCds.join(", ") || "none"}`,
    `Only on Qwiet: ${report.onlyQwiet.join(", ") || "none"}`,
    "",
    `| Path | CDS QA | Qwiet prod |`,
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

function idSet(cves) {
  return new Set((cves || []).map((cve) => cve?.id).filter(Boolean));
}

function join(list) {
  return Array.isArray(list) && list.length ? [...list].sort().join(", ") : "—";
}

function sameList(a, b) {
  return join(a) === join(b);
}

function scoreText(pkg) {
  const score = pkg?.packageScore;
  if (!score) return "—";
  return `${score.compositeScore ?? "—"} (${score.status || "?"})`;
}

function depText(pkg) {
  if (pkg?.directDependenciesCount == null && pkg?.transitiveDependenciesCount == null) return "—";
  return `${pkg.directDependenciesCount ?? 0} direct / ${pkg.transitiveDependenciesCount ?? 0} transitive`;
}

function rank(name) {
  const i = FIELD_ORDER.indexOf(name);
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
