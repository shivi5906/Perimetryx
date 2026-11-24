const $ = (selector) => document.querySelector(selector);
let activeScan = null;
let pollTimer = null;

async function api(url, options = {}) {
  const response = await fetch(`/api${url}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(
      typeof detail.detail === "string" ? detail.detail : response.statusText,
    );
  }
  return response.json();
}

function message(text, isError = false) {
  $("#message").textContent = text;
  $("#message").className = isError ? "error" : "";
}

function lines(id) {
  return $(id)
    .value.split("\n")
    .map((value) => value.trim())
    .filter(Boolean);
}

function scopeFromForm() {
  const domain = $("#rootDomain").value.trim().toLowerCase();
  const allowedDomains = lines("#allowedDomains");
  if (!allowedDomains.includes(domain)) allowedDomains.unshift(domain);
  return {
    domain,
    authorization_basis: $("#authorization").value,
    allowed_domains: allowedDomains,
    excluded: lines("#excludedDomains"),
    active_verification: false,
    max_requests_per_second: Number($("#rate").value),
    max_concurrent_connections: Number($("#concurrent").value),
    allowed_ports: [80, 443],
    user_agent: "Perimetryx/2.0 (+authorized scan; security contact required)",
  };
}

function render(data, diff, graph) {
  const assets = data.assets;
  const findings = data.findings;
  const highRisk = assets.filter((asset) =>
    ["high", "critical"].includes(asset.band),
  ).length;
  $("#metrics").innerHTML =
    `<article><small>ASSETS</small><b>${assets.length}</b></article><article><small>FINDINGS</small><b>${findings.length}</b></article><article><small>HIGH RISK</small><b>${highRisk}</b></article><article><small>NEW ASSETS</small><b>${diff.new_assets.length}</b></article>`;
  $("#assets").innerHTML =
    assets
      .map(
        (asset) =>
          `<tr><td>${asset.hostname}<br><small>${asset.source}</small></td><td>${asset.environment}</td><td>${asset.status_code || "—"}</td><td class="risk ${asset.band || "low"}">${asset.total ?? 0} ${asset.band || "low"}</td></tr>`,
      )
      .join("") ||
    '<tr><td colspan="4">No in-scope assets were recorded.</td></tr>';
  $("#diff").innerHTML = diff.from_scan_id
    ? `<b>${diff.new_assets.length} new</b>, ${diff.removed_assets.length} removed<br><small>${diff.new_assets.join(", ") || "No new assets"}</small>`
    : "This is the first completed scan.";
  $("#graph").innerHTML =
    graph.nodes
      .map(
        (node) => `<span class="node ${node.risk || ""}">${node.label}</span>`,
      )
      .join("") || "No observed relations";
}

async function load() {
  activeScan = Number($("#scanId").value);
  if (!activeScan) throw new Error("Enter a scan ID.");
  const scan = await api(`/scans/${activeScan}`);
  $("#scanStatus").textContent = `Scan ${activeScan}: ${scan.status}`;
  if (["queued", "running"].includes(scan.status)) {
    message(`Scan ${activeScan} is ${scan.status}. Refreshing automatically…`);
    schedulePoll();
    return;
  }
  if (scan.status === "failed")
    throw new Error(scan.stats.error || "Scan failed. See audit data.");
  const [data, diff, graph] = await Promise.all([
    api(`/scans/${activeScan}/overview`),
    api(`/scans/${activeScan}/diff`),
    api(`/scans/${activeScan}/graph`),
  ]);
  render(data, diff, graph);
  message(`Loaded completed scan ${activeScan}.`);
  clearTimeout(pollTimer);
}

function schedulePoll() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(
    () => load().catch((error) => message(error.message, true)),
    1500,
  );
}

async function startScan(event) {
  event.preventDefault();
  try {
    const scope = scopeFromForm();
    if (!scope.domain.includes("."))
      throw new Error("Enter a valid root domain.");
    const dryRun = $("#dryRun").checked;
    const confirmed = $("#confirmed").checked;
    if (!dryRun && !confirmed)
      throw new Error("Live scans require authorization confirmation.");
    message("Saving scope and queuing scan…");
    let domain;
    try {
      domain = await api("/domains", {
        method: "POST",
        body: JSON.stringify({ root_domain: scope.domain, scope }),
      });
    } catch (error) {
      if (!error.message.includes("already exists")) throw error;
      const domains = await api("/domains");
      domain = domains.find((item) => item.root_domain === scope.domain);
      if (!domain) throw error;
    }
    const scan = await api(`/domains/${domain.id}/scans`, {
      method: "POST",
      body: JSON.stringify({
        dry_run: dryRun,
        confirmed_authorization: confirmed,
      }),
    });
    $("#scanId").value = scan.id;
    await load();
  } catch (error) {
    message(error.message, true);
  }
}

$("#scanForm").addEventListener("submit", startScan);
$("#load").addEventListener("click", () =>
  load().catch((error) => message(error.message, true)),
);
$("#ask").addEventListener("click", async () => {
  try {
    if (!activeScan) throw new Error("Load a completed scan first.");
    const result = await api(`/scans/${activeScan}/copilot`, {
      method: "POST",
      body: JSON.stringify({ question: $("#question").value }),
    });
    $("#answer").textContent =
      `${result.answer} Citations: ${result.citations.map((citation) => citation.hostname).join(", ")}`;
  } catch (error) {
    message(error.message, true);
  }
});

api("/health")
  .then(() => {
    $("#health").textContent = "● API online";
  })
  .catch(() => {
    $("#health").textContent = "● API unavailable";
  });
