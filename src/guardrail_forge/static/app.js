const $ = (selector) => document.querySelector(selector);

function cell(row, value, className = "") {
  const element = document.createElement("td");
  element.textContent = value;
  if (className) element.className = className;
  row.appendChild(element);
}

async function getJSON(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

async function refresh() {
  $("#status").textContent = "Loading…";
  $("#refresh").disabled = true;
  try {
    const [summary, history, alerts] = await Promise.all([
      getJSON("/v1/audits-summary"),
      getJSON("/v1/audits?limit=20"),
      getJSON("/v1/alerts"),
    ]);
    $("#total").textContent = summary.total_scans.toLocaleString();
    $("#blocked").textContent = summary.blocked_scans.toLocaleString();
    $("#risk").textContent = summary.average_risk_score.toFixed(1);
    $("#alerts").textContent = alerts.length.toLocaleString();
    const body = $("#activity");
    body.replaceChildren();
    for (const item of history.items) {
      const row = document.createElement("tr");
      cell(row, new Date(item.created_at).toLocaleString());
      cell(row, item.source);
      cell(row, item.action, item.action === "block" ? "blocked" : "allow");
      cell(row, item.risk_score);
      cell(row, item.finding_count);
      body.appendChild(row);
    }
    $("#empty").hidden = history.items.length !== 0;
    $("#status").textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    $("#status").textContent = `Unable to load: ${error.message}`;
  } finally {
    $("#refresh").disabled = false;
  }
}

$("#refresh").addEventListener("click", refresh);
refresh();
