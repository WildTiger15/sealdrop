// audit.ts: renders /api/audit as a table. Uses textContent only (no HTML
// injection from audit fields, which can contain agent-chosen strings).

type Entry = {
  id: number; ts_ms: number; request_id: string; actor: string; on_behalf_of: string;
  action: string; file_id: string; grant_id: string; decision: "allow" | "deny"; reason: string;
};

const tbody = document.querySelector("#audit tbody") as HTMLTableSectionElement;
const statusEl = document.getElementById("status")!;
const onlyDeny = document.getElementById("only-deny") as HTMLInputElement;
let entries: Entry[] = [];

function render() {
  const shown = onlyDeny.checked ? entries.filter((e) => e.decision === "deny") : entries;
  tbody.replaceChildren();
  for (const e of shown) {
    const tr = document.createElement("tr");
    tr.className = e.decision;
    for (const v of [
      new Date(e.ts_ms).toLocaleString(), e.actor, e.on_behalf_of || "—", e.action,
      e.file_id ? e.file_id.slice(0, 8) : "—", e.decision, e.reason, e.request_id,
    ]) {
      const td = document.createElement("td");
      td.textContent = v;
      tr.append(td);
    }
    tbody.append(tr);
  }
  const denied = entries.filter((e) => e.decision === "deny").length;
  statusEl.textContent = `${entries.length} entries, ${denied} denied. Newest first.`;
}

async function load() {
  const r = await fetch("/api/audit");
  if (r.status === 401) {
    statusEl.textContent = "Sign in on the main page first.";
    return;
  }
  entries = await r.json();
  render();
}

document.getElementById("reload")!.onclick = load;
onlyDeny.onchange = render;
load();
