const statusElement = document.querySelector("#connection-status");
const emptyState = document.querySelector("#empty-state");
const tableWrap = document.querySelector("#trace-table-wrap");
const rows = document.querySelector("#trace-rows");
let cursor = null;

const renderTime = (timestamp) => new Date(timestamp).toLocaleTimeString();
const renderLatency = (latency) => latency === null ? "—" : `${latency.toFixed(3)} ms`;
const renderDirection = (direction) => {
  if (direction === "client_to_upstream") return "client → server";
  if (direction === "upstream_to_client") return "server → client";
  return "proxy";
};
const renderControl = (trace) => trace.reason_code ?? trace.layer ?? "—";

function addTrace(trace, newestFirst = true) {
  const row = document.createElement("tr");
  const fields = [
    renderTime(trace.created_at),
    renderDirection(trace.direction),
    trace.method ?? "response",
    trace.disposition,
    renderLatency(trace.latency_ms),
    renderControl(trace),
    `${trace.summary} (${trace.byte_count} bytes)`,
  ];
  fields.forEach((value, index) => {
    const cell = document.createElement("td");
    cell.textContent = value;
    if (index === 1) cell.className = "direction";
    if (index === 3) cell.className = "decision";
    row.append(cell);
  });
  if (newestFirst) rows.prepend(row); else rows.append(row);
  emptyState.hidden = true;
  tableWrap.hidden = false;
}

async function loadExisting() {
  const response = await fetch("/api/traces?limit=100");
  if (!response.ok) throw new Error("Trace API is unavailable");
  const traces = await response.json();
  cursor = traces[0]?.event_id ?? null;
  traces.reverse().forEach((trace) => addTrace(trace, false));
}

async function start() {
  try {
    await loadExisting();
    const suffix = cursor === null ? "" : `?after=${encodeURIComponent(cursor)}`;
    const stream = new EventSource(`/api/traces/stream${suffix}`);
    stream.addEventListener("trace", (event) => {
      const trace = JSON.parse(event.data);
      cursor = trace.event_id;
      addTrace(trace);
    });
    stream.onopen = () => { statusElement.textContent = "Live trace stream connected"; };
    stream.onerror = () => { statusElement.textContent = "Waiting to reconnect to trace stream"; };
  } catch (error) {
    statusElement.textContent = error.message;
  }
}

start();
