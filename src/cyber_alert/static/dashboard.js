// Dashboard: loads everything from the JSON API and refreshes when the server
// pushes new events over Socket.IO. Log data is attacker-controlled, so every
// value reaches the page through textContent, never innerHTML.

const REFRESH_DELAY_MS = 1000; // coalesce bursts of events into one refresh
const POLL_INTERVAL_MS = 10000; // fallback when the Socket.IO client can't load
const MAX_USERNAMES_SHOWN = 5;

const $ = (id) => document.getElementById(id);
const numberFormat = new Intl.NumberFormat();
const EVENT_LABELS = {
  auth_failure: "Failed",
  auth_success: "Accepted",
  invalid_user: "Nonexistent user",
};

// --- Data loading ---------------------------------------------------------

async function getJSON(path, params = {}) {
  const url = new URL(path, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value) url.searchParams.set(key, value);
  }
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${path} returned HTTP ${response.status}`);
  return response.json();
}

function alertFilters() {
  return {
    severity: $("filter-severity").value,
    rule: $("filter-rule").value,
    source_ip: $("filter-ip").value.trim(),
  };
}

let alertsRequest = 0;

async function refreshAlerts() {
  const request = ++alertsRequest;
  const table = $("alerts");
  table.classList.add("refreshing"); // keep the old rows visible while loading
  try {
    const { alerts } = await getJSON("/api/alerts", alertFilters());
    if (request === alertsRequest) renderAlerts(alerts); // ignore out-of-order responses
  } finally {
    if (request === alertsRequest) table.classList.remove("refreshing");
  }
}

async function refreshAll() {
  const [summary, timeline, events] = await Promise.all([
    getJSON("/api/summary"),
    getJSON("/api/timeline"),
    getJSON("/api/events", { limit: 50 }),
    refreshAlerts(),
  ]);
  renderSummary(summary);
  renderTimeline(timeline);
  renderEvents(events.events);
}

let refreshTimer = null;

function scheduleRefresh() {
  if (refreshTimer !== null) return;
  refreshTimer = setTimeout(() => {
    refreshTimer = null;
    refreshAll().catch(console.error);
  }, REFRESH_DELAY_MS);
}

// --- DOM helpers ------------------------------------------------------------

function el(tag, { className, text, title, data } = {}, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  if (title) node.title = title;
  for (const [key, value] of Object.entries(data ?? {})) node.dataset[key] = value;
  node.append(...children);
  return node;
}

function cell(text, className) {
  return el("td", { className, text });
}

function emptyRow(columns, text) {
  const td = el("td", { text });
  td.colSpan = columns;
  return el("tr", { className: "muted-row" }, td);
}

function formatTime(iso) {
  return new Date(iso).toLocaleString();
}

const displayName = (value) => value || "(empty)";

// --- Summary tiles and bar lists ------------------------------------------------

function renderSummary(summary) {
  $("total-events").textContent = numberFormat.format(summary.total_events);
  $("failed-logins").textContent = numberFormat.format(summary.failed_logins);
  $("successful-logins").textContent = numberFormat.format(summary.successful_logins);
  $("unique-sources").textContent = numberFormat.format(summary.unique_sources);

  const counts = Object.entries(summary.alerts_by_severity);
  const total = counts.reduce((sum, [, count]) => sum + count, 0);
  $("alert-total").textContent = numberFormat.format(total);
  $("alert-breakdown").textContent = counts
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => `${count} ${severity}`)
    .join(" · ");

  renderBars(
    $("top-sources"),
    summary.top_failed_sources.map((row) => [row.source_ip, row.count]),
    "No failed logins yet.",
  );
  renderBars(
    $("top-usernames"),
    summary.top_failed_usernames.map((row) => [displayName(row.username), row.count]),
    "No failed logins yet.",
  );
}

function renderBars(list, rows, emptyText) {
  if (rows.length === 0) {
    list.replaceChildren(el("li", { className: "empty", text: emptyText }));
    return;
  }
  const max = Math.max(...rows.map(([, value]) => value));
  list.replaceChildren(
    ...rows.map(([label, value]) => {
      const bar = el("span", { className: "bar" });
      // Leave room after the bar for its value label.
      bar.style.width = `calc((100% - 6ch) * ${value / max})`;
      return el(
        "li",
        {},
        el("span", { className: "bar-label", text: label, title: label }),
        el("span", { className: "bar-track" }, bar, el("span", {
          className: "bar-value",
          text: numberFormat.format(value),
        })),
      );
    }),
  );
}

// --- Timeline chart -------------------------------------------------------

const SVG_NS = "http://www.w3.org/2000/svg";
const CHART_HEIGHT = 220;
const MARGIN = { top: 12, right: 8, bottom: 28, left: 44 };
const SERIES = [
  ["successes", "Successful"],
  ["failures", "Failed"],
];

let currentTimeline = null;

function svg(tag, attributes = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
  return node;
}

function niceTicks(max, count = 4) {
  const rough = max / count;
  const magnitude = 10 ** Math.floor(Math.log10(rough));
  const step = Math.max(1, [1, 2, 5, 10].map((m) => m * magnitude).find((s) => s >= rough));
  const top = Math.ceil(max / step) * step;
  return Array.from({ length: top / step + 1 }, (_, i) => i * step);
}

// A column with rounded top corners and a square base.
function columnPath(x, top, width, height, radius) {
  const r = Math.min(radius, width / 2, height);
  const bottom = top + height;
  return `M${x},${bottom} V${top + r} Q${x},${top} ${x + r},${top} H${x + width - r} `
    + `Q${x + width},${top} ${x + width},${top + r} V${bottom} Z`;
}

function bucketLabel(iso, bucketSeconds, spansDays) {
  const date = new Date(iso);
  if (bucketSeconds >= 86400) return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  const time = date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return spansDays ? `${date.toLocaleDateString(undefined, { month: "short", day: "numeric" })} ${time}` : time;
}

function bucketRange(iso, bucketSeconds) {
  const start = new Date(iso);
  const end = new Date(start.getTime() + bucketSeconds * 1000);
  const time = { hour: "2-digit", minute: "2-digit" };
  return `${start.toLocaleDateString(undefined, { month: "short", day: "numeric" })}, `
    + `${start.toLocaleTimeString(undefined, time)} – ${end.toLocaleTimeString(undefined, time)}`;
}

function renderTimeline(timeline) {
  currentTimeline = timeline;
  const container = $("timeline");
  const { buckets, bucket_seconds: bucketSeconds } = timeline;
  renderTimelineTable(timeline);
  if (buckets.length === 0) {
    container.replaceChildren(el("p", { className: "empty", text: "No logins yet." }));
    return;
  }

  const width = container.clientWidth;
  const plotWidth = width - MARGIN.left - MARGIN.right;
  const plotHeight = CHART_HEIGHT - MARGIN.top - MARGIN.bottom;
  const ticks = niceTicks(Math.max(1, ...buckets.map((b) => b.successes + b.failures)));
  const yMax = ticks.at(-1);
  const y = (value) => MARGIN.top + plotHeight - (value / yMax) * plotHeight;
  const band = plotWidth / buckets.length;
  const barWidth = Math.max(2, Math.min(24, band - 2)); // >= 2px of surface between columns
  const spansDays = new Date(buckets.at(-1).start) - new Date(buckets[0].start) >= 86400000;

  const root = svg("svg", {
    width,
    height: CHART_HEIGHT,
    viewBox: `0 0 ${width} ${CHART_HEIGHT}`,
    role: "img",
    "aria-label": "Successful and failed logins over time. The table view below lists every value.",
  });

  for (const tick of ticks) {
    root.append(svg("line", {
      class: tick === 0 ? "baseline" : "gridline",
      x1: MARGIN.left, x2: width - MARGIN.right, y1: y(tick), y2: y(tick),
    }));
    const label = svg("text", { class: "tick", x: MARGIN.left - 8, y: y(tick) + 4, "text-anchor": "end" });
    label.textContent = numberFormat.format(tick);
    root.append(label);
  }

  buckets.forEach((bucket, i) => {
    const bandX = MARGIN.left + i * band;
    // Hit area first, so the hover wash sits behind the columns.
    const hit = svg("rect", { class: "hit", x: bandX, y: MARGIN.top, width: band, height: plotHeight });
    hit.addEventListener("pointermove", (event) => showTooltip(event, bucket, bucketSeconds));
    hit.addEventListener("pointerleave", hideTooltip);
    root.append(hit);

    const x = bandX + (band - barWidth) / 2;
    const segments = SERIES.filter(([key]) => bucket[key] > 0);
    let stacked = 0;
    segments.forEach(([key], j) => {
      const gap = j > 0 ? 2 : 0; // surface gap between stacked segments
      const bottom = y(stacked) - gap;
      stacked += bucket[key];
      const top = y(stacked);
      if (bottom - top < 1) return; // too thin to draw; the tooltip and table still show it
      const isTop = j === segments.length - 1;
      root.append(svg("path", {
        class: `bar-${key}`,
        d: columnPath(x, top, barWidth, bottom - top, isTop ? 4 : 0),
      }));
    });
  });

  const labelEvery = Math.ceil((spansDays ? 110 : 64) / band);
  buckets.forEach((bucket, i) => {
    if (i % labelEvery) return;
    const label = svg("text", {
      class: "tick",
      x: MARGIN.left + (i + 0.5) * band,
      y: CHART_HEIGHT - 8,
      "text-anchor": "middle",
    });
    label.textContent = bucketLabel(bucket.start, bucketSeconds, spansDays);
    root.append(label);
  });

  container.replaceChildren(root);
}

function renderTimelineTable({ buckets, bucket_seconds: bucketSeconds }) {
  $("timeline-table").replaceChildren(
    ...buckets.map((bucket) => el(
      "tr",
      {},
      cell(bucketRange(bucket.start, bucketSeconds)),
      cell(numberFormat.format(bucket.successes), "num"),
      cell(numberFormat.format(bucket.failures), "num"),
    )),
  );
}

function showTooltip(event, bucket, bucketSeconds) {
  const tooltip = $("tooltip");
  tooltip.replaceChildren(
    el("p", { className: "tooltip-title", text: bucketRange(bucket.start, bucketSeconds) }),
    ...SERIES.map(([key, label]) => el(
      "p",
      { className: "tooltip-row" },
      el("span", { className: `line-key ${key}` }),
      el("strong", { text: numberFormat.format(bucket[key]) }),
      el("span", { text: label }),
    )),
  );
  tooltip.hidden = false;
  const { innerWidth, innerHeight } = window;
  const { offsetWidth, offsetHeight } = tooltip;
  tooltip.style.left = `${Math.min(event.clientX + 12, innerWidth - offsetWidth - 8)}px`;
  tooltip.style.top = `${Math.min(event.clientY + 12, innerHeight - offsetHeight - 8)}px`;
}

function hideTooltip() {
  $("tooltip").hidden = true;
}

let resizeFrame = 0;
new ResizeObserver(() => {
  cancelAnimationFrame(resizeFrame);
  resizeFrame = requestAnimationFrame(() => currentTimeline && renderTimeline(currentTimeline));
}).observe($("timeline"));

// --- Tables -----------------------------------------------------------------

function renderAlerts(alerts) {
  const filtered = Object.values(alertFilters()).some(Boolean);
  if (alerts.length === 0) {
    const text = filtered ? "No alerts match these filters." : "No alerts yet.";
    $("alerts").replaceChildren(emptyRow(6, text));
    return;
  }
  $("alerts").replaceChildren(...alerts.map((alert) => {
    const technique = el("a", {
      text: alert.technique.id,
      title: alert.technique.name,
    });
    technique.href = alert.technique.url;
    technique.target = "_blank";
    technique.rel = "noopener noreferrer";

    const shown = alert.usernames.slice(0, MAX_USERNAMES_SHOWN).map(displayName).join(", ");
    const hidden = alert.usernames.length - MAX_USERNAMES_SHOWN;

    return el(
      "tr",
      {},
      cell(formatTime(alert.last_seen)),
      el("td", {}, el("span", {
        className: "severity",
        text: alert.severity,
        data: { severity: alert.severity },
      })),
      el(
        "td",
        {},
        el("strong", { text: alert.title }),
        el("span", { className: "detail", text: alert.description }),
      ),
      el("td", {}, technique),
      cell(hidden > 0 ? `${shown} +${hidden} more` : shown),
      cell(numberFormat.format(alert.event_count), "num"),
    );
  }));
}

function renderEvents(events) {
  if (events.length === 0) {
    $("events").replaceChildren(emptyRow(5, "No events yet."));
    return;
  }
  $("events").replaceChildren(...events.map((event) => el(
    "tr",
    {},
    cell(formatTime(event.timestamp)),
    el("td", {}, el("span", {
      className: "event-kind",
      text: EVENT_LABELS[event.event_type] + (event.count > 1 ? ` ×${event.count}` : ""),
      data: { kind: event.event_type },
    })),
    cell(displayName(event.username)),
    cell(event.source_ip),
    cell(event.method ?? ""),
  )));
}

// --- Wiring -----------------------------------------------------------------

function setConnection(state, label) {
  $("connection").dataset.state = state;
  $("connection-label").textContent = label;
}

let filterTimer = null;
for (const id of ["filter-severity", "filter-rule"]) {
  $(id).addEventListener("change", () => refreshAlerts().catch(console.error));
}
$("filter-ip").addEventListener("input", () => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => refreshAlerts().catch(console.error), 300);
});

refreshAll().catch(console.error);

if (typeof window.io === "function") {
  const socket = window.io();
  socket.on("connect", () => {
    setConnection("connected", "Live");
    scheduleRefresh(); // catch up on anything missed while disconnected
  });
  socket.on("disconnect", () => setConnection("disconnected", "Disconnected"));
  socket.on("auth_event", scheduleRefresh);
  socket.on("alert", scheduleRefresh);
} else {
  setConnection("disconnected", "Live updates unavailable; refreshing every 10s");
  setInterval(() => refreshAll().catch(console.error), POLL_INTERVAL_MS);
}
