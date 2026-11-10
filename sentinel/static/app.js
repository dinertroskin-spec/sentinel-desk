"use strict";
const $ = (selector) => document.querySelector(selector);
const state = { data: null, rules: [], view: "overview", filter: "all", search: "" };
const severities = { critical: "Critical", high: "High", medium: "Medium" };
const statuses = { new: "Новый", investigating: "В работе", resolved: "Закрыт", false_positive: "Ложный сигнал" };
const titles = { overview: ["Обзор", "Ситуация под контролем.", "От первого сигнала до решения — всё в одном рабочем пространстве.", "01"], incidents: ["Инциденты", "От сигнала к решению.", "Контекст, доказательства и история каждого расследования.", "02"], events: ["Журнал событий", "Каждое событие имеет значение.", "Единый формат для SSH, веб-сервисов и собственных источников.", "03"], rules: ["Правила детекции", "Прозрачная логика. Ясный сигнал.", "Пять проверяемых правил с порогами и рекомендациями по реагированию.", "04"] };
function el(tag, className, text) { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; }
function badge(type, value) { return el("span", `${type} ${value}`, type === "severity" ? severities[value] : statuses[value]); }
function date(value) { return value ? value.replace("T", " ").replace("+00:00", "").replace(".000000", "") : "—"; }
function time(value) { return value ? value.slice(11, 19) : "—"; }
function notify(text, error = false) { const node = $("#notice"); node.textContent = text; node.classList.toggle("error", error); node.hidden = false; }
async function api(path, data) {
  const options = data === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json", "X-Sentinel-Request": "1" }, body: JSON.stringify(data) };
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
  return result;
}
async function busy(button, action) { button.disabled = true; try { await action(); } finally { button.disabled = false; } }
function changeView(view) {
  state.view = view;
  const [crumb, title, description, number] = titles[view];
  $("#breadcrumb").textContent = crumb; $("#page-title").textContent = title; $("#page-description").textContent = description; $("#view-number").textContent = number;
  document.querySelectorAll(".nav-item").forEach((item) => { item.classList.toggle("active", item.dataset.view === view); item.setAttribute("aria-current", item.dataset.view === view ? "page" : "false"); });
  document.querySelectorAll(".view").forEach((item) => { item.hidden = item.id !== `${view}-view`; });
  $("#incident-section").hidden = !["overview", "incidents"].includes(view);
  $("#empty-state").hidden = !(state.data && !state.data.summary.events && view === "overview");
}
function renderIncidents() {
  const filtered = state.data.incidents.filter((item) => {
    const open = ["new", "investigating"].includes(item.status);
    return (state.filter === "all" || (state.filter === "open" ? open : !open)) && `${item.title} ${item.actor} ${item.rule_id}`.toLowerCase().includes(state.search.toLowerCase());
  });
  const body = $("#incident-rows"); body.replaceChildren();
  for (const item of filtered) {
    const row = el("tr"); const priority = el("td"); priority.append(badge("severity", item.severity));
    const title = el("td"); title.append(el("span", "incident-title", item.title), el("span", "incident-sub", `${item.rule_id} · ${time(item.first_seen)} UTC`));
    const actor = el("td", "mono", item.actor); const count = el("td", "mono", String(item.event_count));
    const status = el("td"); status.append(badge("status", item.status));
    const action = el("td"); const button = el("button", "open-incident", "↗"); button.setAttribute("aria-label", `Открыть ${item.title}, ${item.actor}`);
    button.addEventListener("click", () => openIncident(item.id).catch((error) => notify(error.message, true))); action.append(button);
    row.append(priority, title, actor, count, status, action); body.append(row);
  }
  $("#no-incidents").hidden = filtered.length > 0;
  $("#incident-total").textContent = state.data.incidents.length;
  $("#table-count").textContent = `Показано ${filtered.length} из ${state.data.incidents.length}`;
}
function renderEvents() {
  const body = $("#event-rows"); body.replaceChildren();
  for (const item of state.data.events) {
    const row = el("tr");
    [date(item.timestamp), item.kind, item.ip, item.user || item.path, item.service, item.status || "—"].forEach((value) => row.append(el("td", "mono", String(value))));
    body.append(row);
  }
}
function svgNode(tag, attrs = {}, text) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
  if (text !== undefined) node.textContent = text;
  return node;
}
function renderChart() {
  const events = [...state.data.events].reverse();
  const chart = $("#chart"); chart.replaceChildren();
  const svg = svgNode("svg", { viewBox: "0 0 660 160", role: "img", "aria-label": "Количество обычных событий и событий, вошедших в инциденты, в 12 временных интервалах" });
  const buckets = Array.from({ length: 12 }, () => ({ normal: 0, suspicious: 0 }));
  const first = events.length ? Date.parse(events[0].timestamp) : 0;
  const last = events.length ? Date.parse(events[events.length - 1].timestamp) : 0;
  const span = Math.max(1, last - first);
  const evidence = new Set(state.data.incidents.flatMap((item) => item.evidence));
  for (const event of events) { const index = Math.min(11, Math.floor((Date.parse(event.timestamp) - first) / span * 12)); buckets[index][evidence.has(event.id) ? "suspicious" : "normal"]++; }
  const max = Math.max(4, ...buckets.map((b) => b.normal + b.suspicious));
  for (let i = 0; i <= 3; i++) { const y = 16 + i * 36; svg.append(svgNode("line", { x1: 30, x2: 650, y1: y, y2: y, class: "grid-line" }), svgNode("text", { x: 20, y: y + 3, "text-anchor": "end", class: "axis-text" }, Math.round(max * (3 - i) / 3))); }
  buckets.forEach((bucket, i) => {
    const normal = bucket.normal / max * 108, suspicious = bucket.suspicious / max * 108, x = 42 + i * 50;
    const group = svgNode("g"); group.append(svgNode("title", {}, `${bucket.normal} обычных, ${bucket.suspicious} в инцидентах`));
    group.append(svgNode("rect", { x, y: 124 - normal, width: 25, height: normal, rx: 2, class: "bar-normal" }), svgNode("rect", { x, y: 124 - normal - suspicious, width: 25, height: suspicious, rx: 2, class: "bar-alert" })); svg.append(group);
    if (i % 3 === 0 || i === 11) { const stamp = new Date(first + span * i / 12).toISOString().slice(11, 16); svg.append(svgNode("text", { x: x + 12, y: 149, "text-anchor": "middle", class: "axis-text" }, events.length ? stamp : "—")); }
  });
  chart.append(svg);
  $("#time-range").textContent = events.length ? `${events[0].timestamp.slice(0, 10)} / ${time(events[0].timestamp)} — ${time(events[events.length - 1].timestamp)} UTC` : "Нет данных";
}
function renderQueue() {
  const open = state.data.incidents.filter((item) => ["new", "investigating"].includes(item.status));
  $("#queue-total").textContent = open.length;
  const container = $("#severity-bars"); container.replaceChildren();
  for (const [severity, label] of Object.entries(severities)) {
    const count = open.filter((item) => item.severity === severity).length;
    const row = el("div", "severity-row"); const track = el("div", "severity-track");
    const svg = svgNode("svg", { viewBox: "0 0 100 4", preserveAspectRatio: "none", "aria-hidden": "true" });
    svg.append(svgNode("rect", { width: open.length ? count / open.length * 100 : 0, height: 4, rx: 2, fill: { critical: "#fa9a91", high: "#e9c27f", medium: "#9ebbe5" }[severity] })); track.append(svg);
    row.append(el("span", "", label), track, el("strong", "", String(count))); container.append(row);
  }
}
function renderRules() {
  const container = $("#rule-cards"); container.replaceChildren();
  for (const rule of state.rules) { const card = el("article", "panel rule-card"), top = el("div", "rule-card-top"); top.append(el("span", "rule-id", rule.id), badge("severity", rule.severity)); card.append(top, el("h2", "", rule.name), el("p", "", rule.description), el("p", "rule-response", rule.response)); container.append(card); }
}
async function refresh() {
  state.data = await api("/api/state");
  for (const key of ["events", "open", "critical"]) $(`#metric-${key}`).textContent = state.data.summary[key];
  $("#nav-count").textContent = state.data.summary.open;
  renderIncidents(); renderEvents(); renderChart(); renderQueue(); changeView(state.view);
}
async function openIncident(id) {
  const item = await api(`/api/incidents/${id}`), rule = state.rules.find((r) => r.id === item.rule_id);
  const content = $("#detail-content"); content.replaceChildren();
  content.append(badge("severity", item.severity), el("h2", "", item.title));
  const meta = el("div", "detail-meta"); meta.append(el("span", "mono", item.rule_id), el("span", "mono", item.actor), badge("status", item.status)); content.append(meta, el("p", "dialog-description", rule.description), el("p", "detail-response", rule.response));
  content.append(el("h3", "", "Доказательства"), el("p", "evidence-count", `${item.event_count} событий · ${date(item.first_seen)} — ${date(item.last_seen)} UTC. Показаны первые 100.`));
  const wrapper = el("div", "detail-events"), table = el("table"), head = el("thead"), headRow = el("tr");
  ["ВРЕМЯ UTC", "СОБЫТИЕ", "ПОЛЬЗОВАТЕЛЬ / ПУТЬ", "HTTP"].forEach((t) => headRow.append(el("th", "", t))); head.append(headRow); table.append(head);
  const body = el("tbody"); for (const event of item.events.slice(0, 100)) { const row = el("tr"); [date(event.timestamp), event.kind, event.user || event.path, event.status || "—"].forEach((value) => row.append(el("td", "mono detail-path", String(value)))); body.append(row); } table.append(body); wrapper.append(table); content.append(wrapper, el("h3", "", "История расследования"));
  if (!item.history.length) content.append(el("p", "history-empty", "Пока нет записей. Добавьте первое решение аналитика."));
  for (const entry of item.history) { const history = el("div", "history-item"); history.append(el("small", "", `${date(entry.timestamp)} UTC · ${statuses[entry.status]}`), el("span", "", entry.note)); content.append(history); }
  const form = el("form"), label = el("label", "", "Комментарий аналитика"), textarea = el("textarea"); textarea.required = true; textarea.maxLength = 2000; textarea.rows = 3; textarea.placeholder = "Что проверили, что обнаружили, следующий шаг…"; textarea.setAttribute("aria-label", "Комментарий аналитика"); label.append(textarea);
  const actions = el("div", "note-actions"), statusLabel = el("label", "", "Статус"), select = el("select"); select.setAttribute("aria-label", "Статус инцидента");
  for (const [value, text] of Object.entries(statuses)) { const option = el("option", "", text); option.value = value; select.append(option); } select.value = item.status; statusLabel.append(select);
  const submit = el("button", "button primary", "Сохранить решение"); submit.type = "submit"; actions.append(statusLabel, submit); const errorNode = el("p", "form-error"); errorNode.setAttribute("role", "alert"); form.append(label, actions, errorNode);
  form.addEventListener("submit", (event) => { event.preventDefault(); busy(submit, async () => { try { await api(`/api/incidents/${id}`, { status: select.value, note: textarea.value }); await refresh(); await openIncident(id); } catch (error) { errorNode.textContent = error.message; } }); });
  content.append(form); if (!$("#detail-dialog").open) $("#detail-dialog").showModal();
}
document.querySelectorAll(".nav-item").forEach((item) => item.addEventListener("click", () => changeView(item.dataset.view)));
document.querySelectorAll(".tab").forEach((item) => item.addEventListener("click", () => { state.filter = item.dataset.filter; document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab === item)); renderIncidents(); }));
$("#incident-search").addEventListener("input", (event) => { state.search = event.target.value; renderIncidents(); });
document.querySelectorAll("[data-close]").forEach((item) => item.addEventListener("click", () => document.getElementById(item.dataset.close).close()));
$("#import-open").addEventListener("click", () => { $("#import-error").textContent = ""; $("#import-dialog").showModal(); });
$("#demo-load").addEventListener("click", () => busy($("#demo-load"), async () => { try { const result = await api("/api/demo", {}); await refresh(); notify(`Демо-сценарий загружен: ${result.added} событий, ${result.incidents} инцидентов. Все данные синтетические.`); } catch (error) { notify(error.message, true); } }));
$("#import-file").addEventListener("change", async (event) => { const file = event.target.files[0]; if (!file) return; if (file.size > 2 * 1024 * 1024) { $("#import-error").textContent = "Файл превышает 2 МиБ."; event.target.value = ""; return; } $("#import-text").value = await file.text(); if (!$("#import-source").value) $("#import-source").value = file.name.slice(0, 100); });
$("#import-form").addEventListener("submit", (event) => { event.preventDefault(); busy($("#import-submit"), async () => {
  try { const text = $("#import-text").value; if (!text.trim()) throw new Error("Выберите файл или вставьте логи."); const data = { text, format: $("#import-format").value, source: $("#import-source").value.trim() }; if (new TextEncoder().encode(JSON.stringify(data)).length > 2 * 1024 * 1024) throw new Error("Запрос превышает 2 МиБ. Разделите лог на части.");
    const result = await api("/api/import", data); await refresh(); $("#import-dialog").close();
    let message = `Импорт завершён: добавлено ${result.added}, дубликатов ${result.duplicates}, отклонено ${result.rejected}. Инцидентов в базе: ${result.incidents}.`;
    if (result.errors.length) message += "\n" + result.errors.slice(0, 5).map((error) => `Строка ${error.line}: ${error.reason}`).join("\n"); notify(message, result.rejected > 0);
  } catch (error) { $("#import-error").textContent = error.message; }
}); });
(async () => { try { state.rules = await api("/api/rules"); renderRules(); await refresh(); } catch (error) { notify(`Не удалось загрузить данные: ${error.message}`, true); } })();
