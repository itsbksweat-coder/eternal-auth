import { authenticatedLauncher, ffaLauncher } from "./entry-loader.js";
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
let currentGuild = "";
let backendState = { last_guild_id: null, active_tab: "gateway", preferences: {} };
let stockCache = [];
let serverKeyCache = [];
let scriptCache = [];
let selectedScriptId = null;

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { "content-type": "application/json", ...(options.headers || {}) },
  });
  let data;
  try { data = await res.json(); } catch { data = { ok: false, error: `HTTP ${res.status}` }; }
  if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function msg(text = "", type = "") {
  const el = $("#statusMsg");
  el.textContent = text;
  el.className = `msg ${type}`;
}

function fmtTime(value) {
  const n = Number(value);
  if (n === -1) return "Lifetime";
  if (!n) return "—";
  return new Date(n * 1000).toLocaleString();
}

function esc(v) {
  return String(v ?? "").replace(/[&<>'"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c]));
}

function loaderLoadstring(url) {
  const value = String(url || "").trim();
  return value ? authenticatedLauncher(value) : "";
}

function guildQuery() {
  const id = $("#guildId").value.trim();
  if (!id) throw new Error("Enter the Discord server ID first.");
  currentGuild = id;
  return encodeURIComponent(id);
}

async function loadBackendState() {
  const data = await api("/api/admin/state");
  backendState = data.state || backendState;
  currentGuild = backendState.last_guild_id || "";
  $("#guildId").value = currentGuild;
  const desired = $(`[data-tab="${backendState.active_tab || "gateway"}"]`) || $('[data-tab="gateway"]');
  if (desired) setActiveTab(desired, false);
  return backendState;
}

async function saveBackendState(patch = {}) {
  try {
    const data = await api("/api/admin/state", {
      method: "PUT",
      body: JSON.stringify(patch),
    });
    backendState = data.state || backendState;
    return backendState;
  } catch (error) {
    console.warn("Could not persist dashboard state:", error);
    return backendState;
  }
}

async function loadBackendStatus(showMessage = false) {
  try {
    if (showMessage) msg("Checking backend persistence…");
    const data = await api("/api/admin/backend/status");
    const b = data.backend || {};
    $("#backendCredential").textContent = b.admin_credential_in_d1 ? "Stored in D1" : "Not initialized";
    $("#backendSessions").textContent = b.active_sessions ?? 0;
    $("#backendGuild").textContent = b.state?.last_guild_id || "None";
    $("#backendTab").textContent = b.state?.active_tab || "gateway";
    const snap = b.gateway_snapshot;
    $("#backendGatewaySnapshot").textContent = snap?.gateway_ready ? "Online" : (snap ? "Stored" : "None yet");
    $("#backendGatewayUpdated").textContent = b.gateway_snapshot_updated_at ? fmtTime(b.gateway_snapshot_updated_at) : "—";
    if (showMessage) msg("Backend state is persistent.", "success");
  } catch (error) {
    if (showMessage) msg(error.message, "error");
  }
}

async function loadProject() {
  try {
    const gid = guildQuery();
    msg("Loading Eternal Auth project…");
    const [stats, licenses, stock, blacklists, config, scripts, panels, logs] = await Promise.all([
      api(`/api/admin/stats?guild_id=${gid}`),
      api(`/api/admin/licenses?guild_id=${gid}`),
      api(`/api/admin/stock-keys?guild_id=${gid}`),
      api(`/api/admin/blacklists?guild_id=${gid}`),
      api(`/api/admin/config?guild_id=${gid}`),
      api(`/api/admin/scripts?guild_id=${gid}`),
      api(`/api/admin/panels?guild_id=${gid}`),
      api(`/api/admin/logs?guild_id=${gid}`),
    ]);
    renderStats(stats.stats);
    renderLicenses(licenses.licenses);
    renderStock(stock.keys);
    renderBlacklists(blacklists.blacklists);
    renderConfig(config);
    renderScripts(scripts.scripts || []);
    renderPanels(panels.panels || []);
    renderLogs(logs.logs);
    await saveBackendState({ last_guild_id: currentGuild });
    msg("Project loaded.", "success");
  } catch (e) { msg(e.message, "error"); }
}

async function loadServerKeys() {
  try {
    const data = await api("/api/admin/server-keys");
    renderServerKeys(data.keys || []);
  } catch (e) {
    msg(e.message, "error");
  }
}

async function loadGatewayStatus(showMessage = false) {
  try {
    if (showMessage) msg("Checking Discord Gateway…");
    const data = await api("/api/admin/gateway/status");
    renderGateway(data.gateway || {});
    if (showMessage) msg(data.gateway?.gateway_ready ? "Eternal Auth is Online." : "Gateway is starting…", data.gateway?.gateway_ready ? "success" : "");
  } catch (e) {
    renderGateway({ gateway_ready: false, last_error: e.message });
    if (showMessage) msg(e.message, "error");
  }
}

function renderGateway(g = {}) {
  const online = !!g.gateway_ready;
  const bot = g.user_tag || g.user_id || "—";
  const uptime = Number.isFinite(Number(g.uptime_seconds)) ? `${Math.floor(Number(g.uptime_seconds) / 60)}m` : "—";
  $("#sGateway").textContent = online ? "Online" : "Starting";
  $("#gatewayStatus").textContent = online ? "Online" : "Connecting / unavailable";
  $("#gatewayBot").textContent = bot;
  const bot2 = $("#gatewayBotSecondary");
  if (bot2) bot2.textContent = bot;
  $("#gatewayGuilds").textContent = g.guilds ?? "—";
  $("#gatewayUptime").textContent = uptime;
  const uptime2 = $("#gatewayUptimeSecondary");
  if (uptime2) uptime2.textContent = uptime;
  $("#gatewayStatus").title = g.last_error || "";
}

function renderServerKeys(rows = []) {
  serverKeyCache = rows;
  $("#serverKeyRows").innerHTML = rows.length ? rows.map(r => {
    const status = r.used_at ? `Used by ${esc(r.used_by_guild_id || "unknown")}` : (Number(r.expires_at) <= Math.floor(Date.now()/1000) ? "Expired" : "Unused");
    const revoke = !r.used_at && Number(r.expires_at) > Math.floor(Date.now()/1000)
      ? `<button class="danger" data-revoke-server-key="${esc(r.id)}">Revoke</button>` : "";
    const copy = r.key ? `<button class="ghost" data-copy-server-key="${esc(r.id)}">Copy</button>` : "";
    return `<tr><td class="key">${esc(r.key_hint)}</td><td>${esc(r.intended_guild_id || "Any server")}</td><td>${esc(status)}</td><td>${esc(fmtTime(r.expires_at))}</td><td>${esc(r.note || "—")}</td><td><div class="actions">${copy}${revoke}</div></td></tr>`;
  }).join("") : `<tr><td colspan="6" class="empty">No server setup keys yet.</td></tr>`;

  $("#serverKeyRows").onclick = async (e) => {
    const copyId = e.target.dataset.copyServerKey;
    if (copyId) {
      const row = serverKeyCache.find((item) => item.id === copyId);
      if (!row?.key) return msg("That older key was created before encrypted backend key storage was enabled.", "error");
      try { await navigator.clipboard.writeText(row.key); msg("Server key copied from backend storage.", "success"); }
      catch { msg("Could not copy the server key.", "error"); }
      return;
    }
    const id = e.target.dataset.revokeServerKey;
    if (!id) return;
    try {
      await api(`/api/admin/server-keys/${encodeURIComponent(id)}`, { method: "DELETE" });
      msg("Server key revoked.", "success");
      await loadServerKeys();
    } catch (err) { msg(err.message, "error"); }
  };
}

function renderStats(s = {}) {
  $("#sLicenses").textContent = s.licenses ?? 0;
  $("#sActive").textContent = s.active_licenses ?? 0;
  $("#sExec").textContent = s.executions_24h ?? 0;
  $("#sGuilds").textContent = s.guilds ?? 0;
  const scripts = $("#sScripts");
  if (scripts) scripts.textContent = s.scripts ?? 0;
}

function renderLicenses(rows = []) {
  const q = $("#licenseSearch").value.trim().toLowerCase();
  const filtered = rows.filter(r => !q || `${r.discord_id||""} ${r.note||""} ${r.id}`.toLowerCase().includes(q));
  $("#licenseRows").innerHTML = filtered.length ? filtered.map(r => `
    <tr>
      <td>${esc(r.discord_id || "Unclaimed")}</td>
      <td><span class="pill ${r.status === "active" ? "" : "bad"}">${esc(r.status)}</span></td>
      <td>${esc(fmtTime(r.auth_expire))}</td>
      <td>${r.hwid_hash ? "Linked" : "Not linked"}</td>
      <td>${esc(r.note || "—")}</td>
      <td><div class="actions"><button class="ghost" data-reset="${esc(r.id)}">Reset HWID</button><button class="danger" data-delete="${esc(r.id)}">Unwhitelist</button></div></td>
    </tr>`).join("") : `<tr><td colspan="6" class="empty">No matching licenses.</td></tr>`;
  $("#licenseRows").onclick = async (e) => {
    const reset = e.target.dataset.reset;
    const del = e.target.dataset.delete;
    try {
      if (reset) await api(`/api/admin/licenses/${encodeURIComponent(reset)}/reset-hwid`, { method: "POST", body: "{}" });
      if (del && confirm("Remove this license?")) await api(`/api/admin/licenses/${encodeURIComponent(del)}`, { method: "DELETE" });
      if (reset || del) await loadProject();
    } catch (err) { msg(err.message, "error"); }
  };
  window.__licenseRows = rows;
}

function renderStock(rows = []) {
  stockCache = rows;
  $("#stockRows").innerHTML = rows.length ? rows.map(r => `<tr><td class="key">${esc(r.key)}</td><td>${esc(fmtTime(r.auth_expire))}</td><td>${esc(r.note || "—")}</td><td>${esc(fmtTime(r.created_at))}</td></tr>`).join("") : `<tr><td colspan="4" class="empty">No unclaimed stock keys.</td></tr>`;
}

function renderBlacklists(rows = []) {
  $("#blacklistRows").innerHTML = rows.length ? rows.map(r => `<tr><td>${esc(r.discord_id)}</td><td>${esc(r.reason || "—")}</td><td>${esc(fmtTime(r.expires_at))}</td><td><button class="ghost" data-unblacklist="${esc(r.discord_id)}">Remove</button></td></tr>`).join("") : `<tr><td colspan="4" class="empty">No blacklisted users.</td></tr>`;
  $("#blacklistRows").onclick = async (e) => {
    const id = e.target.dataset.unblacklist;
    if (!id) return;
    try { await api(`/api/admin/blacklists/${guildQuery()}/${encodeURIComponent(id)}`, { method: "DELETE" }); await loadProject(); }
    catch (err) { msg(err.message, "error"); }
  };
}

function renderConfig(data) {
  $("#loaderTemplate").value = data.guild?.loader_template || "";
}

function selectScript(id) {
  const script = scriptCache.find((row) => row.id === id);
  if (!script) {
    selectedScriptId = null;
    $("#scriptId").value = "";
    $("#scriptEditorTitle").textContent = "Select a script";
    $("#scriptName").value = "";
    $("#scriptVersion").value = "";
    $("#scriptEnabled").checked = false;
    $("#scriptFfaEnabled").checked = false;
    $("#scriptSourceStatus").textContent = "Select a script";
    $("#loaderUrl").value = "";
    $("#ffaLoaderUrl").value = "";
    return;
  }

  selectedScriptId = script.id;
  $("#scriptId").value = script.id;
  $("#scriptEditorTitle").textContent = script.name || "Eternal Auth Script";
  $("#scriptName").value = script.name || "Eternal Auth Script";
  $("#scriptVersion").value = script.version || "1.0.0";
  $("#scriptEnabled").checked = !!script.enabled;
  $("#scriptFfaEnabled").checked = !!script.ffa_enabled;
  $("#scriptSourceStatus").textContent = script.content_size > 0 ? `Protected source uploaded • ${script.content_size.toLocaleString()} characters` : "No source file uploaded";
  $("#loaderUrl").value = loaderLoadstring(script.loader_url);
  $("#ffaLoaderUrl").value = script.ffa_enabled && script.ffa_loader_url ? ffaLauncher(script.ffa_loader_url) : "FFA is disabled for this script";
  renderScripts(scriptCache, false);
}

function renderScripts(rows = [], choose = true) {
  scriptCache = rows;
  const wrap = $("#scriptCards");
  if (!wrap) return;

  wrap.innerHTML = rows.length ? rows.map((script) => `
    <article class="script-item ${script.id === selectedScriptId ? "selected" : ""}" data-script-card="${esc(script.id)}">
      <div class="script-file-icon">LUA</div>
      <div class="script-meta">
        <h4>${esc(script.name || "Eternal Auth Script")}</h4>
        <p>${esc(script.id)} • v${esc(script.version || "1.0.0")}</p>
      </div>
      <div class="script-actions">
        <span class="pill ${script.enabled ? "" : "bad"}">${script.enabled ? "ACTIVE" : "DISABLED"}</span>
        ${script.ffa_enabled ? '<span class="pill">FFA</span>' : ''}
        <button class="ghost" data-copy-script-loader="${esc(script.id)}">Loader</button>
        <button class="primary" data-edit-script="${esc(script.id)}">Edit</button>
        <button class="danger" data-delete-script="${esc(script.id)}">Delete</button>
      </div>
    </article>`).join("") : `<div class="empty">No scripts yet. Upload a .txt, .lua, .luau, or another text-based file to add one.</div>`;

  wrap.onclick = async (e) => {
    const edit = e.target.dataset.editScript;
    const copy = e.target.dataset.copyScriptLoader;
    const del = e.target.dataset.deleteScript;
    const card = e.target.closest?.("[data-script-card]");
    if (edit) return selectScript(edit);
    if (copy) {
      const script = scriptCache.find((row) => row.id === copy);
      if (!script?.loader_url) return msg("Loader URL is unavailable.", "error");
      try { await navigator.clipboard.writeText(loaderLoadstring(script.loader_url)); msg("Script loadstring copied.", "success"); }
      catch { msg("Could not copy the loadstring.", "error"); }
      return;
    }
    if (del) return deleteScript(del);
    if (card) selectScript(card.dataset.scriptCard);
  };

  if (choose) {
    if (!rows.length) selectScript(null);
    else if (!selectedScriptId || !rows.some((row) => row.id === selectedScriptId)) selectScript(rows[0].id);
  }
}

async function deleteScript(id) {
  const script = scriptCache.find((row) => row.id === id);
  if (!script) return;
  if (!confirm(`Delete ${script.name}?`)) return;
  try {
    await api(`/api/admin/scripts/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (selectedScriptId === id) selectedScriptId = null;
    msg("Script deleted.", "success");
    await loadProject();
  } catch (err) { msg(err.message, "error"); }
}

function renderPanels(rows = []) {
  const body = $("#panelRows");
  if (!body) return;
  body.innerHTML = rows.length ? rows.map((r) => `
    <tr>
      <td>${esc(r.name || "Eternal Auth Panel")}</td>
      <td>${esc(r.channel_id || "—")}</td>
      <td>${esc(r.manager_role_id || "—")}</td>
      <td>${esc(r.buyer_role_id || "—")}</td>
      <td><span class="pill ${r.active ? "" : "bad"}">${r.active ? "Active" : "Disabled"}</span></td>
      <td>${esc(fmtTime(r.created_at))}</td>
      <td>${r.active ? `<button class="danger" data-disable-panel="${esc(r.id)}">Disable</button>` : ""}</td>
    </tr>`).join("") : `<tr><td colspan="7" class="empty">No saved panels yet. Run /setpanel in Discord to create one.</td></tr>`;

  body.onclick = async (e) => {
    const id = e.target.dataset.disablePanel;
    if (!id) return;
    if (!confirm("Disable this panel? Its existing Discord buttons will stop working.")) return;
    try {
      await api(`/api/admin/panels/${encodeURIComponent(id)}`, { method: "DELETE" });
      msg("Panel disabled.", "success");
      await loadProject();
    } catch (err) { msg(err.message, "error"); }
  };
}

function renderLogs(rows = []) {
  $("#logRows").innerHTML = rows.length ? rows.map(r => `<tr><td>${esc(fmtTime(r.created_at))}</td><td>${esc(r.action)}</td><td>${esc(r.actor_id || "—")}</td><td>${esc(r.target || "—")}</td><td><code>${esc(r.details || "{}")}</code></td></tr>`).join("") : `<tr><td colspan="5" class="empty">No audit logs yet.</td></tr>`;
}

$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#loginMsg");
  try {
    await api("/api/admin/login", { method: "POST", body: JSON.stringify({ password: $("#password").value }) });
    $("#loginView").classList.add("hidden"); $("#appView").classList.remove("hidden"); $("#logoutBtn").classList.remove("hidden");
    out.textContent = "";
    await loadBackendState();
    await Promise.all([loadServerKeys(), loadGatewayStatus(false), loadBackendStatus(false)]);
    if (currentGuild) await loadProject();
  } catch (err) { out.textContent = err.message; out.className = "msg error"; }
});

$("#wakeGatewayBtn").onclick = async () => {
  try {
    msg("Waking Eternal Auth Free Gateway…");
    const data = await api("/api/admin/gateway/wake", { method: "POST", body: "{}" });
    renderGateway(data.gateway || {});
    msg(data.gateway?.gateway_ready ? "Eternal Auth is Online." : "Gateway started and is connecting to Discord…", data.gateway?.gateway_ready ? "success" : "");
    setTimeout(() => loadGatewayStatus(false), 3000);
  } catch (err) { msg(err.message, "error"); }
};

$("#logoutBtn").onclick = async () => { try { await api("/api/admin/logout", { method: "POST", body: "{}" }); } catch {} location.reload(); };
$("#loadBtn").onclick = loadProject;
$("#refreshBtn").onclick = loadProject;
$("#licenseSearch").addEventListener("input", () => renderLicenses(window.__licenseRows || []));

$("#serverKeyForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const payload = {
      password: $("#serverKeyPassword").value,
      intended_guild_id: $("#serverKeyGuild").value.trim() || null,
      expires_in_hours: Number($("#serverKeyHours").value || 24),
      note: $("#serverKeyNote").value.trim(),
    };
    const data = await api("/api/admin/server-keys", { method: "POST", body: JSON.stringify(payload) });
    const key = data.server_key.key;
    $("#newServerKey").value = key;
    $("#serverKeyPassword").value = "";
    try { await navigator.clipboard.writeText(key); msg("Server key created and copied.", "success"); }
    catch { msg("Server key created. Copy it from the Server Keys tab.", "success"); }
    await loadServerKeys();
  } catch (err) { msg(err.message, "error"); }
});

$("#copyServerKeyBtn").onclick = async () => {
  const key = $("#newServerKey").value.trim();
  if (!key) return msg("Generate a server key first.", "error");
  try { await navigator.clipboard.writeText(key); msg("Server key copied.", "success"); }
  catch { msg("Could not copy the server key.", "error"); }
};

$("#whitelistForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const days = $("#wlDays").value ? Number($("#wlDays").value) : -1;
    const data = await api("/api/admin/licenses", { method: "POST", body: JSON.stringify({ guild_id: $("#guildId").value.trim(), discord_id: $("#wlDiscord").value.trim(), days, note: $("#wlNote").value.trim() }) });
    msg(`Whitelisted. Key: ${data.license.key}`, "success");
    e.target.reset(); await loadProject();
  } catch (err) { msg(err.message, "error"); }
});

$("#compensateForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try { const data = await api("/api/admin/compensate", { method: "POST", body: JSON.stringify({ guild_id: $("#guildId").value.trim(), days: Number($("#compDays").value) }) }); msg(`Compensated ${data.changed} timed license(s).`, "success"); await loadProject(); }
  catch (err) { msg(err.message, "error"); }
});

$("#stockForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const data = await api("/api/admin/stock-keys", { method: "POST", body: JSON.stringify({ guild_id: $("#guildId").value.trim(), quantity: Number($("#stockQty").value), days: $("#stockDays").value ? Number($("#stockDays").value) : -1, note: $("#stockNote").value.trim() }) });
    await navigator.clipboard?.writeText(data.keys.join("\n"));
    msg(`Generated ${data.keys.length} key(s)${navigator.clipboard ? " and copied them" : ""}.`, "success");
    await loadProject();
  } catch (err) { msg(err.message, "error"); }
});

$("#copyStockBtn").onclick = async () => { if (!stockCache.length) return msg("No stock keys to copy.", "error"); await navigator.clipboard.writeText(stockCache.map(x => x.key).join("\n")); msg("Copied all unclaimed keys.", "success"); };

$("#blacklistForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try { await api("/api/admin/blacklists", { method: "POST", body: JSON.stringify({ guild_id: $("#guildId").value.trim(), discord_id: $("#blDiscord").value.trim(), reason: $("#blReason").value.trim(), days: $("#blDays").value ? Number($("#blDays").value) : -1 }) }); e.target.reset(); msg("User blacklisted.", "success"); await loadProject(); }
  catch (err) { msg(err.message, "error"); }
});


$("#copyLoaderUrlBtn").onclick = async () => {
  const url = $("#loaderUrl").value.trim();
  if (!url) return msg("Select a script first.", "error");
  try { await navigator.clipboard.writeText(url); msg("Loadstring copied.", "success"); }
  catch { msg("Could not copy the loadstring.", "error"); }
};

$("#copyFfaLoaderBtn").onclick = async () => {
  const script = scriptCache.find((row) => row.id === selectedScriptId);
  if (!script?.ffa_enabled || !script?.ffa_loader_url) return msg("Enable and save FFA for this script first.", "error");
  try { await navigator.clipboard.writeText(ffaLauncher(script.ffa_loader_url)); msg("FFA loader copied.", "success"); }
  catch { msg("Could not copy the FFA loader.", "error"); }
};

const SCRIPT_FILE_EXTENSIONS = new Set(["txt", "lua", "luau", "md", "cfg", "ini", "json", "js", "ts", "xml", "yaml", "yml", "py", "rb", "sh", "ps1", "bat", "cmd", "toml", "conf", "log"]);

function isAllowedScriptFile(file) {
  const name = String(file?.name || "");
  const ext = name.includes(".") ? name.split(".").pop().toLowerCase() : "";
  const mime = String(file?.type || "").toLowerCase();
  return SCRIPT_FILE_EXTENSIONS.has(ext) || mime.startsWith("text/");
}

function baseScriptName(fileName) {
  return String(fileName || "Uploaded Script").replace(/\.[^.]+$/, "") || "Uploaded Script";
}

$("#uploadScriptBtn").onclick = () => $("#scriptFileInput").click();
$("#scriptFileInput").addEventListener("change", async (e) => {
  const files = [...(e.target.files || [])];
  if (!files.length) return;
  const guildId = $("#guildId").value.trim();
  if (!guildId) { e.target.value = ""; return msg("Enter and load a Discord server ID first.", "error"); }

  try {
    const invalid = files.find((file) => !isAllowedScriptFile(file));
    if (invalid) throw new Error(`${invalid.name} is not a supported text/script file.`);
    msg(`Uploading ${files.length} script(s)…`);
    let last = null;
    for (const file of files) {
      const content = await file.text();
      if (!content.trim()) throw new Error(`${file.name} is empty.`);
      if (content.length > 2_000_000) throw new Error(`${file.name} is too large. Maximum source size is 2,000,000 characters.`);
      const data = await api("/api/admin/scripts", {
        method: "POST",
        body: JSON.stringify({
          guild_id: guildId,
          name: baseScriptName(file.name),
          version: "1.0.0",
          enabled: true,
          ffa_enabled: false,
          content,
          source_file_name: file.name,
        }),
      });
      last = data.script;
    }
    if (last) selectedScriptId = last.id;
    msg(`Uploaded ${files.length} script(s).`, "success");
    await loadProject();
  } catch (err) { msg(err.message, "error"); }
  finally { e.target.value = ""; }
});

$("#replaceScriptFileBtn").onclick = () => {
  if (!selectedScriptId) return msg("Select a script first.", "error");
  $("#replaceScriptFileInput").click();
};

$("#replaceScriptFileInput").addEventListener("change", async (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  try {
    if (!selectedScriptId) throw new Error("Select a script first.");
    if (!isAllowedScriptFile(file)) throw new Error(`${file.name} is not a supported text/script file.`);
    const content = await file.text();
    if (!content.trim()) throw new Error(`${file.name} is empty.`);
    if (content.length > 2_000_000) throw new Error(`${file.name} is too large. Maximum source size is 2,000,000 characters.`);
    await api(`/api/admin/scripts/${encodeURIComponent(selectedScriptId)}`, {
      method: "PUT",
      body: JSON.stringify({ content, source_file_name: file.name }),
    });
    msg(`Replaced protected source with ${file.name}.`, "success");
    await loadProject();
  } catch (err) { msg(err.message, "error"); }
  finally { e.target.value = ""; }
});

$("#deleteScriptBtn").onclick = () => {
  if (!selectedScriptId) return msg("Select a script first.", "error");
  deleteScript(selectedScriptId);
};

$("#scriptForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!selectedScriptId) return msg("Select an uploaded script first.", "error");
  try {
    const guildId = $("#guildId").value.trim();
    await Promise.all([
      api(`/api/admin/scripts/${encodeURIComponent(selectedScriptId)}`, {
        method: "PUT",
        body: JSON.stringify({
          name: $("#scriptName").value,
          version: $("#scriptVersion").value,
          enabled: $("#scriptEnabled").checked,
          ffa_enabled: $("#scriptFfaEnabled").checked,
        }),
      }),
      api("/api/admin/config", {
        method: "PUT",
        body: JSON.stringify({ guild_id: guildId, loader_template: $("#loaderTemplate").value }),
      }),
    ]);
    msg("Script metadata saved.", "success");
    await loadProject();
  } catch (err) { msg(err.message, "error"); }
});

$("#refreshBackendBtn").onclick = () => loadBackendStatus(true);

$("#adminPasswordForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const currentPassword = $("#currentAdminPassword").value;
  const newPassword = $("#newAdminPassword").value;
  const confirmPassword = $("#confirmAdminPassword").value;
  if (newPassword !== confirmPassword) return msg("New passwords do not match.", "error");
  if (newPassword.length < 12) return msg("New admin password must be at least 12 characters.", "error");
  try {
    await api("/api/admin/account/password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
    e.target.reset();
    alert("Admin password changed. All admin sessions were revoked. Sign in with the new password.");
    location.reload();
  } catch (error) {
    msg(error.message, "error");
  }
});

function setActiveTab(btn, persist = true) {
  $$('[data-tab]').forEach(x => x.classList.toggle('active', x === btn));
  $$('[data-pane]').forEach(p => p.classList.toggle('hidden', p.dataset.pane !== btn.dataset.tab));
  const label = (btn.textContent || btn.dataset.tab || 'Overview').trim();
  const crumb = $('#sectionCrumb');
  const title = $('#sectionTitle');
  if (crumb) crumb.textContent = label;
  if (title) title.textContent = label;
  if (btn.dataset.tab === 'backend') loadBackendStatus(false);
  if (persist && !$("#appView").classList.contains("hidden")) {
    void saveBackendState({ active_tab: btn.dataset.tab });
  }
}

$$('[data-tab]').forEach(btn => btn.onclick = () => setActiveTab(btn, true));

(async () => {
  // No project/admin state is stored in localStorage. Backend state is restored after login.
  $("#guildId").value = "";
  const active = $('[data-tab].active') || $('[data-tab]');
  if (active) setActiveTab(active, false);
})();
