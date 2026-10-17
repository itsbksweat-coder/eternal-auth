const $ = (s) => document.querySelector(s);
const SESSION_STORAGE_KEY = "_vq";

function storedToken() {
  try { return localStorage.getItem(SESSION_STORAGE_KEY) || ""; } catch { return ""; }
}
function saveToken(token) {
  try { localStorage.setItem(SESSION_STORAGE_KEY, token || ""); } catch {}
}
function clearToken() {
  try { localStorage.removeItem(SESSION_STORAGE_KEY); } catch {}
}

async function postJson(path, body, extraHeaders = {}) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...extraHeaders },
    body: JSON.stringify(body ?? {}),
  });
  let data = null;
  try { data = await res.json(); } catch {}
  return { ok: res.ok && (data?.ok !== false), status: res.status, data };
}

// On entry: if we already have a session (via Authorization header from
// localStorage, or an existing cookie), skip the form. The server re-stamps
// the cookie cluster on /api/admin/csrf, so clearing cookies and reloading
// the login page silently re-establishes the session as long as localStorage
// still has the token.
(async () => {
  const token = storedToken();
  const headers = token ? { authorization: `Bearer ${token}` } : {};
  try {
    const res = await fetch("/api/admin/csrf", { method: "GET", headers });
    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (data?.ok) {
        location.replace("/");
        return;
      }
    }
    // 401 / anything else: fall through to the form. Nuke stale token.
    if (res.status === 401) clearToken();
  } catch {}
})();

$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#loginMsg");
  out.textContent = "Signing in…";
  out.className = "msg";
  const password = $("#password").value;
  const { ok, status, data } = await postJson("/api/admin/login", { password });
  if (!ok) {
    out.textContent = data?.error || `Sign-in failed (HTTP ${status})`;
    out.className = "msg error";
    return;
  }
  if (data?.token) saveToken(String(data.token));
  out.textContent = "Signed in. Loading dashboard…";
  out.className = "msg success";
  location.replace("/");
});
