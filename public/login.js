const $ = (s) => document.querySelector(s);

async function postJson(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  let data = null;
  try { data = await res.json(); } catch {}
  return { ok: res.ok && (data?.ok !== false), status: res.status, data };
}

// If a valid session cookie is already present, skip the form and go to the
// dashboard. Avoids re-typing the password after every reload.
(async () => {
  try {
    const res = await fetch("/api/admin/csrf", { method: "GET" });
    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (data?.ok) {
        location.replace("/");
        return;
      }
    }
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
  out.textContent = "Signed in. Loading dashboard…";
  out.className = "msg success";
  location.replace("/");
});
