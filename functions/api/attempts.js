const enc = new TextEncoder();
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
function from64(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); s += "=".repeat((4 - s.length % 4) % 4); return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
async function currentUser(request, env) {
  const token = (request.headers.get("Cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith("tbmaster_session="))?.slice("tbmaster_session=".length);
  if (!token || !env.JWT_SECRET) return null;
  try {
    const [body, sig] = decodeURIComponent(token).split(".");
    const key = await crypto.subtle.importKey("raw", enc.encode(env.JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    if (!await crypto.subtle.verify("HMAC", key, from64(sig), enc.encode(body))) return null;
    const payload = JSON.parse(new TextDecoder().decode(from64(body)));
    if (payload.exp <= Date.now() / 1000) return null;
    return payload.sub;
  } catch { return null; }
}
export async function onRequest(context) {
  const { request, env } = context;
  if (!env.DB) return json({ error: "D1 не подключена" }, 503);
  const userId = await currentUser(request, env);
  if (!userId) return json({ error: "Войдите в аккаунт, чтобы синхронизировать историю.", attempts: [] }, 401);
  if (request.method === "GET") {
    const { results = [] } = await env.DB.prepare("SELECT id, category, mode, total, correct, percent, elapsed, created_at AS date FROM attempts WHERE user_id = ? ORDER BY created_at DESC LIMIT 50").bind(userId).all();
    return json({ attempts: results });
  }
  if (request.method !== "POST") return json({ error: "Метод не поддерживается" }, 405);
  let data; try { data = await request.json(); } catch { return json({ error: "Неверный JSON" }, 400); }
  const total = Math.max(0, Math.min(1000, Math.floor(Number(data.total) || 0)));
  const correct = Math.max(0, Math.min(total, Math.floor(Number(data.correct) || 0)));
  const percent = Math.round(correct / Math.max(1, total) * 100);
  const elapsed = Math.max(0, Math.min(86400, Math.floor(Number(data.elapsed) || 0)));
  const category = String(data.category || "Все темы").slice(0, 120);
  const mode = data.mode === "exam" ? "exam" : "study";
  await env.DB.prepare("INSERT INTO attempts (user_id, category, mode, total, correct, percent, elapsed, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))").bind(userId, category, mode, total, correct, percent, elapsed).run();
  return json({ ok: true, percent }, 201);
}