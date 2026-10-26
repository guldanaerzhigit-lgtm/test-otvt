const enc = new TextEncoder();
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const cookieName = "tbmaster_session";
function b64url(bytes) { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_"); }
function unb64url(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); s += "=".repeat((4 - s.length % 4) % 4); return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
async function sign(payload, secret) { const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); const body = b64url(enc.encode(JSON.stringify(payload))); const sig = b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(body)))); return body + "." + sig; }
async function verify(token, secret) { try { const [body, sig] = token.split("."); const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]); if (!await crypto.subtle.verify("HMAC", key, unb64url(sig), enc.encode(body))) return null; const p = JSON.parse(new TextDecoder().decode(unb64url(body))); return p.exp > Date.now() / 1000 ? p : null; } catch { return null; } }
function getToken(request) { const raw = request.headers.get("Cookie") || ""; const pair = raw.split(";").map(x => x.trim()).find(x => x.startsWith(cookieName + "=")); return pair ? decodeURIComponent(pair.slice(cookieName.length + 1)) : ""; }
async function hashPassword(password, salt) { const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]); const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" }, key, 256); return b64url(new Uint8Array(bits)); }
function cookie(value, maxAge) { return cookieName + "=" + encodeURIComponent(value) + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + maxAge; }
async function userFromRequest(request, env) { if (!env.JWT_SECRET) return null; const p = await verify(getToken(request), env.JWT_SECRET); if (!p) return null; const row = await env.DB.prepare("SELECT id, username FROM users WHERE id = ?").bind(p.sub).first(); return row || null; }
export async function onRequest(context) {
  const { request, env } = context;
  if (!env.DB) return json({ error: "D1 не подключена. Сначала создайте базу и настройте binding DB." }, 503);
  if (!env.JWT_SECRET) return json({ error: "Не задан секрет JWT_SECRET в настройках Cloudflare." }, 503);
  if (request.method === "GET") { const user = await userFromRequest(request, env); return json({ user: user ? { id: user.id, username: user.username } : null }); }
  if (request.method !== "POST") return json({ error: "Метод не поддерживается" }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: "Неверный JSON" }, 400); }
  const action = String(body.action || "");
  if (action === "logout") return json({ ok: true }, 200, { "set-cookie": cookie("", 0) });
  if (action === "register") {
    const username = String(body.username || "").trim();
    const password = String(body.password || "");
    if (!/^[a-zA-Z0-9_.-]{3,30}$/.test(username)) return json({ error: "Имя пользователя: 3–30 символов, латиница, цифры, точка, дефис или подчёркивание." }, 400);
    if (password.length < 8 || password.length > 128) return json({ error: "Пароль должен содержать от 8 до 128 символов." }, 400);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const passwordHash = await hashPassword(password, salt);
    const saltText = b64url(salt);
    try {
      const id = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO users (id, username, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, datetime('now'))").bind(id, username, passwordHash, saltText).run();
      const token = await sign({ sub: id, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 14 }, env.JWT_SECRET);
      return json({ user: { id, username } }, 201, { "set-cookie": cookie(token, 60 * 60 * 24 * 14) });
    } catch (e) { return json({ error: "Такое имя пользователя уже занято." }, 409); }
  }
  if (action === "login") {
    const username = String(body.username || "").trim();
    const password = String(body.password || "");
    const row = await env.DB.prepare("SELECT id, username, password_hash, password_salt FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
    if (!row) return json({ error: "Неверное имя пользователя или пароль." }, 401);
    const actual = await hashPassword(password, unb64url(row.password_salt));
    if (actual !== row.password_hash) return json({ error: "Неверное имя пользователя или пароль." }, 401);
    const token = await sign({ sub: row.id, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 14 }, env.JWT_SECRET);
    return json({ user: { id: row.id, username: row.username } }, 200, { "set-cookie": cookie(token, 60 * 60 * 24 * 14) });
  }
  if (action === "me") { const user = await userFromRequest(request, env); return json({ user: user ? { id: user.id, username: user.username } : null }); }
  return json({ error: "Неизвестное действие." }, 400);
}