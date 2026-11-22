/* Hố Đen – máy chủ đồng bộ tiến độ (Cloudflare Worker + KV)
   Binding bắt buộc: BH_KV (KV Namespace). Tuỳ chọn: ALLOWED_ORIGIN (vd https://ten.github.io) */
const enc = new TextEncoder();
const ITER = 10000;              // đủ nhẹ cho gói miễn phí của Cloudflare
const TOKEN_DAYS = 90, MAX_FAILS = 10, LOCK_SEC = 900, MAXL = 10000;

const cors = env => ({
  'Access-Control-Allow-Origin': (env && env.ALLOWED_ORIGIN) || '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
  'Vary': 'Origin'
});
const out = (env, o, s = 200) => new Response(JSON.stringify(o), {
  status: s, headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store', ...cors(env) }
});
const fail = (env, err, s = 400) => out(env, { ok: false, err }, s);

const toHex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const fromHex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const same = (a, b) => { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0 };

async function hashPw(pw, saltHex, iter) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return toHex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations: iter }, k, 256));
}

let SECRET = null;
async function secretKey(env) {
  if (!SECRET) {
    let s = await env.BH_KV.get('cfg:secret');
    if (!s) { s = toHex(crypto.getRandomValues(new Uint8Array(32))); await env.BH_KV.put('cfg:secret', s) }
    SECRET = await crypto.subtle.importKey('raw', enc.encode(s), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  }
  return SECRET;
}
async function makeToken(env, key) {
  const p = b64u(enc.encode(JSON.stringify({ k: key, e: Date.now() + TOKEN_DAYS * 864e5 })));
  const sig = await crypto.subtle.sign('HMAC', await secretKey(env), enc.encode(p));
  return p + '.' + b64u(sig);
}
async function readToken(env, req) {
  const m = /^Bearer\s+(\S+)$/.exec(req.headers.get('Authorization') || ''); if (!m) return null;
  const [p, s] = m[1].split('.'); if (!p || !s) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await secretKey(env), unb64u(s), enc.encode(p));
    if (!ok) return null;
    const o = JSON.parse(new TextDecoder().decode(unb64u(p)));
    return o.e > Date.now() ? o.k : null;
  } catch (e) { return null }
}

const normName = u => String(u || '').normalize('NFC').trim();
const nameKey = u => normName(u).toLowerCase();
const validName = u => { const n = normName(u); return n.length >= 1 && n.length <= 30 && !/[\u0000-\u001f\u007f]/.test(n) };
const validPw = p => typeof p === 'string' && p.length >= 1 && p.length <= 200;

const GFXS = ['ultra', 'normal', 'low'];
function clean(d) {
  d = d && typeof d === 'object' ? d : {};
  const i = (v, lo, hi, df) => Number.isInteger(v) && v >= lo && v <= hi ? v : df;
  return {
    d: i(d.d, 0, MAXL, 0),
    l: d.l === 0 ? 0 : 1,
    g: GFXS.includes(d.g) ? d.g : null,
    s: i(d.s, -1, 99, -1),
    ts: i(d.ts, 0, Date.now() + 864e5, 0)
  };
}
// Gộp dữ liệu: số màn luôn lấy giá trị cao hơn; tuỳ chọn lấy từ bên mới hơn
function merge(a, b) {
  const r = { ...a };
  r.d = Math.max(a.d, b.d);
  if (b.ts > a.ts) { r.l = b.l; r.s = b.s; r.ts = b.ts; if (b.g) r.g = b.g }
  else if (!a.g && b.g) r.g = b.g;
  return r;
}

async function body(req) { try { return await req.json() } catch (e) { return {} } }

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(env) });
    if (!env.BH_KV) return fail(env, 'Máy chủ chưa gắn KV (BH_KV)', 500);
    const path = new URL(req.url).pathname.replace(/\/+$/, '') || '/';
    try {
      if (req.method === 'GET' && path === '/') return out(env, { ok: true, name: 'holden-sync' });
      if (req.method !== 'POST') return fail(env, 'Không hỗ trợ', 405);

      if (path === '/register') {
        const b = await body(req);
        if (!validName(b.u)) return fail(env, 'Tên đăng nhập dài 1–30 ký tự');
        if (!validPw(b.p)) return fail(env, 'Mật khẩu cần ít nhất 1 ký tự');
        const key = nameKey(b.u);
        if (await env.BH_KV.get('u:' + key)) return fail(env, 'Tên đăng nhập đã có người dùng', 409);
        const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
        const user = { name: normName(b.u), salt, iter: ITER, hash: await hashPw(b.p, salt, ITER), created: Date.now(), data: merge(clean(null), clean(b.data)) };
        await env.BH_KV.put('u:' + key, JSON.stringify(user));
        return out(env, { ok: true, token: await makeToken(env, key), user: user.name, data: user.data });
      }

      if (path === '/login') {
        const b = await body(req);
        if (!validName(b.u) || !validPw(b.p)) return fail(env, 'Sai tên đăng nhập hoặc mật khẩu', 401);
        const key = nameKey(b.u), fk = 'f:' + key;
        const fails = parseInt(await env.BH_KV.get(fk)) || 0;
        if (fails >= MAX_FAILS) return fail(env, 'Thử sai quá nhiều lần, hãy thử lại sau 15 phút', 429);
        const raw = await env.BH_KV.get('u:' + key);
        const user = raw && JSON.parse(raw);
        const ok = user && same(await hashPw(b.p, user.salt, user.iter), user.hash);
        if (!ok) { await env.BH_KV.put(fk, String(fails + 1), { expirationTtl: LOCK_SEC }); return fail(env, 'Sai tên đăng nhập hoặc mật khẩu', 401) }
        if (fails) await env.BH_KV.delete(fk);
        return out(env, { ok: true, token: await makeToken(env, key), user: user.name, data: user.data });
      }

      if (path === '/sync') {
        const key = await readToken(env, req);
        if (!key) return fail(env, 'Phiên đăng nhập đã hết hạn', 401);
        const raw = await env.BH_KV.get('u:' + key);
        if (!raw) return fail(env, 'Tài khoản không tồn tại', 401);
        const user = JSON.parse(raw), b = await body(req);
        const m = merge(clean(user.data), clean(b.data));
        if (JSON.stringify(m) !== JSON.stringify(user.data)) { user.data = m; await env.BH_KV.put('u:' + key, JSON.stringify(user)) }
        return out(env, { ok: true, user: user.name, data: m });
      }

      if (path === '/logout') return out(env, { ok: true });
      return fail(env, 'Không tìm thấy', 404);
    } catch (e) { return fail(env, 'Lỗi máy chủ', 500) }
  }
};
