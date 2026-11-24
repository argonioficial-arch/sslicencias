import { createClient } from "npm:@supabase/supabase-js@2.45.4";
const E = (k: string) => Deno.env.get(k)!;
export const db = createClient(E("SUPABASE_URL"), E("SUPABASE_SERVICE_ROLE_KEY"), { auth: { persistSession: false, autoRefreshToken: false } });
const H = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info", "Access-Control-Allow-Methods": "POST, OPTIONS", "Content-Type": "application/json" };
export class Fail extends Error { constructor(public code: string, public status = 200, public extra: Record<string, unknown> = {}) { super(code); } }
const enc = new TextEncoder();
export const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
export const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function serve(name: string, limit: [number, number], fn: (b: any, ip: string, req: Request) => Promise<unknown>) {
  Deno.serve(async (req) => {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: H });
    try {
      if (req.method !== "POST") throw new Fail("BAD_REQUEST", 405);
      const raw = await req.text();
      if (raw.length > 20000) throw new Fail("BAD_REQUEST", 413);
      let b: any; try { b = JSON.parse(raw || "{}"); } catch { throw new Fail("BAD_REQUEST", 400); }
      if (!b || typeof b !== "object") throw new Fail("BAD_REQUEST", 400);
      const ip = (req.headers.get("x-forwarded-for") || "").split(",")[0].trim() || "?";
      const { data: ok } = await db.rpc("lic_rate", { p_key: name + ":" + ip, p_limit: limit[0], p_secs: limit[1] });
      if (ok === false) throw new Fail("RATE_LIMITED", 429);
      return new Response(JSON.stringify(await fn(b, ip, req)), { headers: H });
    } catch (e) {
      if (e instanceof Fail) return new Response(JSON.stringify({ ok: false, error: e.code, ...e.extra }), { status: e.status, headers: H });
      console.error(name, e);
      return new Response(JSON.stringify({ ok: false, error: "SERVER_ERROR" }), { status: 500, headers: H });
    }
  });
}
export async function rpc(fn: string, args: Record<string, unknown>) {
  const { data, error } = await db.rpc(fn, args);
  if (error) { console.error(fn, error.message); throw new Fail("SERVER_ERROR", 500); }
  return data as any;
}

/* ---- claves de firma del servidor (Ed25519). La privada nunca sale de license_config ---- */
let K: { priv: CryptoKey; pub: CryptoKey; pubB64: string } | null = null;
export async function keys() {
  if (K) return K;
  const get = async () => Object.fromEntries(((await db.from("license_config").select("key,value").in("key", ["sign_priv", "sign_pub"])).data || []).map((r: any) => [r.key, r.value]));
  let m: any = await get();
  if (!m.sign_priv || !m.sign_pub) {
    const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const priv = b64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey)));
    const pub = b64(new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey)));
    await db.from("license_config").upsert([{ key: "sign_priv", value: priv }, { key: "sign_pub", value: pub }], { onConflict: "key", ignoreDuplicates: true });
    m = await get();
  }
  K = { priv: await crypto.subtle.importKey("pkcs8", unb64(m.sign_priv), "Ed25519", false, ["sign"]), pub: await crypto.subtle.importKey("spki", unb64(m.sign_pub), "Ed25519", false, ["verify"]), pubB64: m.sign_pub };
  return K;
}
export async function sign(o: unknown) {
  const p = JSON.stringify(o);
  return { p, s: b64(new Uint8Array(await crypto.subtle.sign("Ed25519", (await keys()).priv, enc.encode(p)))) };
}
export async function openSigned(t: any) {
  if (!t || typeof t.p !== "string" || typeof t.s !== "string") throw new Fail("BAD_REQUEST");
  let ok = false; try { ok = await crypto.subtle.verify("Ed25519", (await keys()).pub, unb64(t.s), enc.encode(t.p)); } catch { /* */ }
  if (!ok) throw new Fail("BAD_SIGNATURE", 401);
  return JSON.parse(t.p);
}

/* ---- identidad del dispositivo: firma Ed25519 sobre fn|device|seq|ts|extra ---- */
export async function device(b: any, fn: string, extra = "", touch = false, ip = "") {
  const { device_id: id, seq, ts, sig } = b;
  if (typeof id !== "string" || !/^[0-9a-f-]{36}$/.test(id) || !Number.isSafeInteger(seq) || !Number.isSafeInteger(ts) || typeof sig !== "string") throw new Fail("BAD_REQUEST");
  if (Math.abs(Date.now() - ts) > 10 * 60e3) throw new Fail("CLOCK_SKEW");
  const { data: d } = await db.from("devices").select("public_key").eq("id", id).maybeSingle();
  if (!d) throw new Fail("DEVICE_NOT_FOUND");
  let ok = false;
  try { ok = await crypto.subtle.verify("Ed25519", await crypto.subtle.importKey("spki", unb64(d.public_key), "Ed25519", false, ["verify"]), unb64(sig), enc.encode([fn, id, seq, ts, extra].join("|"))); } catch { /* */ }
  if (!ok) throw new Fail("BAD_SIGNATURE", 401);
  if (touch) { const t = await rpc("lic_touch", { p_device: id, p_seq: seq, p_ip: ip }); if (!t.ok) throw new Fail(t.error); }
  return { id, seq: seq as number };
}
/* autorización firmada: caduca al terminar el periodo de gracia (o antes si caduca la licencia) */
export async function grant(id: string, r: any) {
  const iat = Math.floor(Date.now() / 1000);
  let exp = iat + Number(r.grace_hours) * 3600;
  if (r.license_expires_at) exp = Math.min(exp, Math.floor(new Date(r.license_expires_at).getTime() / 1000));
  return { ok: true, now: iat, grace_hours: r.grace_hours, auth: await sign({ v: 1, did: id, lid: r.license_id, lk: r.license_key, uid: r.user_id, em: r.user_email, iat, exp }) };
}
/* administrador: JWT de Supabase Auth + fila en public.admins */
export async function admin(req: Request) {
  const jwt = (req.headers.get("authorization") || "").replace(/^Bearer /i, "");
  const { data, error } = await db.auth.getUser(jwt);
  if (error || !data.user) throw new Fail("UNAUTHORIZED", 401);
  const { data: a } = await db.from("admins").select("user_id").eq("user_id", data.user.id).maybeSingle();
  if (!a) throw new Fail("FORBIDDEN", 403);
  return data.user.id;
}
export const isUuid = (s: unknown) => typeof s === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
