import { serve, db, device, sign, Fail } from "./core.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.4";
serve("device-authenticate", [20, 600], async (b, ip) => {
  const email = String(b.email || "").trim().toLowerCase(), password = String(b.password || "");
  if (!email || !password || password.length > 72) throw new Fail("BAD_REQUEST");
  const dv = await device(b, "device-authenticate", email, true, ip);
  const { data: rl } = await db.rpc("lic_rate", { p_key: "auth:" + email, p_limit: 8, p_secs: 600 });
  if (rl === false) throw new Fail("RATE_LIMITED", 429);
  const anon = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, { auth: { persistSession: false } });
  const s = await anon.auth.signInWithPassword({ email, password });
  if (s.error || !s.data.user) throw new Fail("BAD_CREDENTIALS", 401);
  const { data: u } = await db.from("users").select("id,status,email").eq("auth_user_id", s.data.user.id).maybeSingle();
  if (!u || u.status !== "active") throw new Fail("USER_NOT_AUTHORIZED");
  const now = Math.floor(Date.now() / 1000);
  return { ok: true, email: u.email, ticket: await sign({ t: "user", uid: u.id, did: dv.id, exp: now + 300 }) };
});
