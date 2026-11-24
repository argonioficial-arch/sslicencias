import { serve, rpc, db, Fail } from "./core.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.4";
serve("user-register", [8, 600], async (b, ip) => {
  const email = String(b.email || "").trim().toLowerCase(), password = String(b.password || ""), name = String(b.name || "").trim().slice(0, 120);
  if (!/^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$/.test(email) || password.length < 8 || password.length > 72 || typeof b.serial !== "string") throw new Fail("BAD_REQUEST");
  let authId: string, created = false;
  const c = await db.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { full_name: name } });
  if (c.data?.user) { authId = c.data.user.id; created = true; }
  else {
    /* la cuenta ya existe: solo se acepta si la contraseña es correcta */
    const anon = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, { auth: { persistSession: false } });
    const s = await anon.auth.signInWithPassword({ email, password });
    if (s.error || !s.data.user) throw new Fail("BAD_CREDENTIALS", 401);
    authId = s.data.user.id;
  }
  const r = await rpc("lic_user_register", { p_auth: authId, p_email: email, p_name: name, p_serial: b.serial, p_ip: ip });
  if (!r.ok) { if (created) await db.auth.admin.deleteUser(authId); throw new Fail(r.error, 200, r); }
  return r;
});
