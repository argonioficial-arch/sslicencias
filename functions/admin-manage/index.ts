import { serve, rpc, db, admin, isUuid, Fail } from "./core.ts";
/* Admin: gestión del resto (licencias, usuarios, series, dispositivos). */
serve("admin-manage", [90, 60], async (b, ip, req) => {
  if (b.action === "bootstrap") { /* primer administrador: un solo uso, con el token de instalación */
    const { data: t } = await db.from("license_config").select("value").eq("key", "admin_bootstrap_token").maybeSingle();
    const email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || "");
    if (!t || !b.token || b.token !== t.value || pw.length < 10 || !email.includes("@")) throw new Fail("FORBIDDEN", 403);
    const { count } = await db.from("admins").select("user_id", { count: "exact", head: true });
    if (count) throw new Fail("FORBIDDEN", 403);
    const c = await db.auth.admin.createUser({ email, password: pw, email_confirm: true });
    if (!c.data?.user) throw new Fail("BAD_REQUEST");
    await db.from("admins").insert({ user_id: c.data.user.id });
    await db.from("license_config").delete().eq("key", "admin_bootstrap_token");
    await rpc("lic_log", { p_license: null, p_type: "admin", p_actor: c.data.user.id, p_action: "admin_bootstrap", p_details: { email }, p_ip: ip });
    return { ok: true };
  }
  const actor = await admin(req);
  let r: any;
  switch (b.action) {
    case "stats": r = { ok: true, stats: await rpc("lic_stats", {}) }; break;
    case "license_save": {
      const x = b.license || {};
      r = await rpc("lic_license_save", { p_id: x.id && isUuid(x.id) ? x.id : null, p_key: x.license_key || null, p_customer_id: x.customer_id || null, p_customer_name: x.customer_name || null, p_max_radios: Number(x.max_radios), p_max_users: Number(x.max_users), p_status: x.status || "active", p_expires: x.expires_at || null, p_grace: Number(x.offline_grace_hours || 24), p_actor: actor });
      break;
    }
    case "serial_set": if (!isUuid(b.id)) throw new Fail("BAD_REQUEST"); r = await rpc("lic_serial_set_status", { p_serial: b.id, p_status: b.status, p_actor: actor }); break;
    case "device_set": if (!isUuid(b.id)) throw new Fail("BAD_REQUEST"); r = await rpc("lic_device_set_status", { p_device: b.id, p_status: b.status, p_actor: actor }); break;
    case "device_release": if (!isUuid(b.id)) throw new Fail("BAD_REQUEST"); r = await rpc("lic_release", { p_device: b.id, p_reissue: b.reissue !== false, p_actor_type: "admin", p_actor: actor, p_ip: ip }); break;
    case "license_user_set": if (!isUuid(b.license_id) || !isUuid(b.user_id)) throw new Fail("BAD_REQUEST"); r = await rpc("lic_license_user_set", { p_license: b.license_id, p_user: b.user_id, p_status: b.status, p_actor: actor }); break;
    case "user_multi": if (!isUuid(b.user_id)) throw new Fail("BAD_REQUEST"); await db.from("users").update({ multi_license: !!b.value }).eq("id", b.user_id); r = { ok: true }; break;
    case "user_create": {
      const email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || "");
      if (!isUuid(b.license_id) || !email.includes("@") || pw.length < 8) throw new Fail("BAD_REQUEST");
      const c = await db.auth.admin.createUser({ email, password: pw, email_confirm: true, user_metadata: { full_name: b.name || "" } });
      if (!c.data?.user) throw new Fail("USER_EXISTS");
      const uid = await rpc("lic_user_upsert", { p_auth: c.data.user.id, p_email: email, p_name: String(b.name || "") });
      r = await rpc("lic_link_user", { p_license: b.license_id, p_user: uid, p_actor_type: "admin", p_actor: actor });
      if (!r.ok) await db.auth.admin.deleteUser(c.data.user.id);
      break;
    }
    default: throw new Fail("BAD_REQUEST");
  }
  if (!r.ok) throw new Fail(r.error, 200, r);
  return r;
});
