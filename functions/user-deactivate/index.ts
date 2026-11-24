import { serve, rpc, db, admin, isUuid, Fail } from "./core.ts";
/* Admin: desactivar/reactivar un usuario (global) o solo su vínculo con una licencia */
serve("user-deactivate", [60, 60], async (b, _ip, req) => {
  const actor = await admin(req);
  if (!isUuid(b.user_id) || !["active", "disabled"].includes(b.status) || (b.license_id && !isUuid(b.license_id))) throw new Fail("BAD_REQUEST");
  let r;
  if (b.license_id) r = await rpc("lic_license_user_set", { p_license: b.license_id, p_user: b.user_id, p_status: b.status, p_actor: actor });
  else {
    r = await rpc("lic_user_set_status", { p_user: b.user_id, p_status: b.status, p_actor: actor });
    if (r.ok) {
      const { data: u } = await db.from("users").select("auth_user_id").eq("id", b.user_id).maybeSingle();
      if (u) await db.auth.admin.updateUserById(u.auth_user_id, { ban_duration: b.status === "disabled" ? "876000h" : "none" });
    }
  }
  if (!r.ok) throw new Fail(r.error, 200, r);
  return r;
});
