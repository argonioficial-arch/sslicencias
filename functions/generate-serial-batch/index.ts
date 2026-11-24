import { serve, rpc, admin, isUuid, Fail } from "./core.ts";
/* Admin: genera un lote. Los códigos solo se devuelven en esta respuesta; en la base solo queda el hash. */
serve("generate-serial-batch", [20, 60], async (b, _ip, req) => {
  const actor = await admin(req);
  const qty = Number(b.quantity), name = String(b.batch_name || "").trim().slice(0, 60);
  if (!isUuid(b.license_id) || !Number.isInteger(qty) || qty < 1 || qty > 200 || !name) throw new Fail("BAD_REQUEST");
  const r = await rpc("lic_gen_batch", { p_license: b.license_id, p_name: name, p_qty: qty, p_actor: actor });
  if (!r.ok) throw new Fail(r.error, 200, r);
  return r;
});
