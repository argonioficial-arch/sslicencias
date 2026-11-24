import { serve, rpc, device, openSigned, grant, Fail } from "./core.ts";
serve("activate-serial", [15, 600], async (b, ip) => {
  if (typeof b.serial !== "string" || b.serial.length > 40 || !b.ticket) throw new Fail("BAD_REQUEST");
  const dv = await device(b, "activate-serial", String(b.ticket.s));
  const t = await openSigned(b.ticket);
  if (t.t !== "user" || t.did !== dv.id || t.exp < Date.now() / 1000) throw new Fail("TICKET_EXPIRED", 401);
  const r = await rpc("lic_activate", { p_device: dv.id, p_serial: b.serial, p_user: t.uid, p_seq: dv.seq, p_ip: ip });
  if (!r.ok) throw new Fail(r.error, 200, r);
  return await grant(dv.id, r);
});
