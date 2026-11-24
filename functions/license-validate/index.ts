import { serve, rpc, device, grant, Fail } from "./core.ts";
serve("license-validate", [60, 600], async (b, ip) => {
  const dv = await device(b, "license-validate");
  const r = await rpc("lic_validate", { p_device: dv.id, p_seq: dv.seq, p_ip: ip, p_log: true });
  if (!r.ok) throw new Fail(r.error, 200, r);
  return await grant(dv.id, r);
});
