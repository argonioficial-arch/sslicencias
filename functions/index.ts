import { serve, rpc, device, grant, Fail } from "./core.ts";
serve("device-heartbeat", [120, 3600], async (b, ip) => {
  const dv = await device(b, "device-heartbeat");
  const r = await rpc("lic_validate", { p_device: dv.id, p_seq: dv.seq, p_ip: ip, p_log: false });
  if (!r.ok) throw new Fail(r.error, 200, r);
  return await grant(dv.id, r);
});
