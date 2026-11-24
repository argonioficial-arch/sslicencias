import { serve, rpc, device, Fail } from "./core.ts";
serve("device-deactivate", [10, 600], async (b, ip) => {
  const dv = await device(b, "device-deactivate");
  const r = await rpc("lic_device_deactivate", { p_device: dv.id, p_seq: dv.seq, p_ip: ip });
  if (!r.ok) throw new Fail(r.error, 200, r);
  return r;
});
