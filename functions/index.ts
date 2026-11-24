import { serve, rpc, keys, Fail } from "./core.ts";
serve("device-register", [30, 600], async (b, ip) => {
  const { pub, hw, family, name, ver } = b;
  if (typeof pub !== "string" || pub.length < 40 || pub.length > 200 || !["v1", "v2", "v3"].includes(family)) throw new Fail("BAD_REQUEST");
  const r = await rpc("lic_device_register", { p_pub: pub, p_hw: String(hw || ""), p_family: family, p_name: String(name || ""), p_ver: String(ver || ""), p_ip: ip });
  if (!r.ok) throw new Fail(r.error);
  return { ...r, server_key: (await keys()).pubB64 };
});
