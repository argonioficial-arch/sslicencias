"use strict";
/* Cliente de licencias compartido por Radio MRP (v1), Radio RP V2 y Radio RP (v3).
   Sin dependencias: solo Node/Electron. La lógica de validación vive en el servidor (Supabase);
   aquí solo se firma con la identidad del equipo y se comprueban autorizaciones firmadas por el servidor. */
const crypto = require("crypto"), fs = require("fs"), os = require("os"), path = require("path");

const SUPABASE_URL = "https://czsxxznvhxkxapxlygyo.supabase.co";
const APIKEY = "sb_publishable_tTVr7X63HKgMFGWKYtV_-A_H41-HlRg"; // clave pública (no es service_role)
/* clave pública Ed25519 del servidor (fijada): una respuesta falsa no puede firmarse sin la privada */
const SERVER_PUBKEY = "MCowBQYDK2VwAyEA7rEi8Y6QStzwd6XGWSaoVFQxczIlSzTRT3cLPohzuMM=";
const SKEW = 5 * 60 * 1000;

const b64 = (b) => Buffer.from(b).toString("base64");
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const serverKey = (pub) => crypto.createPublicKey({ key: Buffer.from(pub || SERVER_PUBKEY, "base64"), format: "der", type: "spki" });

function hardwareId() {
  let guid = "";
  try {
    if (process.platform === "win32") guid = require("child_process").execFileSync("reg", ["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"], { encoding: "utf8", timeout: 4000, windowsHide: true }).split(/\s+/).pop();
    else if (fs.existsSync("/etc/machine-id")) guid = fs.readFileSync("/etc/machine-id", "utf8").trim();
  } catch (e) { /* */ }
  const nic = Object.values(os.networkInterfaces()).flat().filter((n) => n && !n.internal && n.mac && n.mac !== "00:00:00:00:00:00").map((n) => n.mac).sort()[0] || "";
  return sha(["rp1", guid, os.hostname(), (os.cpus()[0] || {}).model || "", nic].join("|")).slice(0, 40);
}

class License {
  /* opts: { dir, family: 'v1'|'v2'|'v3', version, name, safeStorage?, fetch?, serverPubkey?, url?, now? } */
  constructor(o) {
    this.o = o; this.file = path.join(o.dir, "license.dat");
    this.url = (o.url || SUPABASE_URL).replace(/\/+$/, ""); this.f = o.fetch || globalThis.fetch;
    this.spk = serverKey(o.serverPubkey); this.now = o.now || (() => Date.now());
    this.S = this._load(); this.hbT = null;
  }
  /* ---- almacenamiento local: la clave privada va cifrada con DPAPI (safeStorage) si existe ---- */
  _enc(s) { const ss = this.o.safeStorage; if (ss && ss.isEncryptionAvailable && ss.isEncryptionAvailable()) return "s:" + b64(ss.encryptString(s)); return "p:" + b64(s); }
  _dec(s) { if (!s) return null; const ss = this.o.safeStorage; if (s.startsWith("s:")) return ss.decryptString(Buffer.from(s.slice(2), "base64")); return Buffer.from(s.slice(2), "base64").toString(); }
  _load() { try { return JSON.parse(fs.readFileSync(this.file, "utf8")); } catch (e) { return {}; } }
  _save() { try { fs.mkdirSync(path.dirname(this.file), { recursive: true }); const t = this.file + ".tmp"; fs.writeFileSync(t, JSON.stringify(this.S)); fs.renameSync(t, this.file); } catch (e) { /* */ } }
  _identity() {
    const S = this.S;
    if (!S.pub || !S.priv || (S.hw && S.hw !== hardwareId())) { // identidad nueva (o fichero copiado a otro equipo)
      const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
      this.S = { pub: b64(publicKey.export({ type: "spki", format: "der" })), priv: this._enc(privateKey.export({ type: "pkcs8", format: "der" }).toString("base64")), hw: hardwareId(), seq: 0, seen: 0 };
      this._save();
    }
    try { this.key = crypto.createPrivateKey({ key: Buffer.from(this._dec(this.S.priv), "base64"), format: "der", type: "pkcs8" }); }
    catch (e) { this.S = {}; this._identity(); }
  }
  /* ---- red ---- */
  async _post(fn, body, ms) {
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), ms || 12000);
    try {
      const r = await this.f(this.url + "/functions/v1/" + fn, { method: "POST", headers: { "Content-Type": "application/json", apikey: APIKEY }, body: JSON.stringify(body), signal: ctl.signal });
      let j; try { j = await r.json(); } catch (e) { return { ok: false, error: "SERVER_ERROR", net: r.status >= 500 }; }
      if (j && j.ok === false && r.status >= 500) j.net = true;
      return j;
    } catch (e) { return { ok: false, error: "OFFLINE", net: true }; } finally { clearTimeout(t); }
  }
  _signed(fn, extra) {
    this._identity();
    const seq = Math.max((this.S.seq || 0) + 1, this.now()); this.S.seq = seq; this._save(); // se guarda antes de enviar
    const ts = this.now();
    const sig = b64(crypto.sign(null, Buffer.from([fn, this.S.did, seq, ts, extra || ""].join("|")), this.key));
    return { device_id: this.S.did, seq, ts, sig };
  }
  async _register() {
    this._identity();
    if (this.S.did) return { ok: true };
    const r = await this._post("device-register", { pub: this.S.pub, hw: this.S.hw, family: this.o.family, name: this.o.name || os.hostname(), ver: this.o.version || "" });
    if (!r.ok) return r;
    if (r.server_key !== (this.o.serverPubkey || SERVER_PUBKEY)) return { ok: false, error: "SERVER_KEY_MISMATCH" };
    this.S.did = r.device_id; this._save(); return { ok: true };
  }
  /* ---- autorización firmada por el servidor ---- */
  _checkAuth(a) {
    if (!a || typeof a.p !== "string" || typeof a.s !== "string") return { ok: false, error: "LICENSE_NOT_FOUND" };
    let good = false; try { good = crypto.verify(null, Buffer.from(a.p), this.spk, Buffer.from(a.s, "base64")); } catch (e) { /* */ }
    if (!good) return { ok: false, error: "AUTH_INVALID" };
    let p; try { p = JSON.parse(a.p); } catch (e) { return { ok: false, error: "AUTH_INVALID" }; }
    if (p.did !== this.S.did) return { ok: false, error: "AUTH_INVALID" };
    const now = this.now();
    if ((this.S.seen || 0) - now > SKEW) return { ok: false, error: "CLOCK_TAMPER" }; // reloj atrasado
    if (now / 1000 > p.exp) return { ok: false, error: "AUTH_EXPIRED", p };
    return { ok: true, p };
  }
  _store(r) {
    const c = this._checkAuth(r.auth); if (!c.ok) return c;
    this.S.auth = r.auth; this.S.seen = Math.max(this.S.seen || 0, this.now(), (r.now || 0) * 1000); this._save(); return c;
  }
  _touchSeen() { const n = this.now(); if (n > (this.S.seen || 0)) { this.S.seen = n; this._save(); } }
  /* Devuelve { ok:true, info } | { ok:false, error, screen:'activate'|'error' } */
  async check() {
    this._identity(); this.S.did || await this._register();
    if (!this.S.did || !this.S.auth) { const r = await this._register(); if (!r.ok) return this._fail(r); return { ok: false, error: this.S.activatedBefore ? "DEVICE_NOT_ACTIVATED" : "NEEDS_ACTIVATION", screen: "activate" }; }
    const r = await this._post("license-validate", this._signed("license-validate"), 6000);
    if (r.ok) { const s = this._store(r); if (!s.ok) return this._fail(s); return { ok: true, info: s.p, online: true }; }
    if (r.net || r.error === "RATE_LIMITED" || r.error === "SERVER_ERROR") { // sin conexión: se usa la autorización guardada
      const c = this._checkAuth(this.S.auth);
      if (c.ok) { this._touchSeen(); return { ok: true, info: c.p, online: false }; }
      return this._fail({ error: c.error === "AUTH_EXPIRED" || c.error === "CLOCK_TAMPER" ? "OFFLINE" : c.error });
    }
    return this._fail(r);
  }
  _fail(r) {
    const e = r.error || "SERVER_ERROR";
    if (["DEVICE_NOT_ACTIVATED", "DEVICE_NOT_FOUND"].includes(e)) { delete this.S.auth; this._save(); return { ok: false, error: e, screen: "activate" }; }
    return { ok: false, error: e, screen: "error", extra: r };
  }
  /* alta: serial + cuenta. create=true crea la cuenta nueva (la serie decide la licencia) */
  async activate({ serial, email, password, name, create }) {
    const reg = await this._register(); if (!reg.ok) return { ok: false, error: reg.error };
    if (create) { const u = await this._post("user-register", { serial, email, password, name }); if (!u.ok) return u; }
    const a = await this._post("device-authenticate", { ...this._signed("device-authenticate", String(email).trim().toLowerCase()), email, password });
    if (!a.ok) return a;
    const r = await this._post("activate-serial", { ...this._signed("activate-serial", a.ticket.s), serial, ticket: a.ticket });
    if (!r.ok) return r;
    const s = this._store(r); if (!s.ok) return s;
    this.S.activatedBefore = true; this._save();
    return { ok: true, info: s.p };
  }
  async heartbeat() {
    const r = await this._post("device-heartbeat", this._signed("device-heartbeat"));
    if (r.ok) { const s = this._store(r); return s.ok ? { ok: true, info: s.p } : this._fail(s); }
    if (r.net || r.error === "RATE_LIMITED") { const c = this._checkAuth(this.S.auth); if (c.ok) { this._touchSeen(); return { ok: true, offline: true, info: c.p }; } return this._fail({ error: "OFFLINE" }); }
    return this._fail(r);
  }
  startHeartbeat(onFail, ms) {
    clearInterval(this.hbT);
    this.hbT = setInterval(async () => { const r = await this.heartbeat().catch(() => ({ ok: true })); if (!r.ok) { clearInterval(this.hbT); onFail(r); } }, ms || 15 * 60e3);
    if (this.hbT.unref) this.hbT.unref();
  }
  async deactivate() { const r = await this._post("device-deactivate", this._signed("device-deactivate")); if (r.ok) { delete this.S.auth; this.S.activatedBefore = false; this._save(); } return r; }
  info() { const c = this._checkAuth(this.S.auth); return c.p || null; }
}
module.exports = { License, SERVER_PUBKEY, hardwareId };
