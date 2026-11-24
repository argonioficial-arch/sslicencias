"use strict";
/* Puerta de licencia (proceso principal). Se ejecuta ANTES de crear la radio y el servicio de comunicación.
   Licencia válida -> no se muestra nada. Cualquier problema -> ventana de activación/error y la radio no arranca. */
const path = require("path");
const { License } = require("./license-client.js");

module.exports = async function gate(o) {
  const { app, BrowserWindow, ipcMain, safeStorage, family, productName, version, lockdown } = o;
  const L = new License({ dir: app.getPath("userData"), family, version, name: require("os").hostname(), safeStorage });
  let win = null, cur = null, done = null;
  const model = (r) => ({ screen: r.screen || "error", error: r.error, extra: r.extra || {} });
  const open = () => {
    if (win && !win.isDestroyed()) return;
    const w = win = new BrowserWindow({ width: 520, height: 700, resizable: false, maximizable: false, minimizable: true, autoHideMenuBar: true, backgroundColor: "#0f1115", title: productName + " · Licencia",
      webPreferences: { preload: path.join(__dirname, "preload-license.js"), contextIsolation: true, nodeIntegration: false, sandbox: true } });
    win.setMenu(null);
    win.loadFile(path.join(__dirname, "renderer", "license.html"), { query: { name: productName, v: version } });
    w.on("closed", () => { if (win === w) { win = null; app.exit(0); } });
  };
  const show = (r) => { cur = model(r); open(); if (win && !win.webContents.isLoading()) win.webContents.send("lic:model", cur); };

  ipcMain.handle("lic:model", () => cur);
  ipcMain.handle("lic:retry", async () => { const r = await L.check(); if (r.ok) return finish(r); cur = model(r); return { ok: false, model: cur }; });
  ipcMain.handle("lic:activate", async (e, p) => {
    const clean = { serial: String(p.serial || "").slice(0, 40), email: String(p.email || "").slice(0, 200), password: String(p.password || "").slice(0, 72), name: String(p.name || "").slice(0, 120), create: !!p.create };
    const r = await L.activate(clean);
    if (r.ok) return finish(r);
    return { ok: false, error: r.error, extra: r };
  });
  ipcMain.on("lic:quit", () => app.exit(0));
  ipcMain.on("lic:relaunch", () => { app.relaunch(); app.exit(0); });

  let resolveGate;
  const p = new Promise((res) => (resolveGate = res));
  function finish(r) {
    L.startHeartbeat((bad) => { // la licencia dejó de ser válida con la radio abierta
      try { lockdown && lockdown(); } catch (e) { /* */ }
      done = true; const w = win; win = null; if (w && !w.isDestroyed()) w.destroy();
      show(bad.screen === "activate" ? { ...bad, screen: "error", error: bad.error } : bad);
    }, o.heartbeatMs);
    done = true; const w = win; win = null; if (w && !w.isDestroyed()) w.destroy();
    resolveGate(L); return { ok: true };
  }
  const r = await L.check();
  if (r.ok) { finish(r); return p; }
  show(r);
  return p;
};
