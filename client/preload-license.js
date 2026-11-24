"use strict";
const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("lic", {
  model: () => ipcRenderer.invoke("lic:model"),
  onModel: (cb) => ipcRenderer.on("lic:model", (e, m) => cb(m)),
  retry: () => ipcRenderer.invoke("lic:retry"),
  activate: (p) => ipcRenderer.invoke("lic:activate", p),
  quit: () => ipcRenderer.send("lic:quit"),
  relaunch: () => ipcRenderer.send("lic:relaunch")
});
