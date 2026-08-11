const { app, BrowserWindow } = require("electron");

app.disableHardwareAcceleration();

app.whenReady().then(() => {
  const window = new BrowserWindow({ show: false });
  window.loadURL("data:text/html,<h1>smoke</h1>");
  window.webContents.once("did-finish-load", () => {
    setTimeout(() => window.close(), 1000);
  });
});

app.on("window-all-closed", () => app.quit());
