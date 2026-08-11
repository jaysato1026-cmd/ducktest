# 鴨鴨測 DuckTest v1.15.1

作者：王宥傑

鴨鴨測是 Windows 桌面網站品質工作台，整合：

- 自動多輪 HTTP 壓力測試與下一輪調整
- DNS、TCP、HTTP、TLS、Geo 與機器存活偵測
- 1、8、12、24 小時存活監控
- Globalping 公共全球節點與自架 Agent
- 可選公共或自訂 DNS
- 非破壞性資安基線
- 完整 HTML 與 JSON 報告匯出

## 開發與驗證

```powershell
npm.cmd test
npm.cmd run build:web
npm.cmd run build
```

Windows 安裝版與可攜版建置：

```powershell
npm.cmd run build
```

儲存庫不包含 `node_modules`、離線 Electron runtime、安裝包或歷史 release 目錄；請先以 `npm install` 安裝相依套件。

## 使用提醒

壓力測試只可對已取得授權的系統執行。長時間監控期間請保持鴨鴨測與 Windows 電腦開啟。

## Reliability features

- Reliability Center: outage root-cause evidence, history baselines, run comparison, CPU/memory/process/disk samples.
- Uptime monitoring: 1, 8, 12, or 24 hours with 30-second-or-longer intervals and suspend prevention.
- Scheduled probes: 1 minute to 1 hour intervals; optional JSON webhook alerts for offline and HTTP 5xx results.
- Reports: JSON, CSV, and printable HTML (use the browser print dialog to save PDF).
- Templates and scenarios: repeatable health/API/spike/POST templates plus authorized multi-step scenario IPC.
- CLI/CI: `npm.cmd run cli -- --url https://example.com --authorized --json`.

All active test paths require explicit authorization in the desktop UI or `--authorized` in CLI mode.

## Repository safety

- 不包含公司內部網址、帳密、憑證或營運資料。
- 請只對本人擁有或已取得明確授權的系統進行負載測試。
- 公開範例及測試資料應使用 `example.com`、本機服務或自行控制的測試環境。

## License

目前未授予再散布或商業使用權；原始碼公開作為個人技術作品展示。如需使用或合作，請先聯絡作者。
