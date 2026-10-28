# PHPtoSHELL 商業化驗收矩陣

版本：2026.10.28｜作者：王宥傑

| 要求 | 目前證據 | 狀態 |
|---|---|---|
| PHP/Tomcat 相容性與主功能 | 本機合成測試、GUI demo；尚未連到目標 PHP/Tomcat | NOT VERIFIED：需目標主機回歸 |
| 性能與誤封率 | 尚無現場基線或長時間負載資料 | NOT VERIFIED |
| 回復測試 | Guard.ps1 有預覽／撤回流程；未在目標主機演練 | NOT VERIFIED：需現場演練 |
| HTTP 前端限制 | HTTP Guard Pilot 有大小、multipart 結構與固定上游限制 | PILOT ONLY：未接入現場流量 |
| 規則版本與政策審批 | 現有政策 JSON 與事件記錄；正式 Draft/Approve/Apply workflow 尚未完成 | PARTIAL |
| Windows 簽章 | EXE 為未簽章測試建置 | NOT VERIFIED：需組織憑證與簽章流程 |
| 安裝與更新 | 六項更新測試通過：含合成檔案實際更新、政策／事件保留、獨立備份與舊版 manifest 保留；另涵蓋 WhatIf、降版、缺檔、竄改、路徑與目錄重疊拒絕 | PARTIAL：真實執行中 EXE、中斷復原與撤回待驗收 |
| 使用者文件 | README、Security Boundary、HTTP Pilot README 已提供 | PARTIAL：需現場操作手冊與支援流程 |
| 無障礙與縮放 | 900×600 捲動通過；1280×720 的 Tk 100%／125%／150% 合成字型縮放下，五個主要控制項未超出右側視窗邊界 | PARTIAL：實際 Windows DPI、全控制項與鍵盤操作仍待驗收 |
| 持續監控 | GUI 5 秒取樣、健康狀態、錯誤計數與事件保留已完成 | LOCAL ONLY |
| 告警管道 | 本機 JSONL 事件；未接 SIEM／Email | LOCAL ONLY |
| 資料保留 | 30 天或 100 MiB 邊界與敏感欄位過濾已測試 | LOCAL TESTED |
| 權限設計 | 觀察模式可不需管理員；防火牆變更需管理員 | LOCAL REVIEWED：需現場權限驗證 |
| 故障可觀測性與支援 | Dashboard 健康摘要已完成；支援 runbook、support bundle 尚未完成 | PARTIAL |

鍵盤補充證據：以實際 Tk 鍵盤事件確認 Ctrl+L 切到操作紀錄並取得焦點、F5 觸發更新，以及 Ctrl+Tab／Ctrl+Shift+Tab 往返切換頁籤。這不涵蓋螢幕閱讀器或每個表單／對話框的完整鍵盤操作。

空表狀態補充證據：在展示模式直接設定未取得成功取樣、觀察暫停、取樣超過 30 秒、最近成功空取樣四種狀態，確認 `_render()` 產生對應提示。這是介面狀態測試，未模擬實際遠端斷線或 PowerShell 故障。

## 目前通過的本機證據

- 最新一輪 42 項 Python 測試通過，包含八項更新測試及替換後故障回復；HTTP Guard 合成整合檢查另於同次執行通過。Tk 100%／125%／150% 合成縮放檢查亦再次通過。
- GUI 900×600 捲動、空狀態、GEO／runtime path 檢查通過。
- PHPtoSHELL EXE 展示模式啟動通過。
- HTTP Guard Pilot 以假上游和自含式 EXE 完成一般請求、合法 multipart、異常 multipart、路徑固定、標頭清除與 loopback 啟動限制測試。
- 兩個 ZIP 的雜湊與完整性通過。

任何 `NOT VERIFIED` 或 `PILOT ONLY` 項目都不能對外宣稱為正式商用能力。

更新安全補充：實際 PowerShell 更新器已在隔離套件副本上驗證，遭修改的 EXE 會於 WhatIf 前拒絕，未執行安裝寫入。SHA-256 清單本身尚無可信發行者簽章，不能抵抗套件與清單同時被替換；正式更新仍須補齊來源驗證與撤回驗收。

更新拒絕情境已覆蓋三項：EXE 雜湊不符、清單路徑穿越、清單列出的檔案缺失。三項均以實際 PowerShell 更新器在暫存套件執行，驗證非零結束且未進入更新預覽成功路徑。尚未驗證寫入中斷或作業系統重新啟動時的復原。
