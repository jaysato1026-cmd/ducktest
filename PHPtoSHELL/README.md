# PHPtoSHELL 防禦程式：舊系統來源限制工具

介面支援滑鼠滾輪與右側捲軸：文字框、清單、表格會先捲動自己的內容，抵達上下邊界後可繼續捲動整個頁面，方便在較小視窗閱讀下方區域。

鍵盤操作：`F5` 更新來源；`Ctrl+L` 切換至操作紀錄並將焦點移到紀錄文字；`Ctrl+Tab`／`Ctrl+Shift+Tab` 切換頁籤。Ctrl+L 與 F5 已用 Tk 鍵盤事件驗證；螢幕閱讀器及全鍵盤工作流程尚待驗收。

作者：王宥傑 ｜ 版本：2026.10.28

發行者：Ailisa。此為使用者指定的顯示名稱；正式程式碼簽章憑證身分尚未確認，不代表 EXE 已簽章。

交付包更新與驗證方式見 `UPDATE-GUIDE.md`；目前只驗證套件預檢與 WhatIf，實際更新及撤回仍待隔離環境驗收。

商業化交付：執行 `Install-PHPtoSHELL.ps1` 可安裝到目前使用者的 `%LOCALAPPDATA%\PHPtoSHELL` 並建立桌面捷徑；加上 `-Uninstall` 可解除安裝。安裝器不自動修改 Windows Firewall，避免安裝階段影響既有服務。

PHPtoSHELL 是面向既有 PHP／Tomcat 服務的 Windows 來源防禦控制台。它不修改 PHP 程式、不停止 PHP 或 Java 程序，僅針對 TCP 8080 的入站來源提供盤點、三分鐘標記、人工封鎖與可選的自動封鎖。

## 兩套既有工具的整合

- 整合「鴨鴨測」的深色控制台風格、狀態卡、展示模式與操作導向介面。
- 整合「連線軟體監控程式」的來源連線表、事件／CSV 匯出、右鍵人工處置、白名單與倒數標記。
- Dashboard 盤點 PHP／Tomcat、AnyDesk、VNC、SMB、TeamViewer 服務埠與遠端連線對象，顯示遠端 IP、服務、狀態與 PID。
- 來源分析支援白名單／黑名單狀態、三分鐘倒數、反向 DNS／PTR 偵測、封鎖原因與可回復操作。
- 保留原本的服務保護邊界：不執行 process kill、不重啟 PHP／Tomcat、不修改應用程式或資料庫；封鎖只產生來源限定的 Windows Firewall 入站規則。

## Blue Team 防禦基線

- 盤點：記錄 TCP 8080 與遠端連線對象，並顯示 AnyDesk、VNC、SMB、TeamViewer 等相關服務埠。
- 最小權限：預設只觀察；寫入 Windows Firewall 前須通過規則、白名單、連線與管理員權限檢查。
- 偵測與歸因：未知來源立即標記，保留首次出現時間；可做反向 DNS／PTR 查詢，但不把 DNS 結果當成可信授權。
- 回應：來源限定封鎖、人工解除、10 分鐘暫存回復與事件紀錄；不終止共用服務程序。
- 稽核：事件 JSONL 旋轉保存；政策變更會停用自動封鎖，要求重新檢查。
- 安全限制：目前保護範圍是本機 Windows Firewall 與指定 TCP 服務，不等同 WAF、EDR、SIEM 或 Daybreak 代理程式；正式導入前仍需在測試主機驗證白名單、NAT 與服務相依性。

這是可檢查原始碼的第一版工具，尚未部署到遠端，也尚未證明能在該機器完整運作。它用 Windows 防火牆阻擋非核准來源連入 TCP 8080；不修復 PHP／Tomcat 漏洞、不解析 HTTP 攻擊內容，也不替代 WAF。

另附 `PHPtoSHELL-HTTPGuard-Pilot` 獨立測試包，可在受控環境對 multipart 請求做前置限制；主 GUI 未接入此元件，既有 8080 流量不會自動通過它。其限制與驗證方式見試作包內 README。

目前附帶方案為 **PREVIEW ONLY**，Apply 會拒絕執行。不能把這個 ZIP 當作已啟用防禦。

## 範圍

- Audit：取樣服務連線、程序路徑、有效防火牆設定與入站規則，寫入本機 JSON。預設 3 次、間隔 10 秒；不改防火牆。
- plan.py：離線計算合法來源以外的 IPv4／IPv6 封鎖範圍，沒有網路連線。
- Apply：只新增 TCP 8080 的兩個來源範圍封鎖規則（每個 IP 家族一個）；不改既有規則、預設政策或其他埠。
- Rollback：只刪除該次 journal 記錄且群組名稱吻合的自有規則。
- Commit：操作人員完成業務驗證後，取消 10 分鐘自動撤回。已 Commit 的部署仍可手動 Rollback。

未涵蓋：8009、9267、3306、FTP、VNC、遠端管理權限、VLAN、PHP 更新、檔案完整性監控及自動告警。本版不安裝長駐程式。

## 先在目標機器執行唯讀盤點

需要 Windows PowerShell 5.1、NetSecurity 與 CIM 元件；不需要安裝 Python 才能 Audit。使用管理員 PowerShell 可取得較完整資料。不要為執行本工具永久降低執行政策，也不要停用防毒。

```powershell
.\Guard.ps1 -Mode Audit -Samples 12 -IntervalSeconds 10
```

請同時涵蓋正常播放器更新、管理登入、既有排程與發布作業週期。單次取樣不能證明來源清單完整；不要為測試而任意發布內容。JSON 存在 audit/，含來源位址、電腦名稱、程式路徑與規則，須保留於受控位置，不要貼到公開網站。

本工具未收集命令列、封包內容、密碼、Cookie 或資料庫內容。Audit 本身仍有取樣負載，正式機器上的效能尚未實測。

## 補齊來源後才產生正式方案

policy.json 前三個來源由使用者確認為合法公司來源；最後一個是先前觀察到的公網／NAT 自身來源，仍須確認用途。內網管理電腦、播放器網段、備援出口和 IPv6 尚未補齊。沒有自動信任整個 LocalSubnet。

確認以上項目及固定 IP／動態出口後，設定正確的 target_computer（使用 Audit 回傳值，大小寫需相符），再將 inventory_approved 改為 true。不要只為通過檢查而開啟此旗標。

在具有 Python 3.7+ 的管理電腦上離線執行（標準函式庫，不安裝套件）：

```powershell
py -3 .\plan.py .\policy.json .\approved-plan.json
```

程式輸出 READY 或 PREVIEW ONLY 與 SHA256。審閱完整方案後，將它與 Guard.ps1 放到目標電腦。SHA256 只確認套用的是審閱過的同一份方案，不是數位簽章或來源可信證明。

## 套用前必須具備

- 所有必要公司來源、NAT hairpin／備援來源與 IPv6 已核對。
- 已記錄主要功能基線，現場有獨立管理或主控台存取方式。
- 防火牆已啟用、允許本機規則合併，沒有介面排除；工具遇到不符條件會拒絕。
- 已檢視現行有效規則。工具沒有修改既有封鎖或允許規則，無法修復既有錯誤政策。
- 已安排可驗證功能的時段。任何真正的網路限制都可能影響漏列的來源，不能保證零中斷。

## 套用、驗證與撤回

下列指令只應在**目標機器**以管理員身分執行，SHA256 必須換成審閱後的實際值：

```powershell
.\Guard.ps1 -Mode Apply -PlanPath .\approved-plan.json -ApprovedPlanSha256 <實際64位SHA256>
```

套用前會再次檢查現行 Established 的 8080 來源是否都在方案內。這不能涵蓋當下離線的播放器或備援線路。工具會先在 ProgramData/IngressGuard 建立僅 SYSTEM／Administrators 可存取的 journal 與回復程式，註冊 SYSTEM 的 10 分鐘撤回工作，再新增規則。

定時回復程式使用該次 PowerShell 程序的 ExecutionPolicy Bypass 來執行受保護目錄中的同一份程式；不變更系統執行政策。若環境的組織政策或應用程式控制阻止程式／排程執行，不能假設定時回復必定成功。本機模擬測試沒有證明遠端排程的執行能力。

套用後必須在時限內由合法公司來源檢查：管理登入、播放器更新、發布、排程、檔案傳輸及維護連線；並從未核准、受控的測試來源確認 8080 被阻擋。長週期排程須先在前一階段完成驗證，不能只看首頁正常就 Commit。

驗證失敗可立即撤回，不必等待。以下 journal 路徑使用 Apply 回傳的實際值：

```powershell
.\Guard.ps1 -Mode Rollback -JournalPath <該次journal.json完整路徑>
```

驗證通過才取消自動撤回：

```powershell
.\Guard.ps1 -Mode Commit -JournalPath <該次journal.json完整路徑> -BusinessChecksPassed
```

工具使用跨程序互斥鎖，避免 Commit 與定時 Rollback 同時修改狀態。主機故障、系統時間變更或排程服務異常仍可能影響撤回時效；務必保留獨立管理方式。撤回只移除本工具的規則，不匯入整份舊防火牆設定，避免覆蓋其他管理作業。

## 為何不直接「允許公司 IP，再封鎖所有來源」

Windows 明確封鎖規則優先於允許規則，因此廣泛封鎖也會擋住公司來源。本工具採用不重疊的補集封鎖，保留合法來源與本機回送；IPv6 同樣納入，未核准的 IPv6 來源也會受限制。

## 驗證狀態

- 已完成離線 IPv4／IPv6 範圍分割、邊界、重疊、錯誤來源與未核准方案測試。
- 已完成 PowerShell 語法與模擬條件檢查。
- 已模擬部分套用失敗清理、功能確認閘門、Commit、延遲定時工作、手動及自動回復；沒有對開發機新增防火牆規則。
- **未在目標機器執行 Audit、Apply 或真正的定時回復；未完成主要功能回歸。**

參考：[Microsoft 防火牆規則優先順序](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)、[New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)。
