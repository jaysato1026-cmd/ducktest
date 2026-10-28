# PHPtoSHELL 防禦邊界與商用交付缺口

更新：2026-10-28。作者：王宥傑。

## 目前確實具備

- 本機 TCP 8080 已建立連線每 5 秒取樣、未知來源標記與人工／可選的 180 秒後防火牆封鎖。
- 本機服務埠與連線儀表板；指定 PHP 執行檔的 `php -i` 唯讀版本與設定稽核。
- Windows 本機執行中 PHP／Java 候選程序、產品檔案版本與 TCP 8080 監聽 PID 的唯讀盤點；程序路徑不可讀時顯示未知。
- 指定 PHP／Web 日誌的離線指標搜尋；大檔案僅讀尾端 16 MiB，顯示部分覆蓋。操作人員也可選檔啟動唯讀新增內容監看；每次最多讀 1 MiB，超量會顯示缺口。
- 展示模式、事件紀錄、來源白名單與撤銷本工具建立的來源規則。
- 操作人員匯入的 GEO 與對象 IP 名單，可對選取來源做唯讀比對；標籤可信度取決於資料來源，與封鎖決策分離。

另有獨立的 `PHPtoSHELL-HTTPGuard-Pilot` 測試包，可在隔離環境先檢查 multipart 後轉送至測試上游。它沒有接入本 GUI 或現場流量，不能計入目前已啟用的防護範圍。

## 防護界線

- TCP 取樣會漏掉短暫請求；日誌監看只在選檔且 GUI 運行時生效，啟動時從檔尾開始，格式與記錄欄位不足也會漏報。沒有觀察到指標不能證明未受攻擊。
- 本 GUI／EXE 不解析或攔截 HTTP multipart，不限制請求大小、part header 數或欄位巢狀深度，也不阻止攻擊在 PHP 程式碼執行前發生。獨立 HTTP Guard 試作只在流量確實經過它時才會檢查；它尚未經現場相容性與負載驗收。
- `php -i` 讀的是指定執行檔的 CLI/CGI 設定，不能單獨證明 Web worker 實際載入版本與覆寫設定。
- 程序盤點只涵蓋執行本工具的 Windows 主機；即使看到 PHP 程序與 8080 的 Java PID，也不能單憑這些資訊證明請求確實經過該 PHP worker。
- 防火牆封鎖僅限制之後的指定來源 TCP 8080 入站流量，不保證既有 TCP 連線立即終止。
- 尚未在目標主機完成安裝、主功能回歸、長時間監控、簽章、更新與撤回演練。不得宣稱正式部署或商用驗收完成。

## PHP2SHELL 風險處理順序

1. 確認 Web 請求實際使用的 PHP 執行檔、SAPI、版本、worker 與載入設定；內嵌 PHP 要查供應商修補資訊。
2. 依 PHP 官方公告更新至含完整修補的版本並重啟所有 worker。官方發布的門檻為 8.2.35、8.3.36、8.4.27、8.5.12；舊版須取得可信供應商維護與相容性證據。
3. 對無法立即更新的服務，先評估業務是否依賴 `session.upload_progress`，再決定是否停用。`memory_limit=-1` 僅是官方提出的有條件臨時措施，會增加資源耗盡風險，須先做容量評估；兩者都不是完整修復。
4. 若需在 PHP 之前阻擋惡意 multipart，須在實際 HTTP 前端設置可驗證的大小、欄位、part/header 與速率限制，並用合法業務流量回歸測試。主 EXE 沒有該能力；另附的 HTTP Guard 試作只有固定大小與 multipart 結構限制，沒有速率限制。

## Daybreak Blue 對應

Daybreak Blue 是 OpenAI 對核准使用者的防禦安全工作存取層級，支援漏洞分流、程式審查、偵測工程、事件回應與修補驗證。此程式的唯讀稽核與分流可作為這些工作流程的資料來源；它沒有 Daybreak API 功能，也不應宣稱 Daybreak 認證或把存取權嵌入商用產品。

## 商用驗收仍缺

- 現場的 PHP/Tomcat 相容性、主功能、性能、誤封率與回復測試。
- HTTP 前端層防護與清楚的規則版本、政策審批、部署與撤回流程。
- Windows 程式簽章、可靠的安裝與更新機制、正式使用者文件、無障礙與不同縮放比例的視覺驗收。
- 持續監控、告警管道、資料保留與權限設計；故障情況下的可觀測性與支援流程。

## 參考

- PHP 官方：[OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)、[stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- OpenAI 官方：[Daybreak Trusted Access for Cyber](https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview)
