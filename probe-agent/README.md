# 壓測台全球節點 Agent

在各國的 VPS、雲端 VM 或能進入公司 VPN 的主機執行：

```powershell
$env:PROBE_TOKEN="replace-with-a-long-random-token"
$env:ALLOWED_TARGET_HOSTS="example.com,api.example.com"
$env:PORT="8787"
node server.mjs
```

或使用 Docker：

```bash
docker build -t yat-global-probe .
docker run -d --restart unless-stopped -p 8787:8787 \
  -e PROBE_TOKEN="replace-with-a-long-random-token" \
  -e ALLOWED_TARGET_HOSTS="example.com,api.example.com" \
  yat-global-probe
```

桌面端節點格式：

```text
日本|東京|https://jp-probe.example.com/probe
新加坡|新加坡|https://sg-probe.example.com/probe
美國|維吉尼亞|https://us-probe.example.com/probe
德國|法蘭克福|https://de-probe.example.com/probe
```

桌面端可選系統 DNS、Cloudflare `1.1.1.1`、Google `8.8.8.8`、Quad9 `9.9.9.9` 或自訂 DNS。Agent 會用指定 DNS 解析出的 IP 建立 HTTP/HTTPS 連線，並回傳 DNS 平均延遲、P95、失敗數與解析位址。

建議將 Agent 放在 HTTPS 反向代理後方、防火牆僅開放必要來源，設定相同的 `PROBE_TOKEN`，並用 `ALLOWED_TARGET_HOSTS` 限制可測目標，避免成為公開代理。
