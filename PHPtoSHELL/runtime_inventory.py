"""Read only Windows process inventory for PHP2SHELL triage."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

from diagnostics import ToolResult

QUERY = r'''
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$rows = @(Get-CimInstance Win32_Process -Filter "Name='php-cgi.exe' OR Name='php.exe' OR Name='java.exe'" |
    ForEach-Object {
        $version = $null
        if ($_.ExecutablePath) {
            try { $version = (Get-Item -LiteralPath $_.ExecutablePath).VersionInfo.ProductVersion } catch {}
        }
        [pscustomobject]@{name=$_.Name;pid=$_.ProcessId;path=$_.ExecutablePath;version=$version}
    })
$listenerError = $false
try {
    $listeners = @(Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction Stop |
        ForEach-Object { [pscustomobject]@{address=$_.LocalAddress;pid=$_.OwningProcess} })
} catch { $listeners = @(); $listenerError = $true }
[pscustomobject]@{processes=$rows;listeners=$listeners;listenerError=$listenerError} |
    ConvertTo-Json -Compress -Depth 4
'''


def format_inventory(raw: str) -> str:
    data = json.loads(raw.lstrip('\ufeff').strip())
    if not isinstance(data, dict):
        raise ValueError('程序盤點輸出格式錯誤')
    processes = data.get('processes') or []
    listeners = data.get('listeners') or []
    if isinstance(processes, dict): processes = [processes]
    if isinstance(listeners, dict): listeners = [listeners]
    lines = ['執行中 PHP／Java 候選程序（僅本機唯讀）']
    if not processes:
        lines.append('未列出候選程序；可能是權限不足、不同 SAPI 或其他主機，不能據此判定沒有 PHP。')
    for item in processes[:100]:
        name = str(item.get('name') or '未知')
        pid = item.get('pid')
        path = str(item.get('path') or '路徑不可讀')
        version = str(item.get('version') or '版本資訊不可讀')
        lines.append(f'{name}  PID {pid}  產品版本 {version}\n  {path}')
    if len(processes) > 100: lines.append('只顯示前 100 筆候選程序。')
    lines.append('\nTCP 8080 本機監聽：')
    if data.get('listenerError'):
        lines.append('無法查詢監聽程序；需核對權限或 NetTCPConnection。')
    elif listeners:
        for item in listeners[:30]:
            lines.append(f"{item.get('address', '未知')}  PID {item.get('pid', '未知')}")
    else:
        lines.append('此次未查到監聽；不能判定其他主機或代理入口。')
    lines.append('\n上方只是候選程序與檔案產品版本；須再核對 Web 服務設定、實際 PHP SAPI 與 worker 載入版本。')
    return '\n'.join(lines)


def candidate_php_paths(raw: str) -> list[str]:
    data = json.loads(raw.lstrip('\ufeff').strip())
    rows = data.get('processes') or []
    if isinstance(rows, dict): rows = [rows]
    return sorted({str(row['path']) for row in rows if isinstance(row, dict) and
                   str(row.get('name', '')).lower() in ('php.exe', 'php-cgi.exe') and row.get('path')})


def runtime_inventory() -> ToolResult:
    if os.name != 'nt':
        return ToolResult('runtime-inventory', False, '此盤點只支援 Windows。')
    engine = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    try:
        completed = subprocess.run([str(engine), '-NoProfile', '-NonInteractive', '-Command', QUERY],
                                   capture_output=True, text=True, encoding='utf-8', errors='replace',
                                   timeout=20, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if completed.returncode:
            return ToolResult('runtime-inventory', False, (completed.stderr or completed.stdout or '盤點失敗')[-2000:])
        return ToolResult('runtime-inventory', True, format_inventory(completed.stdout),
                          {'php_paths': candidate_php_paths(completed.stdout)})
    except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
        return ToolResult('runtime-inventory', False, '盤點失敗：'+str(exc))
