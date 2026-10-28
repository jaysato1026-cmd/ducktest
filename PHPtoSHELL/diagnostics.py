"""Safe, opt-in defensive diagnostics used by the PHPtoSHELL toolbox."""
from __future__ import annotations
import shutil
import subprocess
import time
from urllib.error import URLError
from urllib.request import Request, urlopen
from dataclasses import dataclass

@dataclass(frozen=True)
class ToolResult:
    tool: str
    ok: bool
    output: str
    metadata: dict | None = None

def tool_status() -> dict[str, bool]:
    return {name: shutil.which(name) is not None for name in ('nmap', 'tshark', 'iperf3', 'netstat')}

def _run(tool: str, args: list[str], timeout: int = 30) -> ToolResult:
    exe = shutil.which(tool)
    if not exe:
        return ToolResult(tool, False, f'{tool} 未安裝或不在 PATH。')
    try:
        p = subprocess.run([exe, *args], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        text = (p.stdout or p.stderr or '').strip()
        return ToolResult(tool, p.returncode == 0, text[-12000:])
    except subprocess.TimeoutExpired:
        return ToolResult(tool, False, f'{tool} 超過 {timeout} 秒逾時，已停止等待。')
    except OSError as exc:
        return ToolResult(tool, False, f'{tool} 執行失敗：{exc}')

def nmap_inventory(target: str) -> ToolResult:
    if not target or len(target) > 255 or any(ch in target for ch in ';&|`$<>'):
        return ToolResult('nmap', False, '目標格式不合法；只接受主機名稱、IP 或 CIDR。')
    return _run('nmap', ['-Pn', '--top-ports', '20', '--open', target], 90)

def tshark_interfaces() -> ToolResult:
    return _run('tshark', ['-D'], 15)

def iperf3_probe(host: str, port: int = 5201, seconds: int = 5) -> ToolResult:
    if not host or len(host) > 255 or any(ch in host for ch in ';&|`$<>'):
        return ToolResult('iperf3', False, '主機格式不合法。')
    if not 1 <= int(port) <= 65535 or not 1 <= int(seconds) <= 30:
        return ToolResult('iperf3', False, '埠號或測試秒數超出安全範圍。')
    return _run('iperf3', ['-c', host, '-p', str(int(port)), '-t', str(int(seconds)), '--json'], int(seconds) + 10)

def local_connections() -> ToolResult:
    return _run('netstat', ['-ano', '-p', 'TCP'], 10)

def http_probe(url: str, timeout: int = 5) -> ToolResult:
    if not (url.startswith('http://') or url.startswith('https://')) or any(ch in url for ch in '\r\n;&|`$<>'):
        return ToolResult('http-probe', False, '只接受 http／https URL，且禁止 shell 特殊字元。')
    try:
        started = time.perf_counter()
        with urlopen(Request(url, headers={'User-Agent': 'PHPtoSHELL-BlueTeam/2026.10.28'}), timeout=max(1, min(int(timeout), 15))) as response:
            elapsed = (time.perf_counter() - started) * 1000
            return ToolResult('http-probe', True, f'HTTP {response.status}\n延遲：{elapsed:.1f} ms\nContent-Type：{response.headers.get("Content-Type", "N/A")}')
    except (OSError, URLError, TimeoutError) as exc:
        return ToolResult('http-probe', False, f'HTTP 探測失敗：{exc}')

def safe_load_test(url: str, seconds: int = 5, concurrency: int = 2, authorized: bool = False) -> ToolResult:
    if not authorized:
        return ToolResult('safe-load-test', False, '未確認授權；工具拒絕執行。')
    if seconds < 1 or seconds > 30 or concurrency < 1 or concurrency > 10:
        return ToolResult('safe-load-test', False, '安全上限：1-30 秒、1-10 併發。')
    end = time.monotonic() + seconds; total = 0; failures = 0
    while time.monotonic() < end and total < 1000:
        result = http_probe(url, 3); total += 1
        if not result.ok: failures += 1
    return ToolResult('safe-load-test', True, f'完成請求：{total}\n失敗：{failures}\n執行方式：循序請求\n測試秒數：{seconds}')
