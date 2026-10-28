[rtk] /!\ No hook installed — run `rtk init -g` for automatic token savings
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

def tool_status() -> dict[str, bool]:
    return {name: shutil.which(name) is not None for name in ('nmap', 'tshark', 'iperf3', 'netstat')}

def _run(tool: str, args: list[str], timeout: int = 30) -> ToolResult:
    exe = shutil.which(tool)
    if not exe:
        return ToolResult(tool, False, f'{tool} ?芸?鋆?銝 PATH??)
    try:
        p = subprocess.run([exe, *args], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
        text = (p.stdout or p.stderr or '').strip()
        return ToolResult(tool, p.returncode == 0, text[-12000:])
    except subprocess.TimeoutExpired:
        return ToolResult(tool, False, f'{tool} 頞? {timeout} 蝘暹?嚗歇?迫蝑???)
    except OSError as exc:
        return ToolResult(tool, False, f'{tool} ?瑁?憭望?嚗exc}')

def nmap_inventory(target: str) -> ToolResult:
    if not target or len(target) > 255 or any(ch in target for ch in ';&|`$<>'):
        return ToolResult('nmap', False, '?格??澆?銝?瘜??芣?蜓璈?蝔晞P ??CIDR??)
    return _run('nmap', ['-Pn', '--top-ports', '20', '--open', target], 90)

def tshark_interfaces() -> ToolResult:
    return _run('tshark', ['-D'], 15)

def iperf3_probe(host: str, port: int = 5201, seconds: int = 5) -> ToolResult:
    if not host or len(host) > 255 or any(ch in host for ch in ';&|`$<>'):
        return ToolResult('iperf3', False, '銝餅??澆?銝?瘜?)
    if not 1 <= int(port) <= 65535 or not 1 <= int(seconds) <= 30:
        return ToolResult('iperf3', False, '???葫閰衣??貉??箏??函???)
    return _run('iperf3', ['-c', host, '-p', str(int(port)), '-t', str(int(seconds)), '--json'], int(seconds) + 10)

def local_connections() -> ToolResult:
    return _run('netstat', ['-ano', '-p', 'TCP'], 10)

def http_probe(url: str, timeout: int = 5) -> ToolResult:
    if not (url.startswith('http://') or url.startswith('https://')) or any(ch in url for ch in '\r\n;&|`$<>'):
        return ToolResult('http-probe', False, '?芣??http嚗ttps URL嚗?蝳迫 shell ?寞?摮???)
    try:
        started = time.perf_counter()
        with urlopen(Request(url, headers={'User-Agent': 'PHPtoSHELL-BlueTeam/2026.10.28'}), timeout=max(1, min(int(timeout), 15))) as response:
            body = response.read(512)
            elapsed = (time.perf_counter() - started) * 1000
            return ToolResult('http-probe', True, f'HTTP {response.status}\n撱園嚗elapsed:.1f} ms\nContent-Type嚗response.headers.get("Content-Type", "N/A")}\n璅?嚗body[:120]!r}')
    except (OSError, URLError, TimeoutError) as exc:
        return ToolResult('http-probe', False, f'HTTP ?Ｘ葫憭望?嚗exc}')

def safe_load_test(url: str, seconds: int = 5, concurrency: int = 2, authorized: bool = False) -> ToolResult:
    if not authorized:
        return ToolResult('safe-load-test', False, '?芰Ⅱ隤?甈?撌亙???瑁???)
    if seconds < 1 or seconds > 30 or concurrency < 1 or concurrency > 10:
        return ToolResult('safe-load-test', False, '摰銝?嚗?-30 蝘?-10 雿萇??)
    end = time.monotonic() + seconds; total = 0; failures = 0
    while time.monotonic() < end and total < 1000:
        result = http_probe(url, 3); total += 1
        if not result.ok: failures += 1
    return ToolResult('safe-load-test', True, f'摰?隢?嚗total}\n憭望?嚗failures}\n雿萇銝?嚗concurrency}\n皜祈岫蝘嚗seconds}')

