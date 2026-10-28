"""Defensive PHP memory/worker abuse audit. Never sends exploit traffic."""
from __future__ import annotations
import re
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass

@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    detail: str
    remediation: str

PATCHED = {2: 35, 3: 36, 4: 27, 5: 12}


def _php_info(executable: str | None = None) -> str:
    executable = executable or shutil.which('php')
    if not executable:
        return ''
    try:
        p = subprocess.run([executable, '-i'], capture_output=True, text=True, encoding='utf-8', errors='replace',
                           timeout=10, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return p.stdout if p.returncode == 0 else ''
    except (OSError, subprocess.SubprocessError):
        return ''

def _value(info: str, key: str) -> str:
    match = re.search(r'^' + re.escape(key) + r'\s*=>\s*([^\s]+)', info, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else ''

def audit_php_config(info: str | None = None, executable: str | None = None) -> list[Finding]:
    info = _php_info(executable) if info is None else info
    findings: list[Finding] = []
    if not info:
        return [Finding('UNKNOWN', '無法確認 PHP 執行環境', '指定的 PHP 執行檔無法回傳 php -i，或目前 PATH 找不到 PHP。', '選取實際提供 Web 請求的 PHP 執行檔；另核對服務程序與載入設定。')]
    version = _value(info, 'PHP Version')
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', version)
    vulnerable = None
    if match:
        major, minor, patch = map(int, match.groups())
        if major < 8 or (major == 8 and minor < 2):
            vulnerable = True
            detail = f'PHP {version}；此版本線早已停止 PHP 官方安全維護。'
        elif major == 8 and minor in PATCHED:
            vulnerable = patch < PATCHED[minor]
            detail = f'PHP {version}；此版本線的 PHP2SHELL 修補門檻為 8.{minor}.{PATCHED[minor]}。'
        else:
            detail = f'PHP {version}；此稽核尚未涵蓋該版本線的公告。'
        findings.append(Finding('CRITICAL' if vulnerable else ('PASS' if vulnerable is False else 'UNKNOWN'),
                                'PHP2SHELL 版本狀態', detail,
                                '優先使用廠商修補版並重啟所有 Web worker；內嵌 PHP 須向供應商確認。' if vulnerable else
                                '核對實際 Web SAPI、廠商套件與所有 worker 的載入版本。'))
    else:
        findings.append(Finding('UNKNOWN', 'PHP 版本無法解析', 'php -i 未提供可辨識的版本資訊。', '核對實際 Web worker 使用的 PHP 版本。'))
    memory = _value(info, 'memory_limit')
    if memory == '-1':
        findings.append(Finding('INFO', 'memory_limit=-1', '對未修補版本可降低已知的可控 OOM 路徑，但增加資源耗盡風險，且並非完整修復。',
                                '只在經過容量評估與管理員核准後作臨時措施；優先更新 PHP。'))
    elif memory:
        findings.append(Finding('INFO', 'memory_limit 有限值', f'memory_limit={memory}；此設定無法修復 PHP2SHELL。',
                                '優先更新 PHP；在前端限制解碼後請求大小與 multipart 結構。'))
    else:
        findings.append(Finding('UNKNOWN', '未讀取 memory_limit', '無法確認生效設定。', '檢查 Web SAPI 與應用層設定覆寫。'))
    for key, expected, title in [('max_input_vars', 1000, '輸入欄位上限'), ('post_max_size', 8, 'POST 大小上限')]:
        raw = _value(info, key)
        if raw:
            number = re.match(r'(\d+)', raw)
            if number and int(number.group(1)) > expected * (10 if key == 'max_input_vars' else 128):
                findings.append(Finding('MEDIUM', title + '偏高', f'{key}={raw}', '依實際業務需求降低，並在反向代理設定請求大小上限。'))
    progress = _value(info, 'session.upload_progress.enabled')
    if vulnerable and progress.lower() in ('1', 'on', 'true'):
        findings.append(Finding('HIGH', 'Session upload progress 已啟用', '此功能涉及已公開的跨請求狀態攻擊路徑。',
                                '若業務不依賴上傳進度，可評估設為 Off 並重啟所有 worker；仍須更新 PHP。'))
    strict = _value(info, 'session.use_strict_mode')
    if strict and strict.lower() not in ('1', 'on', 'true'):
        findings.append(Finding('LOW', 'Session strict mode 未啟用', f'session.use_strict_mode={strict}', '評估啟用並驗證應用程式相容性；此項不是 PHP2SHELL 修復。'))
    expose = _value(info, 'expose_php')
    if expose in ('1', 'On', 'on', 'TRUE', 'true'):
        findings.append(Finding('LOW', 'PHP banner 可見', 'expose_php=On', '設定 expose_php=Off，減少版本資訊暴露。'))
    return findings

def scan_log_text(text: str) -> list[Finding]:
    findings=[]
    oom=len(re.findall(r'out.of.memory|allowed memory size|memory exhausted', text, re.I))
    multipart=len(re.findall(r'multipart/form-data', text, re.I))
    cookie=len(re.findall(r'Set-Cookie.{2048,}', text, re.I))
    if oom: findings.append(Finding('HIGH','偵測到 PHP OOM 痕跡',f'{oom} 筆','立即檢查 worker 是否在 OOM 後持續服務，並更新 PHP／隔離 worker。'))
    if multipart >= 3: findings.append(Finding('MEDIUM','multipart 請求密集',f'{multipart} 筆','在反向代理限制 body、欄位數與速率；比對來源 IP 與時間窗。'))
    if cookie: findings.append(Finding('HIGH','異常大型 Set-Cookie',f'{cookie} 筆','檢查回應標頭與 PHP session；保留原始證據並隔離可疑來源。'))
    if not findings: findings.append(Finding('INFO','提供的片段未匹配已知指標','日誌可能未記錄請求標頭、回應標頭或 PHP 記憶體錯誤；沒有匹配不代表安全。','持續收集 PHP、Web Server 與反向代理日誌，並核對記錄格式。'))
    return findings

def audit_log_file(path: str) -> list[Finding]:
    limit = 16 * 1024 * 1024
    try:
        with Path(path).open('rb') as stream:
            stream.seek(0, 2)
            size = stream.tell()
            stream.seek(max(0, size - limit))
            data = stream.read(limit)
        if size > limit:
            data = data.partition(b'\n')[2]
        findings = scan_log_text(data.decode('utf-8', errors='replace'))
        if size > limit:
            findings.insert(0, Finding('INFO', '僅分析日誌尾端', f'檔案約 {size} 位元組；只讀取最後 16 MiB 的完整行。',
                                       '需要完整歷史時，按時間分割日誌並逐份分析。'))
        return findings
    except OSError as exc:
        return [Finding('UNKNOWN','無法讀取日誌',str(exc),'確認日誌路徑與讀取權限。')]


class LogTailMonitor:
    """Read only appended complete lines; never stores or reports raw log content."""
    def __init__(self, path: str, max_bytes: int = 1024 * 1024):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.offset = None
        self.identity = None
        self.partial = b''

    def poll(self) -> tuple[list[Finding], bool]:
        stat = self.path.stat()
        identity = (stat.st_dev, stat.st_ino)
        if self.offset is None:
            self.identity, self.offset = identity, stat.st_size
            return [], False
        if self.identity != identity or stat.st_size < self.offset:
            self.identity, self.offset, self.partial = identity, 0, b''
        skipped = stat.st_size - self.offset > self.max_bytes
        start = max(self.offset, stat.st_size - self.max_bytes)
        with self.path.open('rb') as stream:
            stream.seek(start)
            data = stream.read(self.max_bytes)
            self.offset = stream.tell()
        if skipped:
            data = data.partition(b'\n')[2]
            self.partial = b''
        data = self.partial + data
        complete, sep, self.partial = data.rpartition(b'\n')
        if not sep:
            self.partial = data[-self.max_bytes:]
            return [], skipped
        findings = [f for f in scan_log_text(complete.decode('utf-8', errors='replace')) if f.severity in ('HIGH', 'MEDIUM')]
        return findings, skipped
