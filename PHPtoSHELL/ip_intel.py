"""Operator supplied IP annotations. These never authorize or block traffic."""
from __future__ import annotations

import csv
import ipaddress
import json
from pathlib import Path

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ENTRIES = 10000


def _network(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError('IP/CIDR 不可空白')
    return str(ipaddress.ip_network(value.strip(), strict=False))


def _label(value: object) -> str:
    label = str(value).strip()
    if not label or len(label) > 80 or any(ord(ch) < 32 for ch in label):
        raise ValueError('GEO 標籤須為 1–80 個可顯示字元')
    return label


def parse_list_file(path: str | Path, kind: str) -> list:
    if kind not in ('geo_sources', 'object_ips'):
        raise ValueError('未知的名單類型')
    file = Path(path)
    if file.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('檔案超過 5 MiB，請分割後匯入')
    raw = file.read_text(encoding='utf-8-sig')
    if file.suffix.lower() == '.json':
        data = json.loads(raw)
        if isinstance(data, dict):
            data = data.get(kind, data.get('sources'))
        if not isinstance(data, list):
            raise ValueError('JSON 須包含對應名單陣列')
        rows = data
    else:
        rows = []
        for row in csv.reader(raw.splitlines()):
            if not row or not row[0].strip() or row[0].lstrip().startswith('#'):
                continue
            if row[0].strip().lower() in ('cidr', 'ip', 'address'):
                continue
            rows.append(row)
    if len(rows) > MAX_ENTRIES:
        raise ValueError('名單超過 10,000 筆')
    result = []
    seen = set()
    for row in rows:
        if kind == 'geo_sources':
            if isinstance(row, dict):
                net = _network(row.get('cidr', row.get('ip')))
                label = _label(row.get('label', row.get('region', '')))
            elif isinstance(row, (list, tuple)) and len(row) >= 2:
                net, label = _network(row[0]), _label(row[1])
            else:
                raise ValueError('GEO 每筆需有 IP/CIDR 與區域標籤')
            item = {'cidr': net, 'label': label}
            key = net
        else:
            value = row.get('cidr', row.get('ip')) if isinstance(row, dict) else row[0] if isinstance(row, (list, tuple)) else row
            item = _network(value)
            key = item
        if key not in seen:
            result.append(item)
            seen.add(key)
    return result


def classify(address: str, geo_sources: list, object_ips: list) -> tuple[str, bool]:
    ip = ipaddress.ip_address(address.split('%')[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    best = None
    for row in geo_sources:
        try:
            net = ipaddress.ip_network(row['cidr'], strict=False)
            if ip.version == net.version and ip in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, row['label'])
        except (ValueError, KeyError, TypeError):
            continue
    watched = False
    for value in object_ips:
        try:
            net = ipaddress.ip_network(value, strict=False)
            if ip.version == net.version and ip in net:
                watched = True
                break
        except (ValueError, TypeError):
            continue
    return (best[1] if best else '未比對到', watched)
