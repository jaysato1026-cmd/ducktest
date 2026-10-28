"""Local health, retention and redaction helpers for PHPtoSHELL."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path


def health_snapshot(*, started_at: dt.datetime, last_poll_at: dt.datetime | None,
                    last_firewall_check_at: dt.datetime | None, queue_age_seconds: float,
                    error_count: int, event_log: Path, now: dt.datetime | None = None,
                    paused: bool = False) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    age = lambda value: None if value is None else max(0, int((now - value).total_seconds()))
    log_error = False
    try:
        log_bytes = event_log.stat().st_size
    except FileNotFoundError:
        log_bytes = 0
    except OSError:
        log_bytes = None
        log_error = True
    return {
        'started_at': started_at.isoformat(),
        'last_poll_age_seconds': age(last_poll_at),
        'last_firewall_check_age_seconds': age(last_firewall_check_at),
        'queue_age_seconds': max(0, int(queue_age_seconds)),
        'error_count': max(0, int(error_count)),
        'event_log_bytes': log_bytes,
        'event_log_error': log_error,
        'state': ('ERROR' if log_error else 'PAUSED' if paused else
                  'STALE' if (age(last_poll_at) if last_poll_at else age(started_at)) > 30 else
                  'STARTING' if last_poll_at is None else 'HEALTHY'),
    }


def append_event(path: Path, event: dict, *, max_bytes: int = 100 * 1024 * 1024,
                 max_age_days: int = 30, now: dt.datetime | None = None) -> int:
    """Append a redacted event and remove only expired/oversized old rotations."""
    now = now or dt.datetime.now(dt.timezone.utc)
    row = dict(event)
    row.pop('cookie', None); row.pop('token', None); row.pop('password', None)
    row.setdefault('utc', now.isoformat())
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')
    removed = 0
    cutoff = now - dt.timedelta(days=max_age_days)
    for candidate in sorted(path.parent.glob(path.name + '.*')):
        try:
            modified = dt.datetime.fromtimestamp(candidate.stat().st_mtime, dt.timezone.utc)
            if modified < cutoff or candidate.stat().st_size > max_bytes:
                candidate.unlink(); removed += 1
        except OSError:
            continue
    if path.exists() and path.stat().st_size > max_bytes:
        rotated = path.with_name(path.name + '.1')
        if rotated.exists(): rotated.unlink()
        path.replace(rotated); removed += 1
    return removed
