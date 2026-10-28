"""Interactive 8080 source guard. Python 3.7+; no third-party packages."""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time


def normalize(value):
    addr = ipaddress.ip_address(value.split('%')[0])
    return addr.ipv4_mapped if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped else addr


class Tracker:
    def __init__(self, sources):
        self.allowed = [ipaddress.ip_network(s, strict=True) for s in sources]
        if not self.allowed or any(n.prefixlen == 0 for n in self.allowed):
            raise ValueError('Nonempty, restricted allowlist required')
        if any(n.version == 6 and n.overlaps(ipaddress.ip_network('::ffff:0:0/96')) for n in self.allowed):
            raise ValueError('Use native IPv4 entries for mapped sources')
        self.allowed += [ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('::1/128')]
        self.marks = {}

    def trusted(self, source):
        addr = normalize(source)
        return any(addr.version == net.version and addr in net for net in self.allowed)

    def observe(self, sources, now):
        active = {str(normalize(s)) for s in sources}
        new = []
        for mark in self.marks.values():
            mark['active'] = False
        for source in sorted(active):
            if self.trusted(source):
                continue
            if source not in self.marks:
                if len(self.marks) >= 4096:
                    raise ValueError('Mark capacity reached; operator review required; no automatic block this cycle')
                self.marks[source] = dict(first=now, active=True, blocked=False, unblock_hold=False, retry=0)
                new.append(source)
            self.marks[source]['active'] = True
        return new

    def due(self, now):
        return [source for source, mark in self.marks.items()
                if mark['active'] and not mark['blocked'] and not mark['unblock_hold']
                and now - mark['first'] > 180 and now >= mark['retry']]


class Backend:
    def __init__(self, policy):
        self.policy = str(policy.resolve())
        self.script = str(Path(__file__).with_name('WatchBackend.ps1').resolve())
        self.engine = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) /
                          'System32/WindowsPowerShell/v1.0/powershell.exe')

    def call(self, operation, address=None):
        cmd = [self.engine, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
               '-File', self.script, '-Operation', operation, '-PolicyPath', self.policy]
        if address is not None:
            cmd += ['-Address', str(normalize(address))]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=45, encoding='utf-8', errors='replace',
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or 'Backend failed')
        return json.loads(result.stdout.lstrip('\ufeff').strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, default=Path(__file__).with_name('policy.json'))
    parser.add_argument('--log', type=Path, default=Path(__file__).with_name('watch-events.jsonl'))
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text(encoding='utf-8-sig'))
    if policy.get('version') != 1 or policy.get('port') != 8080 or not policy.get('allowed_sources'):
        raise ValueError('Invalid policy')
    tracker, backend = Tracker(policy['allowed_sources']), Backend(args.policy)
    backend.call('Check')
    # Prior blocks are not silently removed or forgotten after restart.
    existing = backend.call('Blocks')
    commands = queue.Queue()
    auto = False

    def log(event, **fields):
        row = dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), event=event, **fields)
        if args.log.exists() and args.log.stat().st_size >= 10 * 1024 * 1024:
            for index in (2, 1):
                previous = args.log.with_name(args.log.name + '.' + str(index))
                if previous.exists():
                    previous.replace(args.log.with_name(args.log.name + '.' + str(index+1)))
            args.log.replace(args.log.with_name(args.log.name + '.1'))
        with args.log.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(row, ensure_ascii=True) + '\n')
        print(json.dumps(row, ensure_ascii=True), flush=True)

    def block(source, reason):
        source = str(normalize(source))
        if tracker.trusted(source):
            raise ValueError('Allowlisted/loopback sources cannot be blocked by Watch')
        # Log intent durably before any firewall mutation. If writing fails, do not block.
        log('block-request', source=source, reason=reason)
        result = backend.call('Block', source)
        if not result.get('blocked'):
            raise RuntimeError('Backend did not verify the block')
        if source in tracker.marks:
            tracker.marks[source]['blocked'] = True
        log('source-block-rule-active', source=source, reason=reason, tcp_close_proven=False)

    def reader():
        while True:
            try:
                commands.put(input().strip())
            except EOFError:
                commands.put('quit')
                return

    print('MANUAL mode. New unapproved sources are marked. Automatic threshold: >180 seconds.')
    print('Commands: list | blocks | block IP | unblock IP | auto on | auto off | quit')
    print('Block targets TCP 8080 traffic only; never terminates PHP/Java/MySQL. Existing rules:', existing)
    log('watch-start', auto=False)
    threading.Thread(target=reader, daemon=True).start()
    next_poll = 0
    running = True
    while running:
        try:
            command = commands.get(timeout=0.25)
        except queue.Empty:
            command = None
        if command:
            try:
                words = command.split()
                if words == ['quit']:
                    running = False
                    continue
                if words == ['auto', 'on'] or words == ['auto', 'off']:
                    auto = words[1] == 'on'
                    log('auto-mode', enabled=auto)
                elif words == ['list']:
                    now = time.monotonic()
                    print({s: dict(m, elapsed_seconds=int(now-m['first'])) for s, m in tracker.marks.items()}, flush=True)
                elif words == ['blocks']:
                    print(backend.call('Blocks'), flush=True)
                elif len(words) == 2 and words[0] == 'block':
                    block(words[1], 'operator')
                elif len(words) == 2 and words[0] == 'unblock':
                    source = str(normalize(words[1]))
                    log('unblock-request', source=source)
                    backend.call('Unblock', source)
                    if source in tracker.marks:
                        tracker.marks[source].update(blocked=False, unblock_hold=True)
                    log('source-unblocked', source=source, auto_hold_until_restart=True)
                else:
                    print('Unknown command', flush=True)
            except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                print('COMMAND FAILED:', str(exc), flush=True)
        if time.monotonic() < next_poll:
            continue
        next_poll = time.monotonic() + 5
        try:
            rows = backend.call('Poll')
            sources = [row['RemoteAddress'] for row in rows]
            now = time.monotonic()
            for source in tracker.observe(sources, now):
                log('unapproved-source-marked', source=source)
            if auto and commands.empty():
                # Bound rule churn and operator-command latency during bursts.
                for source in tracker.due(now)[:1]:
                    try:
                        block(source, 'observed-over-180-seconds')
                    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                        tracker.marks[source]['retry'] = time.monotonic() + 30
                        print('AUTO BLOCK FAILED:', source, str(exc), flush=True)
        except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired, KeyError, TypeError) as exc:
            # No enforcement from stale/failed observations.
            print('POLL FAILED; no block this cycle:', str(exc), flush=True)
    log('watch-stop', rules_retained=True)
    print('Watch stopped. Existing source block rules remain until explicitly unblocked.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Stopped; existing source blocks remain. Restart Watch to inspect/unblock them.')
