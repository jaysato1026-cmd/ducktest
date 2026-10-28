import http.server
import http.client
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
import socket
import subprocess
import threading
import tempfile
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DLL = ROOT / 'http-guard' / 'bin' / 'Release' / 'net9.0' / 'PHPtoSHELL.HttpGuard.dll'
PACKAGED_EXE = ROOT / 'PHPtoSHELL.HttpGuard.exe'
COMMAND = ([os.environ['HTTPGUARD_BIN']] if os.environ.get('HTTPGUARD_BIN') else
           [str(PACKAGED_EXE)] if PACKAGED_EXE.exists() else ['dotnet', str(DLL)])


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Upstream(http.server.BaseHTTPRequestHandler):
    calls = 0
    hold_condition = threading.Condition()
    holding = 0
    release_hold = threading.Event()

    def do_GET(self):
        type(self).calls += 1
        if self.path == '/hold':
            with self.hold_condition:
                type(self).holding += 1
                self.hold_condition.notify_all()
            self.release_hold.wait(6)
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/login?step=1')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        body = json.dumps({'path': self.path, 'host': self.headers.get('Host'),
                           'internal': self.headers.get('X-Internal'),
                           'forwarded': self.headers.get('Forwarded'),
                           'real_ip': self.headers.get('X-Real-IP'),
                           'forwarded_host': self.headers.get('X-Forwarded-Host')}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Set-Cookie', 'demo=ok; HttpOnly')
        self.send_header('Connection', 'X-Upstream-Hop')
        self.send_header('X-Upstream-Hop', 'must-not-reach-client')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        type(self).calls += 1
        size = int(self.headers.get('Content-Length', '0'))
        payload = self.rfile.read(size)
        body = json.dumps({'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(), 'forwarded': self.headers.get('X-Forwarded-For'),
                           'type': self.headers.get('Content-Type')}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def request(url, data=None, headers=None):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers or {}), timeout=8) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers


upstream_port, guard_port = free_port(), free_port()
server = http.server.ThreadingHTTPServer(('127.0.0.1', upstream_port), Upstream)
threading.Thread(target=server.serve_forever, daemon=True).start()
environment = dict(os.environ, HTTPGUARD_LISTEN=f'http://127.0.0.1:{guard_port}',
                   HTTPGUARD_UPSTREAM=f'http://127.0.0.1:{upstream_port}', HTTPGUARD_TEST_DIAGNOSTICS='1')
remote_env = dict(environment, HTTPGUARD_LISTEN=f'http://0.0.0.0:{free_port()}')
remote_env.pop('HTTPGUARD_ALLOW_REMOTE_LISTEN', None)
remote = subprocess.run(COMMAND, env=remote_env, capture_output=True,
                        timeout=8, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
assert remote.returncode != 0 and b'ALLOW_REMOTE_LISTEN' in remote.stderr
loop_env = dict(environment, HTTPGUARD_LISTEN=f'http://localhost:{upstream_port}')
loop = subprocess.run(COMMAND, env=loop_env, capture_output=True,
                      timeout=8, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
assert loop.returncode != 0 and b'distinct' in loop.stderr
guard_log = tempfile.TemporaryFile()
guard = subprocess.Popen(COMMAND, env=environment, stdout=guard_log,
                         stderr=guard_log, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
try:
    base = f'http://127.0.0.1:{guard_port}'
    for _ in range(40):
        try:
            health_status, health_body, _ = request(base + '/_phptoshell/health')
            if health_status == 200 and health_body == b'pilot-ready':
                break
        except (OSError, TimeoutError):
            time.sleep(0.1)
    else:
        raise AssertionError('Guard did not start')
    status, body, headers = request(base + '/ok?x=1')
    assert status == 200 and json.loads(body)['path'] == '/ok?x=1'
    assert headers['Set-Cookie'] == 'demo=ok; HttpOnly'
    assert headers.get('X-Upstream-Hop') is None
    encoded_path = '/files/a%20b/%E6%B8%AC%E8%A9%A6?name=a%2Bb&value=%26%3D'
    status, encoded_body, _ = request(base + encoded_path)
    assert status == 200 and json.loads(encoded_body)['path'] == encoded_path, encoded_body
    redirect_calls = Upstream.calls
    redirect_connection = http.client.HTTPConnection('127.0.0.1', guard_port, timeout=8)
    redirect_connection.request('GET', '/redirect')
    redirect_response = redirect_connection.getresponse()
    assert redirect_response.status == 302
    assert redirect_response.getheader('Location') == '/login?step=1'
    redirect_response.read()
    redirect_connection.close()
    assert Upstream.calls == redirect_calls + 1
    trap_port = free_port()
    status, body, _ = request(base + f'/http://127.0.0.1:{trap_port}/escape?x=1')
    assert status == 200 and json.loads(body)['path'] == f'/http://127.0.0.1:{trap_port}/escape?x=1'
    assert json.loads(body)['host'] == f'127.0.0.1:{upstream_port}'
    header_connection = http.client.HTTPConnection('127.0.0.1', guard_port, timeout=8)
    header_connection.request('GET', '/headers', headers={
        'Connection': 'X-Internal', 'X-Internal': 'injected', 'Forwarded': 'for=192.0.2.1',
        'X-Real-IP': '192.0.2.1', 'X-Forwarded-Host': 'wrong.example'})
    header_response = header_connection.getresponse()
    status, body = header_response.status, header_response.read()
    header_connection.close()
    assert status == 200
    assert all(json.loads(body)[name] is None for name in
               ('internal', 'forwarded', 'real_ip', 'forwarded_host')), body

    status, body, _ = request(base + '/form', b'hello=world', {'Content-Type': 'application/x-www-form-urlencoded'})
    assert status == 200 and json.loads(body)['bytes'] == 11
    status, body, _ = request(base + '/empty', b'', {'Content-Type': 'application/x-www-form-urlencoded'})
    assert status == 200 and json.loads(body)['bytes'] == 0
    assert json.loads(body)['type'] == 'application/x-www-form-urlencoded'

    multipart = b'--safe\r\nContent-Disposition: form-data; name="title"\r\n\r\nhello\r\n--safe--\r\n'
    status, body, _ = request(base + '/upload', multipart,
                              {'Content-Type': 'multipart/form-data; boundary=safe', 'X-Forwarded-For': '1.2.3.4'})
    assert status == 200 and json.loads(body)['bytes'] == len(multipart)
    assert json.loads(body)['sha256'] == hashlib.sha256(multipart).hexdigest()
    status, quoted_body, _ = request(base + '/upload', multipart,
                                     {'Content-Type': 'multipart/form-data; boundary="safe"'})
    assert status == 200 and json.loads(quoted_body)['sha256'] == hashlib.sha256(multipart).hexdigest()
    assert json.loads(body)['forwarded'] != '1.2.3.4'
    boundary_parts = b''.join(b'--limit\r\nContent-Disposition: form-data; name="x"\r\n\r\na\r\n'
                              for _ in range(128)) + b'--limit--\r\n'
    status, body, _ = request(base + '/upload', boundary_parts,
                             {'Content-Type': 'multipart/form-data; boundary=limit'})
    assert status == 200 and json.loads(body)['bytes'] == len(boundary_parts)
    assert json.loads(body)['sha256'] == hashlib.sha256(boundary_parts).hexdigest()
    valid_nested = (b'--validnest\r\nContent-Disposition: form-data; name="a' + b'[b]' * 8 +
                    b'"\r\n\r\nx\r\n--validnest--\r\n')
    status, body, _ = request(base + '/upload', valid_nested,
                             {'Content-Type': 'multipart/form-data; boundary=validnest'})
    assert status == 200 and json.loads(body)['bytes'] == len(valid_nested)
    upload = (b'--diskbuffer\r\nContent-Disposition: form-data; name="file"; filename="fixture.bin"\r\n'
              b'Content-Type: application/octet-stream\r\n\r\n' + bytes(range(256)) * 4096 +
              b'\r\n--diskbuffer--\r\n')
    status, body, _ = request(base + '/upload', upload,
                             {'Content-Type': 'multipart/form-data; boundary=diskbuffer'})
    assert status == 200 and json.loads(body)['bytes'] == len(upload)
    assert json.loads(body)['sha256'] == hashlib.sha256(upload).hexdigest()
    def parallel_upload(index, destination=base):
        body = upload.replace(b'fixture.bin', f'fixture-{index}.bin'.encode())
        status, received, _ = request(destination + '/parallel-upload', body,
                                      {'Content-Type': 'multipart/form-data; boundary=diskbuffer'})
        assert status == 200, (destination, index, status, received[:256])
        assert json.loads(received)['sha256'] == hashlib.sha256(body).hexdigest(), (index, received)
        return True
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(lambda index: parallel_upload(index, f'http://127.0.0.1:{upstream_port}'), range(4)))
        assert all(pool.map(parallel_upload, range(4)))
    header_limit_part = (b'--headercount\r\nContent-Disposition: form-data; name="x"\r\n' +
                         b''.join(f'X-Test-{i}: ok\r\n'.encode() for i in range(31)) +
                         b'\r\nx\r\n--headercount--\r\n')
    status, body, _ = request(base + '/upload', header_limit_part,
                             {'Content-Type': 'multipart/form-data; boundary=headercount'})
    assert status == 200 and json.loads(body)['sha256'] == hashlib.sha256(header_limit_part).hexdigest()
    allowed_calls = Upstream.calls
    too_many_headers = header_limit_part.replace(b'\r\n\r\nx', b'\r\nX-Extra: over-limit\r\n\r\nx')
    status, _, _ = request(base + '/upload', too_many_headers,
                          {'Content-Type': 'multipart/form-data; boundary=headercount'})
    assert status == 413 and Upstream.calls == allowed_calls

    status, _, _ = request(base + '/upload', b'bad', {'Content-Type': 'multipart/form-data'})
    assert status == 400 and Upstream.calls == allowed_calls
    status, _, _ = request(base + '/upload', b'bad',
                          {'Content-Type': 'multipart/form-data; boundary=""'})
    assert status == 400 and Upstream.calls == allowed_calls
    parts = b''.join(b'--many\r\nContent-Disposition: form-data; name="x"\r\n\r\na\r\n'
                     for _ in range(129)) + b'--many--\r\n'
    status, _, _ = request(base + '/upload', parts, {'Content-Type': 'multipart/form-data; boundary=many'})
    assert status == 413 and Upstream.calls == allowed_calls
    header = b'--long\r\nX-Test: ' + b'a' * 9000 + b'\r\n\r\nx\r\n--long--\r\n'
    status, _, _ = request(base + '/upload', header, {'Content-Type': 'multipart/form-data; boundary=long'})
    assert status == 413 and Upstream.calls == allowed_calls
    nested = (b'--nest\r\nContent-Disposition: form-data; name="a' + b'[b]' * 9 +
              b'"\r\n\r\nx\r\n--nest--\r\n')
    status, _, _ = request(base + '/upload', nested, {'Content-Type': 'multipart/form-data; boundary=nest'})
    assert status == 413 and Upstream.calls == allowed_calls
    connection = http.client.HTTPConnection('127.0.0.1', guard_port, timeout=8)
    connection.request('POST', '/upload', [parts[:2000], parts[2000:]],
                       {'Content-Type': 'multipart/form-data; boundary=many'}, encode_chunked=True)
    response = connection.getresponse()
    assert response.status == 413 and Upstream.calls == allowed_calls
    response.read()
    connection.close()
    with socket.create_connection(('127.0.0.1', guard_port), timeout=8) as connection:
        connection.sendall(b'POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\n'
                           b'Content-Length: 16777217\r\nConnection: close\r\n\r\n')
        first_line = connection.recv(256).split(b'\r\n', 1)[0]
        assert b'413' in first_line and Upstream.calls == allowed_calls, first_line
    with ThreadPoolExecutor(max_workers=16) as pool:
        held = [pool.submit(request, base + '/hold') for _ in range(16)]
        try:
            with Upstream.hold_condition:
                assert Upstream.hold_condition.wait_for(lambda: Upstream.holding == 16, timeout=4)
            status, _, headers = request(base + '/over-capacity')
            assert status == 503 and headers.get('Retry-After') == '1'
            assert request(base + '/_phptoshell/health')[1] == b'pilot-ready'
        finally:
            Upstream.release_hold.set()
        assert all(future.result()[0] == 200 for future in held)
    assert request(base + '/after-capacity')[0] == 200
    server.shutdown()
    server.server_close()
    status, _, _ = request(base + '/upstream-unavailable')
    assert status == 502, status
    health_status, health_body, health_headers = request(base + '/_phptoshell/health')
    assert health_status == 200 and health_body == b'pilot-ready'
    assert health_headers.get('Cache-Control') == 'no-store'
    assert health_headers.get('Server') is None
    print('HTTP guard integration OK: pass-through, multipart limits and upstream failure isolation')
finally:
    failed = sys.exc_info()[0] is not None
    guard.terminate()
    try:
        guard.wait(timeout=5)
    except subprocess.TimeoutExpired:
        guard.kill()
    server.shutdown()
    server.server_close()
    if failed:
        guard_log.seek(0)
        print(guard_log.read()[-12000:].decode('utf-8', errors='replace'))
    guard_log.close()
