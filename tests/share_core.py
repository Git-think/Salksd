#!/usr/bin/env python3
"""Real local core authentication before/after shares.sh removes expired/revoked users.

Uses the same saved client nodes after removal. VLESS uses local ordinary TLS to
isolate UUID revocation; this is not a test of the production Reality handshake.
"""
import argparse
import copy
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'SHARE_AUTH_OK')

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--singbox', required=True)
    parser.add_argument('--curl', default='curl')
    args = parser.parse_args()
    state = Path(args.fixture).resolve() / 'state'
    output = state / 'share-core-test'
    output.mkdir(exist_ok=True)
    active = json.loads((state / 'share-active-server.json').read_text(encoding='utf-8'))
    removed = json.loads((state / 'server.json').read_text(encoding='utf-8'))
    bundle = json.loads((state / 'share-active-bundle.json').read_text(encoding='utf-8'))
    accounts = {'owner': json.loads(bundle['content']['singbox-all.json'])}
    for number, share in enumerate(bundle['shares'].values(), 1):
        accounts['share' + str(number)] = json.loads(share['content']['singbox-all.json'])
    assert len(accounts) == 3
    protocols = ['tuic', 'hysteria2', 'vless']
    ports = {p: free_port() for p in protocols}
    env = os.environ.copy()
    env.update(GOMEMLIMIT='64MiB', GOMAXPROCS='2')
    for name in ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']:
        env.pop(name, None)
    pem = (state / 'cert.pem').read_text()
    clients = {}
    # Build once: after revocation no client config or saved credential is changed.
    for account, content in accounts.items():
        for protocol in protocols:
            node = copy.deepcopy(next(n for n in content['outbounds'] if n['type'] == protocol and not n['tls']['insecure']))
            node['server'] = '127.0.0.1'
            node['server_port'] = ports[protocol]
            if protocol == 'vless':
                node['tls'] = {'enabled': True, 'insecure': False,
                    'server_name': 'api.fixture.example.test', 'certificate': [pem],
                    'utls': {'enabled': True, 'fingerprint': 'chrome'}}
            local = free_port()
            path = output / (account + '-' + protocol + '.json')
            path.write_text(json.dumps({'log': {'level': 'error'},
                'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': local}],
                'outbounds': [node]}), encoding='utf-8')
            clients[account, protocol] = path, local
    web = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    results = []
    try:
        for phase, source in [('active', active), ('removed', removed)]:
            inbounds = []
            for inbound in source['inbounds']:
                protocol = inbound['type']
                tls = {'enabled': True, 'certificate_path': str(state / 'cert.pem'),
                       'key_path': str(state / 'private.key')}
                if protocol != 'vless':
                    tls['alpn'] = ['h3']
                node = {'type': protocol, 'listen': '127.0.0.1', 'listen_port': ports[protocol],
                        'users': inbound['users'], 'tls': tls}
                if protocol == 'tuic':
                    node.update(congestion_control='bbr', zero_rtt_handshake=False)
                inbounds.append(node)
            config = output / (phase + '-server.json')
            config.write_text(json.dumps({'log': {'level': 'error'}, 'inbounds': inbounds,
                                         'outbounds': [{'type': 'direct'}]}), encoding='utf-8')
            with (output / (phase + '-server.log')).open('w') as server_log:
                server = subprocess.Popen([args.singbox, 'run', '-c', str(config)], env=env,
                                          stdout=server_log, stderr=server_log)
                try:
                    time.sleep(1)
                    assert server.poll() is None, 'server failed to start'
                    for (account, protocol), (path, local) in clients.items():
                        tag = phase + '-' + account + '-' + protocol
                        with (output / (tag + '.log')).open('w') as client_log:
                            client = subprocess.Popen([args.singbox, 'run', '-c', str(path)], env=env,
                                                      stdout=client_log, stderr=client_log)
                            try:
                                time.sleep(.5)
                                assert client.poll() is None, 'client failed to start: ' + tag
                                result = subprocess.run([args.curl, '--silent', '--max-time', '6', '--noproxy', '',
                                    '--socks5-hostname', '127.0.0.1:' + str(local),
                                    'http://127.0.0.1:' + str(web.server_port) + '/'],
                                    capture_output=True, env=env)
                                connected = result.returncode == 0 and result.stdout == b'SHARE_AUTH_OK'
                                expected = phase == 'active' or account == 'owner'
                                assert connected == expected, 'unexpected authentication result: ' + tag
                                results.append({'phase': phase, 'account': account, 'protocol': protocol,
                                                'connected': connected, 'passed': True})
                                print('PASS', tag, 'connected=' + str(connected), flush=True)
                            finally:
                                if client.poll() is None:
                                    client.terminate()
                                    client.wait(timeout=10)
                finally:
                    if server.poll() is None:
                        server.terminate()
                        server.wait(timeout=10)
        (output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    finally:
        web.shutdown()


if __name__ == '__main__':
    main()
