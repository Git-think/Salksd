#!/usr/bin/env python3
"""Local TUIC/HY2 handshakes against real cores; no VPS or production credentials.

python tests/core_tls.py --fixture /path/from/security.sh --singbox /path/to/sing-box
    --mihomo /path/to/mihomo --openssl /path/to/openssl --curl /path/to/curl
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
        self.wfile.write(b'TLS_IDENTITY_OK')

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    for name in ['fixture', 'singbox', 'mihomo', 'openssl', 'curl']:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    root = Path(args.fixture).resolve()
    state = root / 'state'
    generation = state / (state / 'current').read_text().strip()
    output = root / 'handshakes'
    output.mkdir(exist_ok=True)
    source = json.loads((generation / 'nekobox.json').read_text(encoding='utf-8'))
    mihomo = json.loads((generation / 'mihomo.yaml').read_text(encoding='utf-8'))
    subprocess.run([args.openssl, 'req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt',
                    'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=wrong.example',
                    '-addext', 'subjectAltName=DNS:wrong.example', '-keyout', str(output/'wrong.key'),
                    '-out', str(output/'wrong.pem')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wrong = (output/'wrong.pem').read_text()
    web = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    ports = {p: free_port() for p in ['tuic', 'hysteria2']}
    inbounds = []
    for outbound in source['outbounds']:
        if outbound['type'] not in ports:
            continue
        user = {'password': outbound['password']}
        if outbound['type'] == 'tuic':
            user['uuid'] = outbound['uuid']
        inbound = {'type': outbound['type'], 'listen': '127.0.0.1', 'listen_port': ports[outbound['type']],
                   'users': [user], 'tls': {'enabled': True, 'alpn': ['h3'],
                   'certificate_path': str(state/'cert.pem'), 'key_path': str(state/'private.key')}}
        if outbound['type'] == 'tuic':
            inbound['congestion_control'] = 'bbr'
            inbound['zero_rtt_handshake'] = False
        inbounds.append(inbound)
    server = {'log': {'level':'error'}, 'inbounds': inbounds, 'outbounds':[{'type':'direct'}]}
    (output/'server.json').write_text(json.dumps(server))
    processes = []
    logs = []
    results = []
    env = os.environ.copy()
    for key in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']:
        env.pop(key, None)
    try:
        log = open(output/'server.log', 'w'); logs.append(log)
        srv = subprocess.Popen([args.singbox,'run','-c',str(output/'server.json')], stdout=log, stderr=log, env=env)
        processes.append(srv)
        time.sleep(1)
        assert srv.poll() is None, 'local server failed to start'
        for engine in ['singbox', 'mihomo']:
            for protocol in ['tuic', 'hysteria2']:
                for scenario in ['correct', 'wrong-trust', 'wrong-sni']:
                    # Mihomo leaf-certificate pinning intentionally does not verify SNI.
                    if engine == 'mihomo' and scenario == 'wrong-sni':
                        continue
                    port = free_port()
                    tag = engine+'-'+protocol+'-'+scenario
                    if engine == 'singbox':
                        node = copy.deepcopy(next(o for o in source['outbounds'] if o['type']==protocol))
                        node['server_port'] = ports[protocol]
                        if scenario == 'wrong-trust': node['tls']['certificate'] = [wrong]
                        if scenario == 'wrong-sni': node['tls']['server_name'] = 'wrong.example'
                        cfg = {'log':{'level':'error'}, 'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':port}],
                               'outbounds':[node]}
                        path = output/(tag+'.json')
                        path.write_text(json.dumps(cfg), encoding='utf-8')
                        command = [args.singbox, 'run', '-c', str(path)]
                    else:
                        node = copy.deepcopy(next(o for o in mihomo['proxies'] if o['type']==protocol))
                        node['port'] = ports[protocol]
                        if scenario == 'wrong-trust': node['fingerprint'] = '0'*64
                        cfg = {'mixed-port':port,'allow-lan':False,'log-level':'error','mode':'rule',
                               'proxies':[node], 'rules':['MATCH,'+node['name']]}
                        path = output/(tag+'.json')
                        path.write_text(json.dumps(cfg), encoding='utf-8')
                        command = [args.mihomo, '-d', str(output), '-f', str(path)]
                    log = open(output/(tag+'.log'), 'w'); logs.append(log)
                    client = subprocess.Popen(command, stdout=log, stderr=log, env=env)
                    processes.append(client)
                    time.sleep(1)
                    assert client.poll() is None, tag+' failed to start'
                    result = subprocess.run([args.curl,'--silent','--show-error','--max-time','8','--noproxy','',
                        '--socks5-hostname','127.0.0.1:'+str(port),'http://127.0.0.1:'+str(web.server_port)+'/'],
                        capture_output=True, env=env)
                    success = result.returncode==0 and result.stdout==b'TLS_IDENTITY_OK'
                    assert success == (scenario=='correct'), tag+' unexpected handshake result'
                    results.append({'engine':engine,'protocol':protocol,'case':scenario,'passed':True})
                    print('PASS', tag, flush=True)
                    client.terminate()
                    client.wait(timeout=10)
        (output/'results.json').write_text(json.dumps(results,indent=2))
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill()
        for log in logs: log.close()
        web.shutdown()


if __name__ == '__main__':
    main()
