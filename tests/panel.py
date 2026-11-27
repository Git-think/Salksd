"""Exercise the real PHP router over local HTTP, without SSH or a real port change.

The loopback-only test router marks requests as HTTPS, as the production HTTPS
front-end does. This test does not claim to test TLS transport or browser rendering.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]


def run(php):
    with tempfile.TemporaryDirectory(prefix="salksd-panel-") as temp:
        root = Path(temp)
        data = root / '.salksd-data'
        (data / 'sessions').mkdir(parents=True)
        shutil.copyfile(ROOT / 'lib/sub-router.php', root / 'secure-sub.php')
        shutil.copyfile(ROOT / 'lib/public-index.html', root / 'index.html')
        cover = (root/'index.html').read_text(encoding='utf-8')
        token = 'a' * 64
        legacy = 'old12345'
        payload = {'outbounds': [{'type': 'tuic', 'tls': {'insecure': False}}]}
        bundle = {'token_hash': hashlib.sha256(token.encode()).hexdigest(),
                  'ports': {'vless': 41001, 'tuic': 41002, 'hysteria2': 41003},
                  'content': {'singbox-all.json': json.dumps(payload), 'mihomo-all.yaml': '{"proxies":[]}',
                              'v2.log': base64.b64encode(b'vless://fixture\ntuic://legacy\nhysteria2://legacy\nv2rayn://tuic/fixture\nv2rayn://hysteria2/fixture\n').decode()}}
        share_token='abCD123_'
        share_id='c'*32
        bundle['shares']={hashlib.sha256(share_token.encode()).hexdigest():{'expires_at':int(time.time())+3600,'content':bundle['content']}}
        bundle['share_index']=[{'id':share_id,'token':share_token,'label':'<script>fixture</script>','created_at':int(time.time()),'expires_at':int(time.time())+3600,'revoked_at':0}]
        (data / 'bundle.json').write_text(json.dumps(bundle), encoding='utf-8')
        (data / 'panel.json').write_text(json.dumps({'password_hash': '', 'revision': 'b' * 64}), encoding='utf-8')
        (root / 'test-router.php').write_text("""<?php
parse_str((string)parse_url($_SERVER['REQUEST_URI'], PHP_URL_QUERY), $_GET);
$_SERVER['HTTPS'] = isset($_GET['plain']) ? 'off' : 'on';
require __DIR__ . '/secure-sub.php';
""", encoding='utf-8')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        log = (root / 'php.log').open('wb')
        # Linux builds can load ctype as an optional extension; -n omits it.
        # Disable it explicitly so Windows exercises the same minimal PHP setup.
        process = subprocess.Popen([php, '-n', '-d', 'disable_functions=ctype_digit',
                                    '-S', f'127.0.0.1:{port}', str(root / 'test-router.php')],
                                   cwd=root, stdout=log, stderr=log)
        cookies = {}

        def request(query, post=None, browser=True, client='one', extra=None, method=None):
            headers = {'User-Agent': 'Mozilla/5.0' if browser else 'NekoBox/1.4.2',
                       'Accept': 'text/html' if browser else '*/*'}
            if client in cookies:
                headers['Cookie'] = cookies[client]
            if extra:
                headers.update(extra)
            body = None
            if post is not None:
                if post.get('action') == 'change-ports':
                    post = dict({'protocol':'all'}, **post)
                body = urllib.parse.urlencode(post)
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
            path = ('/manage/' if query.get('format')=='manage' else '/')+query.get('token','')
            if query.get('format')=='bad': path='/unknown/path'
            connection.request(method or ('POST' if post is not None else 'GET'), path+'?' + urllib.parse.urlencode(query), body, headers)
            response = connection.getresponse()
            text = response.read().decode()
            result_headers = dict(response.getheaders())
            if 'Set-Cookie' in result_headers:
                cookies[client] = result_headers['Set-Cookie'].split(';', 1)[0]
            result = response.status, text, result_headers
            connection.close()
            return result

        def page(query, client='one'):
            status, text, headers = request(query, client=client)
            assert status == 200, (status, text)
            csrf = re.search(r'name="csrf" value="([a-f0-9]{64})"', text)
            assert csrf, text
            return csrf.group(1), text, headers

        main = {'token': token, 'format': 'manage'}
        feed = {'token': token, 'format': 'auto'}
        old = {'token': legacy, 'format': 'auto'}
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise AssertionError('PHP test server failed to start')
            assert request(dict(feed, plain='1'))[:2] == (200, cover)
            assert request(dict(feed, token='0' * 64))[:2] == (200, cover)
            assert request(dict(feed, format='bad'))[:2] == (200, cover)
            assert request(old)[:2] == (200, cover)
            share={'token':share_token,'format':'auto'}
            assert request(share)[:2] == (200, cover)
            assert request(share,browser=False,extra={'User-Agent':'curl/8.0'})[:2] == (200, cover)
            assert request(share,browser=False,extra={'User-Agent':''})[:2] == (200, cover)
            assert request(dict(share,format='manage'),browser=False)[:2] == (200, cover)
            assert request(share,{'action':'share-create'},browser=False)[:2] == (200, cover)
            assert request(share,{'action':'share-delete','share_id':share_id},browser=False)[:2] == (200, cover)
            assert request(share,{'action':'share-prune'},browser=False)[:2] == (200, cover)
            status, text, _ = request(feed, browser=False)
            assert status == 200 and json.loads(text) == payload
            status, text, _ = request(feed, extra={'User-Agent': 'Mozilla/5.0 NekoBox/1.4.2'})
            assert status == 200 and json.loads(text) == payload
            assert len(base64.b64decode(request(dict(feed, raw='1'))[1]).splitlines()) == 5
            assert len(base64.b64decode(request(share, browser=False, extra={'User-Agent':'v2rayN/7.25.6'})[1]).splitlines()) == 5
            assert json.loads(request(share, browser=False, extra={'User-Agent':'NekoBox/Android/1.4.2 (Prefer ClashMeta Format)'})[1]) == payload
            assert json.loads(request(share, browser=False, extra={'User-Agent':'FlClash/0.9.4'})[1]) == {'proxies': []}
            csrf, text, headers = page(feed)
            assert '更换全部端口' in text and '更换 TUIC 端口' in text and 'Content-Security-Policy' in headers
            assert '清理全部已失效记录' in text and '删除记录' in text
            assert 'Secure' in headers['Set-Cookie'] or 'secure' in headers['Set-Cookie']
            assert 'HttpOnly' in headers['Set-Cookie'] and 'SameSite=Strict' in headers['Set-Cookie']
            assert not (data / 'request.json').exists()
            assert request(main, method='HEAD')[1] == ''
            assert request(main, method='PUT')[:2] == (200, cover)
            assert request(main, {'action': 'change-ports', 'csrf': 'wrong'})[0] == 403
            assert request(main, {'action': 'change-ports', 'csrf': csrf}, extra={'Sec-Fetch-Site': 'cross-site'})[0] == 403
            password = 'test<&"password'
            assert request(main, {'action': 'password', 'csrf': csrf, 'mode': 'set',
                                 'new_password': password, 'confirm_password': password})[0] == 303
            settings = json.loads((data / 'panel.json').read_text())
            assert settings['password_hash'].startswith('$') and password not in (data / 'panel.json').read_text()
            assert list((data / 'panel-backups').glob('*.json'))
            assert '登录管理面板' in page(main, client='two')[1]
            assert request(share)[:2] == (200, cover)
            assert json.loads(request(feed, browser=False, client='two')[1]) == payload
            two_csrf, _, _ = page(main, client='two')
            for attempt in range(5):
                assert request(main, {'action': 'login', 'csrf': two_csrf, 'secret': 'bad'}, client='two')[0] == 401
            assert request(main, {'action': 'login', 'csrf': two_csrf, 'secret': password}, client='two')[0] == 429
            (data / 'login-rate.json').write_text(json.dumps({'since': 0, 'failures': 0}))
            assert request(main, {'action': 'login', 'csrf': two_csrf, 'secret': password}, client='two')[0] == 303
            two_csrf, _, _ = page(main, client='two')
            assert request(main, {'action': 'change-ports', 'protocol':'shell', 'csrf': two_csrf}, client='two')[0] == 400
            assert request(main, {'action': 'change-ports', 'protocol':'tuic', 'csrf': two_csrf}, client='two')[0] == 303
            queued = json.loads((data / 'request.json').read_text())
            assert set(queued) == {'action', 'id', 'created_at', 'protocol'} and queued['action'] == 'change-ports' and queued['protocol'] == 'tuic'
            assert request(main, {'action': 'change-ports', 'csrf': two_csrf}, client='two')[0] == 403
            two_csrf, _, _ = page(main, client='two')
            assert request(main, {'action': 'change-ports', 'csrf': two_csrf}, client='two')[0] == 409
            assert not (data / 'queue.lock').exists(), 'duplicate submission left a stale lock'
            assert request(dict(main, view='status'), client='two')[0] == 200
            (data / 'request.json').unlink()
            (data / 'result.json').write_text(json.dumps({'status': 'success', 'updated_at': time.time()}))
            assert request(main, {'action': 'change-ports', 'csrf': two_csrf}, client='two')[0] == 429
            assert not (data / 'queue.lock').exists()
            assert request(main, {'action': 'password', 'csrf': two_csrf, 'mode': 'remove',
                                 'current_password': 'wrong'}, client='two')[0] == 401
            assert request(main, {'action': 'password', 'csrf': two_csrf, 'mode': 'remove',
                                 'current_password': password}, client='two')[0] == 303
            assert '更换全部端口' in page(main, client='new')[1]
            csrf, _, _ = page(main, client='new')
            for minutes in ('', '0', '-1', '+1', '1.5', '1e2', ' 2', '2\n', '２', '527041'):
                status, text, _ = request(main, {'action':'share-create','csrf':csrf,'minutes':minutes,'label':'x'},client='new')
                assert status == 400, ('invalid duration', repr(minutes), status, text)
                assert not (data/'request.json').exists()
            assert request(main, {'action':'share-create','csrf':csrf,'minutes':'2','label':'test <>&'},client='new')[0]==303
            task=json.loads((data/'request.json').read_text())
            assert task['action']=='share-create' and task['duration']==120 and task['label']=='test <>&'
            assert not any(key in task for key in ('password','uuid','token'))
            (data/'request.json').unlink()
            csrf, _, _ = page(main,client='new')
            assert request(main,{'action':'share-revoke','csrf':csrf,'share_id':share_id},client='new')[0]==303
            assert json.loads((data/'request.json').read_text())['share_id']==share_id
            (data/'request.json').unlink()
            csrf, _, _ = page(main,client='new')
            assert request(main,{'action':'share-delete','csrf':csrf,'share_id':share_id},client='new')[0]==409
            assert not (data/'request.json').exists()
            bundle['share_index'][0]['expires_at']=1
            bundle['shares'][hashlib.sha256(share_token.encode()).hexdigest()]['expires_at']=1
            (data/'bundle.json').write_text(json.dumps(bundle))
            assert request(share,browser=False)[:2]==(200,cover)
            assert request(main,{'action':'share-delete','csrf':csrf,'share_id':share_id},client='new')[0]==303
            queued=json.loads((data/'request.json').read_text())
            assert queued['action']=='share-delete' and queued['share_id']==share_id
            assert set(queued)=={'id','action','created_at','share_id'}
            (data/'request.json').unlink()
            csrf, _, _ = page(main,client='new')
            assert request(main,{'action':'share-prune','csrf':csrf},client='new')[0]==303
            queued=json.loads((data/'request.json').read_text())
            assert queued['action']=='share-prune' and set(queued)=={'id','action','created_at'}
            (data/'request.json').unlink()
            (data/'result.json').write_text(json.dumps({'status':'success','action':'share-prune','updated_at':time.time()}))
            assert '已清理失效分享记录。' in page(main,client='new')[1]
            (data / 'panel.json').write_text('{broken')
            assert request(main)[0] == 503
            assert request(feed, browser=False)[0] == 200
            print('PASS: PHP routing, HTTPS gate, optional password, session invalidation, rate limit, CSRF, queue deduplication and fail-closed settings')
        finally:
            process.terminate()
            process.wait(timeout=10)
            log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--php', default=shutil.which('php'))
    args = parser.parse_args()
    if not args.php:
        parser.error('PHP 8.0+ is required')
    run(args.php)
