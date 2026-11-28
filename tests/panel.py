from storage_codec import read as stored_read, write as stored_write
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
        runtime=(ROOT / 'lib/php-runtime.php').read_text(encoding='utf8')
        # Mock only the network body. The real URL validator, template compiler,
        # cache, router and persisted task handling remain under test.
        runtime=runtime.replace('function acl_fetch(string $url): string {','function acl_network_fetch(string $url): string {',1)
        runtime += '''
function acl_fetch(string $url): string {
    if ($url==='https://rules.fixture.test/default.ini') {
        file_put_contents(__DIR__.'/fetch-count','x',FILE_APPEND);
        $body=file_get_contents(__DIR__.'/fixture.ini');
        if ($body==='!download-failed') { throw new RuntimeException('fixture network failure'); }
        return $body;
    }
    return acl_network_fetch($url);
}
'''
        (root / 'php-runtime.php').write_text(runtime,encoding='utf8')
        shutil.copyfile(ROOT / 'lib/public-index.html', root / 'index.html')
        cover = (root/'index.html').read_text(encoding='utf-8')
        token = 'a' * 64
        legacy = 'old12345'
        payload = {'outbounds': [{'type': 'tuic', 'tls': {'insecure': False}}]}
        bundle = {'token_hash': hashlib.sha256(token.encode()).hexdigest(),
                  'ports': {'vless': 41001, 'tuic': 41002, 'hysteria2': 41003},
                  'content': {'p08': json.dumps(payload), 'p09': '{"proxies":[]}',
                              'p07': base64.b64encode(b'vless://fixture\ntuic://legacy\nhysteria2://legacy\nv2rayn://tuic/fixture\nv2rayn://hysteria2/fixture\n').decode()}}
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
            if query.get('path_format'): path += '/' + query['path_format']
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
            assert request(share,{'action':'backup-prune','keep':'1'},browser=False)[:2] == (200, cover)
            status, text, _ = request(feed, browser=False)
            assert status == 200 and json.loads(text) == payload
            status, text, _ = request(feed, extra={'User-Agent': 'Mozilla/5.0 NekoBox/1.4.2'})
            assert status == 200 and json.loads(text) == payload
            assert len(base64.b64decode(request(dict(feed, raw='1'))[1]).splitlines()) == 5
            assert len(base64.b64decode(request(share, browser=False, extra={'User-Agent':'v2rayN/7.25.6'})[1]).splitlines()) == 5
            assert json.loads(request(share, browser=False, extra={'User-Agent':'NekoBox/Android/1.4.2 (Prefer ClashMeta Format)'})[1]) == payload
            assert json.loads(request(share, browser=False, extra={'User-Agent':'FlClash/0.9.4'})[1]) == {'proxies': []}
            for kind, name in {'c':'p09','b':'p07','s':'p08','n':'p08'}.items():
                for selection in [{'path_format':kind},{'f':kind}]:
                    assert request(dict(feed, **selection))[1] == bundle['content'][name]
                    assert request(dict(share, **selection))[1] == cover
                    assert request(dict(share, **selection),browser=False)[1] == bundle['content'][name]
            assert request(dict(feed,path_format='1'))[:2] == (200,cover)
            assert request(dict(feed,path_format='clash'))[:2] == (200,cover)
            assert request(dict(feed,path_format='c',f='b'))[:2] == (200,cover)
            for agent in ['Nekoray/4.0','sing-box/1.12','SFA/1.12','SFI/1.12','SFM/1.12','Karing/1','Hiddify/2']:
                assert request(feed,browser=False,extra={'User-Agent':agent})[1] == bundle['content']['p08']
            for agent in ['ClashMetaForAndroid/2','ClashVerge/2','Mihomo/1.19','FlClash/0.9']:
                assert request(feed,browser=False,extra={'User-Agent':agent})[1] == bundle['content']['p09']
            for agent in ['v2rayN/7','v2rayNG/1','Shadowrocket/2','Streisand/1','Loon/3','Happ/1','V2Box/1']:
                text=request(feed,browser=False,extra={'User-Agent':agent})[1]
                if agent.startswith('v2rayN/'):
                    assert text == bundle['content']['p07']
                else:
                    links=base64.b64decode(text).decode().splitlines()
                    assert len(links)==(2 if agent.startswith('v2rayNG/') else 3)
                    assert not any(link.startswith('v2rayn://') for link in links)
            custom='[custom]\ncustom_proxy_group=Custom`select`[]DIRECT\nruleset=DIRECT,[]GEOIP,CN\nruleset=Custom,[]FINAL\n'
            url='https://example.com/template.ini'
            encoded_url=lambda value: base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')
            (data/'templates').mkdir()
            stored_write(data/'templates'/hashlib.sha256(url.encode()).hexdigest(),custom)
            overridden=request(dict(feed,f='c',a=encoded_url(url)))
            assert overridden[0]==200 and json.loads(overridden[1])['rules']==['GEOIP,CN,DIRECT','MATCH,Custom']
            assert request(dict(feed,f='c'))[1]==bundle['content']['p09']
            assert request(dict(feed,f='b',a=url))[0]==400
            assert request(dict(feed,f='c',a=encoded_url('file:///etc/passwd')))[0]==422
            assert request(dict(feed,f='c',a=encoded_url('https://127.0.0.1/private')))[0]==422
            csrf, text, headers = page(feed)
            assert '更换全部端口' in text and '更换 TUIC 端口' in text and 'Content-Security-Policy' in headers
            assert '清理全部已失效记录' in text and '删除记录' in text
            assert '备份清理' in text and '保留最近几份自动备份' in text
            assert '订阅格式与分流' in text and '保存默认模板' in text
            for suffix in ('','c','b','s','n'):
                full=f'https://127.0.0.1:{port}/{token}'+('/'+suffix if suffix else '')
                assert f'value="{full}"' in text
            assert text.count('data-copy=')==6
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
            settings = json.loads(stored_read((data / 'panel.json')))
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
            queued = json.loads(stored_read((data / 'request.json')))
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
            task=json.loads(stored_read((data/'request.json')))
            assert task['action']=='share-create' and task['duration']==120 and task['label']=='test <>&'
            assert not any(key in task for key in ('password','uuid','token'))
            (data/'request.json').unlink()
            csrf, _, _ = page(main,client='new')
            assert request(main,{'action':'share-revoke','csrf':csrf,'share_id':share_id},client='new')[0]==303
            assert json.loads(stored_read((data/'request.json')))['share_id']==share_id
            (data/'request.json').unlink()
            csrf, _, _ = page(main,client='new')
            assert request(main,{'action':'share-delete','csrf':csrf,'share_id':share_id},client='new')[0]==409
            assert not (data/'request.json').exists()
            bundle['share_index'][0]['expires_at']=1
            bundle['shares'][hashlib.sha256(share_token.encode()).hexdigest()]['expires_at']=1
            (data/'bundle.json').write_text(json.dumps(bundle))
            assert request(share,browser=False)[:2]==(200,cover)
            assert request(main,{'action':'share-delete','csrf':csrf,'share_id':share_id},client='new')[0]==303
            queued=json.loads(stored_read((data/'request.json')))
            assert queued['action']=='share-delete' and queued['share_id']==share_id
            assert set(queued)=={'id','action','created_at','share_id'}
            (data/'request.json').unlink()
            csrf, _, _ = page(main,client='new')
            assert request(main,{'action':'share-prune','csrf':csrf},client='new')[0]==303
            queued=json.loads(stored_read((data/'request.json')))
            assert queued['action']=='share-prune' and set(queued)=={'id','action','created_at'}
            (data/'request.json').unlink()
            (data/'result.json').write_text(json.dumps({'status':'success','action':'share-prune','updated_at':time.time()}))
            assert '已清理失效分享记录。' in page(main,client='new')[1]
            csrf, _, _ = page(main,client='new')
            for keep in ('0','-1','1001','3.5','３','1\n'):
                assert request(main,{'action':'backup-prune','csrf':csrf,'keep':keep,'revision':'d'*64},client='new')[0]==400
            assert request(main,{'action':'backup-prune','csrf':csrf,'keep':'3','revision':'bad'},client='new')[0]==400
            assert request(main,{'action':'backup-refresh','csrf':csrf},client='new')[0]==303
            queued=json.loads(stored_read((data/'request.json')))
            assert queued['action']=='backup-refresh' and set(queued)=={'id','action','created_at'}
            (data/'request.json').unlink()
            csrf, _, _ = page(main,client='new')
            assert request(main,{'action':'backup-prune','csrf':csrf,'keep':'3','revision':'d'*64},client='new')[0]==303
            queued=json.loads(stored_read((data/'request.json')))
            assert queued['keep']==3 and queued['revision']=='d'*64 and set(queued)=={'id','action','created_at','keep','revision'}
            (data/'request.json').unlink()
            (data/'backups.json').write_text(json.dumps({'items':[],'revision':'d'*64,'can_prune':False,'total_kib':0}))
            assert json.loads(request(dict(main,view='status'),client='new')[1])['backups']['revision']=='d'*64
            csrf,_,_=page(main,client='new')
            assert request(main,{'action':'rules-save','csrf':csrf,'rules-mode':'paste','rules-ini':custom},client='new')[0]==303
            queued=json.loads(stored_read(data/'request.json'))
            assert queued['action']=='rules-save' and queued['rules']=={'mode':'custom','ini':custom}
            assert b'custom_proxy_group' not in (data/'request.json').read_bytes()
            (data/'request.json').unlink()
            csrf,_,_=page(main,client='new')
            assert request(main,{'action':'rules-save','csrf':csrf,'rules-mode':'paste','rules-ini':'[custom]\nwrong=true'},client='new')[0]==422
            assert not (data/'request.json').exists()
            default_url='https://rules.fixture.test/default.ini'
            (root/'fixture.ini').write_text(custom,encoding='utf8',newline='\n')
            assert request(main,{'action':'rules-save','csrf':csrf,'rules-mode':'url','rules-url':default_url},client='new')[0]==303
            queued=json.loads(stored_read(data/'request.json'))
            assert queued['rules']=={'mode':'url','url':default_url,'ini':custom}
            assert default_url.encode() not in (data/'request.json').read_bytes()
            (data/'request.json').unlink()
            # Emulate only the worker's publication; the real worker save is
            # exercised by security.sh and its queue validation by panel-worker.sh.
            bundle['rules']={**queued['rules'],'updated_at':int(time.time())}
            stored_write(data/'bundle.json',json.dumps(bundle))
            csrf,text,_=page(main,client='new')
            assert '<option value="url" selected>' in text and f'value="{default_url}"' in text
            expected=['GEOIP,CN,DIRECT','MATCH,Custom']
            assert json.loads(request(dict(feed,f='c'))[1])['rules']==expected
            # Shared clients use the same template, while their nodes stay isolated.
            bundle['shares'][hashlib.sha256(share_token.encode()).hexdigest()]['expires_at']=int(time.time())+3600
            stored_write(data/'bundle.json',json.dumps(bundle))
            assert json.loads(request(dict(share,f='c'),browser=False)[1])['rules']==expected
            later=custom.replace('GEOIP,CN','GEOIP,JP')
            (root/'fixture.ini').write_text(later,encoding='utf8',newline='\n')
            # A fresh save is used immediately, even when upstream has changed.
            assert json.loads(request(dict(feed,f='c'))[1])['rules']==expected
            bundle['rules']['updated_at']=int(time.time())-3601
            stored_write(data/'bundle.json',json.dumps(bundle))
            assert json.loads(request(dict(feed,f='c'))[1])['rules']==['GEOIP,JP,DIRECT','MATCH,Custom']
            cache=data/'rules-state.json'
            assert cache.read_bytes().startswith(b'SALKSD-STORE-1:') and 'GEOIP,JP' in stored_read(cache)
            (root/'fixture.ini').write_text('[custom]\nwrong=true',encoding='utf8')
            assert json.loads(request(dict(feed,f='c'))[1])['rules']==['GEOIP,JP,DIRECT','MATCH,Custom']
            live=json.loads(stored_read(cache));live['checked_at']=int(time.time())-3601
            stored_write(cache,json.dumps(live))
            count=(root/'fetch-count').stat().st_size
            # Merely opening the panel does not refresh or schedule a download.
            page(main,client='new')
            assert (root/'fetch-count').stat().st_size==count
            fallback=request(dict(feed,f='c'))
            assert fallback[0]==200 and fallback[2]['X-Subscription-Rules-Status']=='cached-fallback'
            assert r'\/' not in fallback[1], 'Mihomo YAML rejects JSON escaped slashes'
            content=json.loads(fallback[1]);assert content['rules']==['GEOIP,JP,DIRECT','MATCH,Custom']
            notices=content['proxies']
            assert len(notices)==2 and notices[0]['name'].startswith('[NOTICE]') and notices[1]['name'].startswith('[提醒]')
            assert all(n['skip-cert-verify'] is False and n['server'].endswith('.invalid') for n in notices)
            assert all(not any(x.startswith(('[NOTICE]','[提醒]')) for x in g['proxies']) for g in content['proxy-groups'] if g['name']!='[NOTICE] Messages')
            failed=json.loads(stored_read(cache))
            assert failed['ini']==live['ini'] and failed['status']=='stale' and failed['retry_at']>time.time()
            alert=json.loads(request(dict(main,view='status'),client='new')[1])
            assert alert['rules_status']['status']=='stale' and len(alert['notices'])==1 and 'zh' in alert['notices'][0]
            assert '正在使用持久缓存' in page(main,client='new')[1]
            for suffix in ('b','s','n','c'):
                response=request(dict(feed,f=suffix))
                assert response[0]==200
                if suffix=='b':
                    lines=base64.b64decode(response[1]).decode().splitlines()
                    assert len(lines)==7 and '[NOTICE]' in urllib.parse.unquote(lines[-2]) and '[提醒]' in urllib.parse.unquote(lines[-1])
                    assert lines[:-2]==base64.b64decode(bundle['content']['p07']).decode().splitlines()
                elif suffix in ('s','n'):
                    nodes=json.loads(response[1])['outbounds']
                    assert nodes[:-2]==payload['outbounds'] and len(nodes)==3
                    assert all(n['tls']['insecure'] is False for n in nodes[-2:])
            assert (root/'fetch-count').stat().st_size==count+1, 'failed URL was retried within backoff'
            assert len(json.loads(request(dict(share,f='c'),browser=False)[1])['proxies'])==2
            assert json.loads(request(dict(feed,f='c',a=encoded_url(url)))[1])['rules']==expected
            unchanged=(data/'bundle.json').read_bytes()
            assert request(main,{'action':'rules-save','csrf':csrf,'rules-mode':'url','rules-url':default_url},client='new')[0]==422
            assert not (data/'request.json').exists() and (data/'bundle.json').read_bytes()==unchanged
            assert request(main,{'action':'rules-save','csrf':csrf,'rules-mode':'url','rules-url':'https://127.0.0.1/private'},client='new')[0]==422
            # Each request starts a fresh PHP request context; a later network failure
            # also preserves the same last validated INI, never the invalid download.
            (root/'fixture.ini').write_text('!download-failed',encoding='utf8')
            failed['retry_at']=int(time.time())-1;stored_write(cache,json.dumps(failed))
            assert request(dict(feed,f='b'))[2]['X-Subscription-Rules-Status']=='cached-fallback'
            failed=json.loads(stored_read(cache));assert failed['ini']==live['ini']
            # A successful retry replaces the persistent snapshot and removes both notices.
            (root/'fixture.ini').write_text(custom,encoding='utf8',newline='\n')
            failed['retry_at']=int(time.time())-1;stored_write(cache,json.dumps(failed))
            recovered=request(dict(feed,f='n'))
            assert recovered[2]['X-Subscription-Rules-Status']=='ok' and json.loads(recovered[1])==payload
            assert request(dict(feed,f='b'))[1]==bundle['content']['p07']
            live=json.loads(stored_read(cache));assert live['status']=='ok' and live['ini']==custom
            assert json.loads(request(dict(main,view='status'),client='new')[1])['notices']==[]
            # The saved default stays separate from its refreshed persistent version.
            assert (data/'bundle.json').read_bytes()==unchanged
            print('PASS: full HTTPS links, default URL save/readback, request-only refresh, persistent fallback, bilingual notices, retry backoff, recovery and temporary override isolation')
            assert all(b'SALKSD-STORE-1:' in p.read_bytes() for p in (data/'sessions').iterdir() if p.is_file())
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
