"""Enforce the operator's unchanged-behaviour requirements against the exact base."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = '19229fbc64ec744a8f24d9d9b3ad2adef6f6f375'

for file, start, end in [
    ('unbound.sh', 'reset_system() {', '\ndownload_unbound() {'),
    ('unbound.sh', 'add_ssl_cert() {', '\ngenerate_sub_link'),
    ('unbound.sh', 'check_port () {', '\ncheck_website() {'),
    ('unbound_start.sh', 'check_ssl_cert() {', '\n# --- Ensure Required Ports'),
    ('unbound_start.sh', 'ensure_required_ports() {', '\n# --- Main Loop ---'),
]:
    before = subprocess.check_output(['git','show',BASE+':'+file],cwd=ROOT).decode()
    after = (ROOT/file).read_text(encoding='utf-8')
    expected = before[before.index(start):before.index(end,before.index(start))].strip()
    actual = after[after.index(start):after.index(end,after.index(start))].strip()
    assert actual == expected, file+': baseline behaviour changed: '+start

main = (ROOT/'unbound.sh').read_text(encoding='utf-8')
library = (ROOT/'lib/unbound-secure.sh').read_text(encoding='utf-8')
assert 'NEW_FILENAME="$DOWNLOAD_DIR/unbound"' in main
assert 'rm -rf "$(basename ${FILE_MAP[web]})" unbound.conf sb.log core fake_useragent_0.2.0.json private.key cert.pem' in main
assert 'rm -rf unbound "$CONFIG_FILE" private.key cert.pem sb.log core fake_useragent_0.2.0.json' in library
worker = (ROOT/'unbound_start.sh').read_text(encoding='utf-8')
assert 'curl -fL -sS --max-time 10' in worker
assert 'AUTO_LINK="https://api.${USERNAME}.${CURRENT_DOMAIN}/${SUB_TOKEN}"' in main
assert 'RewriteRule ^sub/' not in library
for file in subprocess.check_output(['git','ls-tree','--name-only',BASE],cwd=ROOT,text=True).splitlines():
    if file.endswith('.sh') and file not in ('unbound.sh','unbound_start.sh'):
        before = subprocess.check_output(['git','show',BASE+':'+file],cwd=ROOT)
        assert before.replace(b'\r\n',b'\n') == (ROOT/file).read_bytes().replace(b'\r\n',b'\n'), file
print('PASS: baseline reset, platform ports, HTTPS certificate issuance/renewal, executable name and cleanup preserved')
