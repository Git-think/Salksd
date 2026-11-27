#!/usr/bin/env python3
"""Build the two standalone artifacts; encoding is obfuscation, not encryption."""
import argparse
import base64
import gzip
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def source(name):
    text = (ROOT / name).read_text(encoding="utf-8")
    start = text.index("# SALKSD LIBRARY BEGIN")
    end = text.index("# SALKSD LIBRARY END", start) + len("# SALKSD LIBRARY END")
    library = (ROOT / "lib/unbound-secure.sh").read_text(encoding="utf-8")
    for marker, filename in [('STORAGE', 'unbound-storage.sh'), ('RULES', 'unbound-rules.sh'), ('SHARES', 'unbound-shares.sh'), ('BACKUPS', 'unbound-backups.sh')]:
        a = library.index('# SALKSD ' + marker + ' BEGIN')
        b = library.index('# SALKSD ' + marker + ' END', a) + len('# SALKSD ' + marker + ' END')
        library = library[:a] + (ROOT / 'lib' / filename).read_text(encoding='utf-8') + library[b:]
    codec = (ROOT / 'lib/storage-codec.php').read_text(encoding='utf-8').split('\n',1)[1].rstrip()
    a = library.index('# SALKSD CODEC BEGIN')
    b = library.index('# SALKSD CODEC END', a) + len('# SALKSD CODEC END')
    library = library[:a] + "read -r -d '' SALKSD_STORAGE_PHP <<'SALKSD_CODEC' || :\n" + codec + "\nSALKSD_CODEC\n" + library[b:]
    runtime = (ROOT / 'lib/php-runtime.php').read_text(encoding='utf-8').rstrip()
    a = library.index('    # SALKSD PHP RUNTIME BEGIN')
    b = library.index('    # SALKSD PHP RUNTIME END', a) + len('    # SALKSD PHP RUNTIME END')
    library = library[:a] + "    cat <<'SALKSD_PHP_RUNTIME'\n" + runtime + "\nSALKSD_PHP_RUNTIME\n" + library[b:]
    http_start = library.index("    # SALKSD HTTP BEGIN")
    http_end = library.index("    # SALKSD HTTP END", http_start) + len("    # SALKSD HTTP END")
    router = (ROOT / "lib/sub-router.php").read_text(encoding="utf-8").rstrip()
    assert "\nSALKSD_HTTP\n" not in router
    library = library[:http_start] + "    cat <<'SALKSD_HTTP'\n" + router + "\nSALKSD_HTTP\n" + library[http_end:]
    landing_start = library.index("    # SALKSD LANDING BEGIN")
    landing_end = library.index("    # SALKSD LANDING END", landing_start) + len("    # SALKSD LANDING END")
    landing = (ROOT / "lib/public-index.html").read_text(encoding="utf-8").rstrip()
    assert "\nSALKSD_LANDING\n" not in landing
    library = library[:landing_start] + "    cat > \"$landing\" <<'SALKSD_LANDING'\n" + landing + "\nSALKSD_LANDING\n" + library[landing_end:]
    return text[:start] + library + text[end:]


def build(destination):
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("unbound.sh", "unbound_start.sh"):
        encoded = base64.b64encode(gzip.compress(source(name).encode(), mtime=0)).decode()
        encoded = '\n'.join(encoded[i:i+4] for i in range(0,len(encoded),4))
        # eval preserves stdin, $0, BASH_SOURCE and arguments, including the interactive menu.
        wrapper = "#!/bin/bash\n# Generated from reviewed source; do not edit.\n"
        wrapper += "eval \"$(printf '%s' '" + encoded + "' | base64 -d | gzip -dc)\"\n"
        target = destination / name
        target.write_text(wrapper, encoding="utf-8", newline="\n")
        target.chmod(0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    build(parser.parse_args().output)
