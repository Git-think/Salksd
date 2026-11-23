import base64
import gzip
import importlib.util
import re
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build", root / "tools/build_obfuscated.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for name in ("unbound.sh", "unbound_start.sh"):
    wrapper = (root / "dist" / name).read_text(encoding="utf-8")
    payload = re.search(r"printf '%s' '([^']+)'", wrapper).group(1)
    assert gzip.decompress(base64.b64decode(payload)).decode() == module.source(name)
    assert '| bash -s' not in wrapper  # Would consume menu input and lose the worker's path.
print('PASS: both obfuscated artifacts decode exactly to the reviewed standalone source')
