"""Independent test-side reader; production keeps its shell/PHP implementations."""
import base64
import hashlib
from pathlib import Path

TABLE = bytes.maketrans(b'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234_-',
                       b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')

def read(path):
    data=Path(path).read_bytes()
    if data.startswith(b'SALKSD-STORE-'):
        header, payload=data.split(b'\n',1)
        assert header.startswith(b'SALKSD-STORE-1:')
        data=base64.b64decode(payload.translate(TABLE))
        assert hashlib.sha256(data).hexdigest().encode()==header.split(b':',1)[1]
    return data.decode('utf-8')

def write(path, text):
    data=text.encode('utf-8')
    reverse=bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
                          b'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234_-')
    encoded=base64.b64encode(data).translate(reverse)
    Path(path).write_bytes(b'SALKSD-STORE-1:'+hashlib.sha256(data).hexdigest().encode()+b'\n'+b''.join(encoded[i:i+4]+b'\n' for i in range(0,len(encoded),4)))
