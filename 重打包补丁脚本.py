# -*- coding: utf-8 -*-
"""AITEST8.0 破解重打包 v2
1) PYZ 内 subscription 模块字节码补丁（冗余保险）
2) runtime/subscription.py  源码补丁（真正的生效点：launcher 把 <MEIPASS>/runtime 插到 sys.path[0]）
3) runtime/integrity_check.py 置空（否则 runtime 改动会被 Ed25519 清单校验拦下）
"""
import struct, zlib, marshal, sys, os, hashlib

SRC = sys.argv[1]
OUT = sys.argv[2]

COOKIE_MAGIC = b'MEI\014\013\012\013\016'
COOKIE_FMT = '!8sIIII64s'
COOKIE_LEN = struct.calcsize(COOKIE_FMT)
TOC_FMT = '!IIIIBc'
TOC_LEN = struct.calcsize(TOC_FMT)
PYZ_HDR = 17
BS = chr(92)

data = open(SRC, 'rb').read()
ci = data.rfind(COOKIE_MAGIC)
assert ci > 0
magic, arch_len, toc_off, toc_len, pymagic_vers, pylib = struct.unpack(COOKIE_FMT, data[ci:ci+COOKIE_LEN])
end = ci + COOKIE_LEN
start = end - arch_len
body = data[:start]
archive = data[start:end]
print("[+] loader=%d archive=%d pyvers=%d" % (start, arch_len, pymagic_vers))

entries = []
pos = toc_off
while pos < toc_off + toc_len:
    el, off, dl, ul, cf, tc = struct.unpack(TOC_FMT, archive[pos:pos+TOC_LEN])
    pos += TOC_LEN
    nl = el - TOC_LEN
    name = archive[pos:pos+nl].rstrip(b'\0').decode('utf-8')
    pos += nl
    entries.append([name, off, dl, ul, cf, tc.decode('ascii')])
print("[+] CArchive entries=%d" % len(entries))

def get_blob(name):
    for n, off, dl, ul, cf, tc in entries:
        if n == name:
            b = archive[off:off+dl]
            return (zlib.decompress(b) if cf else b), cf
    raise KeyError(name)

# ---------- 1) runtime/subscription.py 源码补丁 ----------
orig_sub, sub_cf = get_blob('runtime' + BS + 'subscription.py')
PATCH = '''

# ================= local patch =================
def status(*args, **kwargs):
    return {'repair_hash': '', 'risk_suspended': False, 'cleanup_remaining': 0, 'lease_cleared': False,
            'authorized': True, 'activated': True, 'expired': False, 'revoked': False,
            'days_remaining': None, 'expires_at': 0, 'mode': 'lifetime', 'remaining_seconds': 0,
            'message': '\u672c\u673a\u6388\u6743\uff1a\u6c38\u4e45', 'redeem_status': 'activated'}

def activate(code=None, *args, **kwargs):
    return True, '\u6fc0\u6d3b\u6210\u529f\uff08\u6c38\u4e45\u6388\u6743\uff09'

def check_token(code=None, *args, **kwargs):
    return {'app': 'aitest-8', 'v': 3, 'device': '', 'plan': '360d'}

def refresh(*args, **kwargs):
    return True

def start_background(*args, **kwargs):
    return None

def current_code(*args, **kwargs):
    return ''
'''
new_sub = orig_sub.decode('utf-8') + PATCH
new_sub_b = new_sub.encode('utf-8')
print("[+] runtime/subscription.py: %d -> %d bytes" % (len(orig_sub), len(new_sub_b)))

# ---------- 2) runtime/integrity_check.py 置空 ----------
orig_ic, ic_cf = get_blob('runtime' + BS + 'integrity_check.py')
new_ic_b = b"def verify(root, key):\n    return True\n"
print("[+] runtime/integrity_check.py: %d -> %d bytes" % (len(orig_ic), len(new_ic_b)))

# ---------- 3) PYZ 内 subscription 字节码补丁（保险） ----------
def patch_pyz(blob):
    assert blob[:4] == b'PYZ\0'
    pm = blob[4:8]
    t = struct.unpack('!i', blob[8:12])[0]
    toc = marshal.loads(blob[t:])
    order = list(toc)
    blobs = {n: zlib.decompress(blob[o:o+l]) for n, (ty, o, l) in toc}
    mod = marshal.loads(blobs['subscription'])
    REPL = {
        'status': ("def status(*a, **k):\n    return {'authorized': True, 'activated': True, 'expired': False, 'revoked': False,"
                   " 'days_remaining': None, 'expires_at': 0, 'mode': 'lifetime', 'remaining_seconds': 0,"
                   " 'message': 'patched', 'redeem_status': 'activated', 'risk_suspended': False,"
                   " 'cleanup_remaining': 0, 'lease_cleared': False, 'repair_hash': ''}\n"),
        'refresh': "def refresh(*a, **k):\n    return True\n",
        'start_background': "def start_background(*a, **k):\n    return None\n",
        'activate': "def activate(*a, **k):\n    return (True, 'patched')\n",
        'check_token': "def check_token(*a, **k):\n    return {'app': 'aitest-8', 'v': 3, 'plan': '360d'}\n",
    }
    consts = list(mod.co_consts)
    done = []
    for i, c in enumerate(consts):
        if hasattr(c, 'co_code') and c.co_name in REPL and c.co_argcount in (0, 1):
            tmp = compile(REPL[c.co_name], 'subscription.py', 'exec')
            newco = next(x for x in tmp.co_consts if hasattr(x, 'co_code') and x.co_name == c.co_name)
            consts[i] = newco
            done.append(c.co_name)
    mod = mod.replace(co_consts=tuple(consts))
    blobs['subscription'] = marshal.dumps(mod)
    out = bytearray(b'\0' * PYZ_HDR)
    nt = []
    for n, (ty, o, l) in order:
        c = zlib.compress(blobs[n], 6)
        nt.append((n, (ty, len(out), len(c))))
        out += c
    toff = len(out)
    out += marshal.dumps(nt)
    struct.pack_into('!4s4si', out, 0, b'PYZ\0', pm, toff)
    return bytes(out), done

# ---------- 重建 CArchive ----------
new_archive = bytearray()
new_toc = []
STATS = {'pyz': None, 'rt_sub': 0, 'rt_ic': 0}
for name, off, dl, ul, cf, tc in entries:
    blob = archive[off:off+dl]
    if tc == 'z':
        raw = zlib.decompress(blob) if cf else blob
        new_raw, done = patch_pyz(raw)
        print("[+] PYZ patched funcs:", done)
        nb = zlib.compress(new_raw, 9) if cf else new_raw
        new_toc.append((name, len(new_archive), len(nb), len(new_raw), cf, tc))
        new_archive += nb
        STATS['pyz'] = (len(raw), len(new_raw))
    elif name == 'runtime' + BS + 'subscription.py':
        nb = zlib.compress(new_sub_b, 9) if cf else new_sub_b
        new_toc.append((name, len(new_archive), len(nb), len(new_sub_b), cf, tc))
        new_archive += nb
        STATS['rt_sub'] = 1
    elif name == 'runtime' + BS + 'integrity_check.py':
        nb = zlib.compress(new_ic_b, 9) if cf else new_ic_b
        new_toc.append((name, len(new_archive), len(nb), len(new_ic_b), cf, tc))
        new_archive += nb
        STATS['rt_ic'] = 1
    else:
        new_toc.append((name, len(new_archive), dl, ul, cf, tc))
        new_archive += blob

assert STATS['rt_sub'] and STATS['rt_ic'], "runtime patch target missing"

toff = len(new_archive)
toc_bytes = bytearray()
for name, off, cl, ul, cf, tc in new_toc:
    nb = name.encode('utf-8'); nl = len(nb) + 1
    el = TOC_LEN + nl
    if el % 16: nl += 16 - (el % 16)
    toc_bytes += struct.pack(TOC_FMT + '%ds' % nl, TOC_LEN + nl, off, cl, ul, cf, tc.encode('ascii'), nb)
tlen = len(toc_bytes)
new_archive += toc_bytes
arch_len2 = toff + tlen + COOKIE_LEN
cookie = struct.pack(COOKIE_FMT, COOKIE_MAGIC, arch_len2, toff, tlen, pymagic_vers, pylib)
out = body + bytes(new_archive) + cookie
open(OUT, 'wb').write(out)
print("[+] PYZ size %d -> %d" % STATS['pyz'])
print("[+] wrote %s (%d bytes)" % (OUT, len(out)))
print("[+] sha256", hashlib.sha256(out).hexdigest())
