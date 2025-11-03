#!/usr/bin/env python3
import os, random, subprocess, tempfile, string

SEED_FILE = "xml2.txt"
TARGET    = "./xml2"

DICT = [
    b"<?xml version='1.0'?>",
    b"<?xml version='1.1'?>",
    b"<!DOCTYPE r [<!ELEMENT r ANY>]>",
    b"<!DOCTYPE r [<!ENTITY a 'AAAA'>]><r>&a;</r>",
    b"<!DOCTYPE r [<!ENTITY a SYSTEM 'http://0.0.0.0/'>]><r>&a;</r>",
    b"<![CDATA[" + b"A"*4096 + b"]]>",
    b"<r " + b"a=" + b"\""+ b"A"*4096 + b"\"" + b"></r>",
    b"<a><b></a>",
    b"&unknown;",
    b"<r>&#xFFFFFFFF;</r>",
    b"<r>&#-1;</r>",
    b"<r>\x00\x01\x02\x03</r>",
]

ASCII = (string.ascii_letters + string.digits + "_-").encode()

def read_seed(p):
    try:  return open(p, "rb").read()
    except: return b"<r>Hello</r>\n"

def long_ascii(lo=256, hi=8192):
    n = random.randint(lo, hi)
    return bytes(random.choice(ASCII) for _ in range(n))

def deep_nesting(depth=None):
    if depth is None: depth = random.randint(16, 256)
    tag = random.choice([b"a", b"node", b"x"])
    pre = (b"<%s>" % tag) * depth
    suf = (b"</%s>" % tag) * depth
    return pre + b"X" + suf

def rand_attr_block():
    k = random.randint(1, 16)
    parts = []
    for _ in range(k):
        name = long_ascii(3, 12)
        val  = long_ascii(1, 4096)
        parts.append(name + b"=\"" + val + b"\"")
    return b" ".join(parts)

def gen_xml_payload():
    choice = random.random()
    if choice < 0.25:
        return deep_nesting()
    elif choice < 0.50:
        return b"<r " + rand_attr_block() + b"></r>"
    elif choice < 0.75:
        return b"<r>" + long_ascii(256, 16384) + b"</r>"
    else:
        return random.choice(DICT)

def inject_dict(b):
    a = bytearray(b)
    for _ in range(random.randint(1, 6)):
        tok = random.choice(DICT)
        pos = random.randrange(0, len(a) + 1)
        a[pos:pos] = tok
    return bytes(a)

def sprinkle_xml_symbols(b):
    a = bytearray(b)
    sym = [b"<", b">", b"&", b"\"", b"'", b"</", b"/>"]
    for _ in range(random.randint(1, 24)):
        s = random.choice(sym)
        pos = random.randrange(0, len(a) + 1)
        a[pos:pos] = s
    return bytes(a)

def flip_bytes(b):
    if not b: return b
    a = bytearray(b)
    n = max(1, len(a)//32)
    for _ in range(random.randint(1, n)):
        i = random.randrange(len(a))
        a[i] = random.randint(0, 255)
    return bytes(a)

def insert_block(b):
    a = bytearray(b)
    blk = os.urandom(random.randint(16, 2048))
    pos = random.randrange(0, len(a)+1)
    return bytes(a[:pos] + blk + a[pos:])

def delete_block(b):
    if len(b) <= 8: return b
    i = random.randrange(0, len(b)-1)
    j = random.randrange(i+1, min(len(b), i+1+random.randint(1, 4096)))
    return b[:i] + b[j:]

MUTS = [flip_bytes, insert_block, delete_block, sprinkle_xml_symbols, inject_dict]

def mutate(seed):
    d = seed
    if random.random() < 0.6:
        d = inject_dict(d)
    for _ in range(random.randint(1, 3)):
        d = random.choice(MUTS)(d)
    return d

def make_payload(seed):
    if random.random() < 0.6:
        return mutate(seed)
    base = gen_xml_payload()
    if random.random() < 0.8:
        base = inject_dict(base)
    return base

def run_once(data, timeout=0.5):
    mode = random.choices(["stdin", "file", "argv"], weights=[5, 3, 1], k=1)[0]
    try:
        if mode == "stdin":
            p = subprocess.run([TARGET], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            return p, False, mode
        elif mode == "file":
            with tempfile.NamedTemporaryFile(prefix="xmlf_", delete=False) as tf:
                tf.write(data); tf.flush(); path = tf.name
            try:
                p = subprocess.run([TARGET, path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            finally:
                try: os.unlink(path)
                except: pass
            return p, False, mode
        else:
            arg = data.replace(b"\x00", b"")[:65535] or b"<r/>"
            p = subprocess.run([TARGET, arg.decode("latin1", "ignore")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            return p, False, mode
    except subprocess.TimeoutExpired as e:
        return e, True, mode

def is_crash(x, timed_out):
    if timed_out: return True
    if hasattr(x, "returncode"):
        rc = x.returncode
        if rc is None or rc < 0: return True
    return False

def out_path():
    name = "bad_xml1.txt"
    return os.path.join("/fuzzer_output", name) if os.path.isdir("/fuzzer_output") else name

def main():
    seed = read_seed(SEED_FILE)
    out  = out_path()
    for i in range(1, 1001):
        data = make_payload(seed)
        r, to, mode = run_once(data)
        if is_crash(r, to):
            os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
            open(out, "wb").write(data)
            print(f"[CRASH] attempt #{i} via {mode} -> {out}")
            return
        if i % 200 == 0:
            print(f"[{i}] attempts...")
    print("[*] No crash within 1000 attempts.")

if __name__ == "__main__":
    main()
