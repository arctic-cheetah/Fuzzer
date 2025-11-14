#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Round-robin fuzzer: strategies 0->1->2->0->1->2...
# 0: single-line (plaintext1)  | fmt-heavy + length edges
# 1: two-line  (plaintext2)    | keep password line, mutate numeric/length/control
# 2: img-mode  (plaintext3)    | "JPG" + W + H + EOL, favor 8x8 to hit SSP
#
# Crash definition: rc < 0 (signal). On crash -> write bad_<target>.txt and exit.
# Usage: python3 rr_plaintext.py ./plaintextX seed.txt

import os, sys, re, random, subprocess, string

# ---------- Config ----------
TARGET     = sys.argv[1] if len(sys.argv) > 1 else "./plaintext3"
SEED_FILE  = sys.argv[2] if len(sys.argv) > 2 else "plaintext3.txt"
TIMEOUT    = float(os.getenv("TIMEOUT", "0.6"))
ATTEMPTS   = int(os.getenv("ATTEMPTS", "5000"))  # 总尝试次数；按 0/1/2 轮询

ASCII = (string.ascii_letters + string.digits + "_- ").encode()
LEN_EDGES = [63,64,65,127,128,129,255,256,257,511,512,513,1023,1024,1025]

# ---------- fmt dictionary (kept intact) ----------
FMT_DICT = [
    b"%n", b"%hn", b"%hhn", b"%ln", b"%lln",
    b"%p%p%p%p", b"%x%x%x%x", b"%08x%08x%08x", b"%s%s%s%s",
    b"%*s", b"%.10240s", b"%99999999s", b"%d%d%d%d",
    b"%#n", b"%hhn%n", b"%s%n"
]

# ---------- IO utils ----------
def read_seed_lines(p):
    try:
        raw = open(p, "rb").read()
    except:
        raw = b"trivial\n2\n"  # fallback for two-line
    parts = raw.split(b"\n")
    first = parts[0] if parts else b""
    rest  = parts[1:] if len(parts) > 1 else []
    return first, rest

def run_once(data: bytes):
    try:
        p = subprocess.run([TARGET], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT)
        return p, False
    except subprocess.TimeoutExpired as e:
        return e, True

def is_crash(x, to):
    if to: return False
    if hasattr(x, "returncode") and x.returncode is not None:
        return x.returncode < 0
    return False

def out_path():
    name = f"bad_{os.path.basename(TARGET)}.txt"
    return os.path.join("/fuzzer_output", name) if os.path.isdir("/fuzzer_output") else name

# ---------- common mutators ----------
def long_ascii(lo=64, hi=(1<<20)):
    n = random.randint(lo, hi)
    return bytes(random.choice(ASCII) for _ in range(n))

def inject_fmt(b: bytes, kmin=1, kmax=8) -> bytes:
    a = bytearray(b)
    for _ in range(random.randint(kmin, kmax)):
        t = random.choice(FMT_DICT)
        pos = random.randrange(0, len(a)+1)
        a[pos:pos] = t
    return bytes(a)

def encoding_noise_block():
    return random.choice([
        b"\x00"*random.randint(1, 8192),          # NUL
        b"\xEF\xBB\xBF"*random.randint(1, 4096),  # BOM
        b"\xC0\xAF"*random.randint(1, 4096),      # illegal UTF-8
        b"\xF5\x80\x80\x80"*random.randint(1,1024)# overlong UTF-8
    ])

# ---------- Strategy 0: single-line (plaintext1) ----------
def payload_single_line():
    base = random.choice([
        long_ascii(32, 4096),
        b"A"*random.choice(LEN_EDGES),
        b""  # pure fmt allowed
    ])
    if random.random() < 0.8:
        base = inject_fmt(base, 4, 24)
    if random.random() < 0.5:
        pos = min(len(base), random.choice([64,128,256,512,1024]))
        base = base[:pos] + encoding_noise_block() + base[pos:]
    return base.rstrip(b"\n") + b"\n"

# ---------- Strategy 1: two-line (plaintext2) ----------
def id_neg_edges():
    return random.choice([
        b"-1", b"-2", b"-3", b" -1", b"\t-1", b"+-1",
        b"-2147483648", b"-9223372036854775808"
    ])

def id_pos_edges():
    return random.choice([
        b"2147483647", b"2147483648", b"4294967295",
        b"9223372036854775807", b"18446744073709551615",
        b"0x7fffffff", b"0xffffffff", b"9"*10240
    ])

def id_len_edges():
    n = random.choice(LEN_EDGES + [4095,4096,4097])
    return b"9"*n

def id_nonnumeric_or_fmt():
    return random.choice([
        b"NaN", b"inf", b"--", b"+", b"e10", b"1e309",
        long_ascii(1,1024), inject_fmt(b"", 2, 12)
    ])

def id_with_ctrl():
    base = random.choice([b"0", b"1", b"2", b"3", b"-1"])
    noise = random.choice([encoding_noise_block(), inject_fmt(b"", 2, 12)])
    return (noise + base) if random.random() < 0.5 else (base + noise)

def id_fmt_heavy():
    base = random.choice([id_pos_edges(), id_neg_edges(), long_ascii(32, 4096), b""])
    return inject_fmt(base, 4, 24)

def second_line_payload():
    gen = random.choice([id_pos_edges, id_neg_edges, id_len_edges, id_nonnumeric_or_fmt, id_with_ctrl, id_fmt_heavy])
    return gen().rstrip(b"\n") + b"\n"

def tail_lines():
    tails = []
    if random.random() < 0.5:
        tails.append(b"A"*random.choice([32,64,128,256]))
        tails.append(inject_fmt(b"B"*random.choice([200000, 600000, 1200000]), 1, 10))
        tails.append(b"")
        tails.append(inject_fmt(b"C"*random.choice([500000, 1500000]), 1, 10))
    else:
        tails.append(inject_fmt(encoding_noise_block(), 4, 24))
    return b"".join(t + b"\n" for t in tails)

def payload_two_line(password: bytes):
    pwd = (password or b"trivial").rstrip(b"\n")
    data = pwd + b"\n" + second_line_payload()
    if random.random() < 0.5:
        data += tail_lines()
    return data

# ---------- Strategy 2: img-mode (plaintext3) ----------
def payload_img_header():
    # 0.7: (8,8)  | 0.2: (0xF8,0xF8) | 0.1: explore
    r = random.random()
    if r < 0.7:
        w, h = 0x08, 0x08
    elif r < 0.9:
        w, h = 0xF8, 0xF8
    else:
        candidates = [(6,7),(7,6),(16,20),(20,16),(12,12),(1,200),(200,1),(32,10),(10,32)]
        w, h = random.choice(candidates) if random.random() < 0.5 else (random.randint(0,255), random.randint(0,255))
    eol = b"\n" if random.random() < 0.5 else b"\r"
    buf = b"JPG" + bytes([w & 0xFF, h & 0xFF]) + eol
    if random.random() < 0.2:  # optional payload
        plen = (w & 0xFF) * (h & 0xFF) * 10
        buf += b"A" * min(plen, 2_000_000)
    return buf

# ---------- Main (round-robin 0/1/2) ----------
def main():
    first, _ = read_seed_lines(SEED_FILE)
    out = out_path()

    for i in range(1, ATTEMPTS + 1):
        which = (i - 1) % 3  # 0,1,2,0,1,2...
        if which == 0:
            data = payload_single_line()
        elif which == 1:
            data = payload_two_line(first)
        else:
            data = payload_img_header()

        r, to = run_once(data)
        if is_crash(r, to):
            rc = getattr(r, "returncode", None)
            os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
            with open(out, "wb") as f:
                f.write(data)
            print(f"[CRASH] idx={which} attempt={i} -> {out} | rc={rc}")
            return

        if i % 200 == 0:
            last_rc = getattr(r, "returncode", None) if not to else "TIMEOUT"
            print(f"[{i}/{ATTEMPTS}] last_rc={last_rc} next_idx={(i)%3}")

    print("[*] No crash within %d attempts." % ATTEMPTS)

if __name__ == "__main__":
    main()
