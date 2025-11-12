#!/usr/bin/env python3
import os, random, subprocess, tempfile, string, re

SEED_FILE = "xml2.txt"
TARGET    = "./xml2"

DICT = [
    b"<?xml version='1.0'?>",
    b"<?xml version='1.1'?>",
    b"<!DOCTYPE r [<!ELEMENT r ANY>]>",
    b"<!DOCTYPE r [<!ENTITY a 'AAAA'>]><r>&a;</r>",
    b"<!DOCTYPE r [<!ENTITY a SYSTEM 'http://0.0.0.0/'>]><r>&a;</r>",
    b"<![CDATA[" + b"A"*4096 + b"]]>",
    b"<r " + b"a=" + b"\"" + b"A"*4096 + b"\"" + b"></r>",
    b"<a><b></a>",
    b"&unknown;",
    b"<r>&#xFFFFFFFF;</r>",
    b"<r>&#-1;</r>",
    b"<r>\x00\x01\x02\x03</r>",
    b'<a href="',
    b'</a>'
]

ASCII = (string.ascii_letters + string.digits + "_-").encode()

def read_seed(p):
    try:
        return open(p, "rb").read()
    except:
        return b"<r>Hello</r>\n"

def b_insert(b, payload):
    pos = random.randint(0, len(b))
    return b[:pos] + payload + b[pos:]

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

# ====== Advanced / structure-aware mutations ======

def m_fmt_spray(b):
    toks = [b"%n", b"%p", b"%x", b"%s"]
    spray = b"".join(random.choices(toks, k=random.randint(4, 40)))
    # 优先替换/强化 href 属性值
    return b.replace(b'href="', b'href="' + spray)

def m_toggle_quote_style(b):
    if not b: return b
    a = bytearray(b)
    choices = [ord(b'"'), ord(b"'")]
    flips = random.randint(1, max(1, len(a)//256))
    idxs_dq = [i for i, ch in enumerate(a) if ch == ord(b'"')]
    idxs_sq = [i for i, ch in enumerate(a) if ch == ord(b"'")]
    for _ in range(flips):
        which = random.choice([0,1])
        idxs = idxs_dq if which==0 else idxs_sq
        if not idxs: break
        i = random.choice(idxs)
        a[i] = ord(b"'") if which==0 else ord(b'"')
    return bytes(a)

def m_duplicate_attrs(b):
    m = list(re.finditer(br"\s+[A-Za-z0-9_\-:]+=\"[^\"]*\"", b))
    if not m: return b
    s,e = random.choice(m).span()
    return b[:e] + b[s:e] + b[e:]

def m_break_attr_eq(b):
    a = bytearray(b)
    eq_positions = [i for i, ch in enumerate(a) if ch == ord("=")]
    if not eq_positions: return b
    for _ in range(random.randint(1, min(4, len(eq_positions)))):
        i = random.choice(eq_positions)
        repl = random.choice([b"", b" = ", b"==", b" =", b"= ", b" = = "])
        a[i:i+1] = repl
    return bytes(a)

def m_insert_xml_decl_variant(b):
    versions = [b"1.0", b"1.1"]
    encs = [b"UTF-8", b"UTF-16", b"ISO-8859-1", b"US-ASCII"]
    stand = [b"yes", b"no"]
    decl = (b"<?xml version=\"" + random.choice(versions) +
            b"\" encoding=\"" + random.choice(encs) +
            b"\" standalone=\"" + random.choice(stand) + b"\"?>\n")
    return decl + b

def m_namespace_noise(b):
    attrs = [
        b' xmlns="http://example.com/%d"' % random.randint(0, 1_000_000),
        b' xmlns:x="http://ns.example.org/%d"' % random.randint(0, 1_000_000),
        b' xmlns:y="urn:uuid:%032x"' % random.getrandbits(128),
    ]
    insert = b"".join(random.sample(attrs, k=random.randint(1, len(attrs))))
    m = re.search(br"<[^/!?][^>]*", b)
    if not m: return b + insert
    pos = m.end()
    return b[:pos] + insert + b[pos:]

def m_processing_instruction(b):
    targets = [b"xml-stylesheet", b"proc", b"p", b"a"*random.randint(1,8)]
    data = [b'type="text/xsl" href="file.xsl"', b"dbg=1", b"", b"mode=test"]
    pi = b"<?" + random.choice(targets) + b" " + random.choice(data) + b"?>"
    pos = random.randrange(0, len(b)+1)
    return b[:pos] + pi + b[pos:]

def m_comment_storm(b):
    parts, n = [], random.randint(1,8)
    for _ in range(n):
        body = long_ascii(0, random.randint(0,64))
        end  = random.choice([b"-->", b"---->", b"-->-", b">"])
        parts.append(b"<!--" + body + end)
    burst = b"".join(parts)
    pos = random.randrange(0, len(b)+1)
    return b[:pos] + burst + b[pos:]

def m_bom_insertion(b):
    boms = [b"\xEF\xBB\xBF", b"\xFF\xFE", b"\xFE\xFF"]
    pos = random.randrange(0, len(b)+1)
    return b[:pos] + random.choice(boms) + b[pos:]

def m_invalid_utf8(b):
    bad = random.choice([b"\xC0\xAF", b"\xC1\xBF", b"\xF5\x80\x80\x80"])
    return b_insert(b, bad)

def m_surrogate_entities(b):
    samples = [b"&#xD800;", b"&#xDFFF;", b"&#0;", b"&#x10FFFF;", b"&#x110000;"]
    tok = b"".join(random.choices(samples, k=random.randint(1, 6)))
    return b_insert(b, tok)

def m_entity_nesting_bomb(b):
    depth = random.randint(2,5)
    parts = [b"<!DOCTYPE r ["]
    for i in range(depth):
        parts.append(b"<!ENTITY e%d '%s'>" % (i, b"A"*random.randint(64,256)))
    chain = b"".join([b"&e%d;" % i for i in range(depth)])
    parts.append(b"]><r>" + chain + b"</r>")
    dtd = b"".join(parts)
    return b_insert(b, dtd)

def m_cdata_edgecases(b):
    variants = [
        b"<![CDATA[]]>",
        b"<![CDATA[ ]]>",
        b"<![CDATA[" + b"A"*random.randint(0,8192) + b"]]>",
        b"<![CDATA[ ]]>>",
        b"]]>]]>",
    ]
    return b_insert(b, random.choice(variants))

def m_rename_tags(b):
    # Replace some tag names with random identifiers
    def repl(m):
        slash = m.group(1)  # b'' or b'/'
        name  = m.group(2)
        new = random.choice([b"x", b"node", b"tag"]) + \
              bytes(random.choice(ASCII) for _ in range(random.randint(0,6)))
        return b"<" + slash + new
    return re.sub(br"<(/?)([A-Za-z_:][\w:.\-]*)", repl, b, count=random.randint(1,5))

def m_drop_closing_tags(b):
    pattern = re.compile(br"</[^>]+>")
    matches = list(pattern.finditer(b))
    if not matches: return b
    k = random.randint(1, min(3, len(matches)))
    drop = set(random.sample(matches, k))
    a, last = bytearray(), 0
    for m in matches:
        if m in drop:
            a.extend(b[last:m.start()])
            last = m.end()
    a.extend(b[last:])
    return bytes(a) if a else b

def m_whitespace_noise(b):
    ws = [b"\r", b"\t", b"\v", b"\f", b" " * random.randint(1, 8)]
    a = bytearray(b)
    for _ in range(random.randint(1,16)):
        pos = random.randrange(0, len(a)+1)
        a[pos:pos] = random.choice(ws)
    return bytes(a)

def m_crossover_with_generated(b):
    other = gen_xml_payload()
    pos = random.randrange(0, len(b)+1)
    return b[:pos] + other + b[pos:]

def m_long_number_attrs(b):
    pattern = re.compile(br"=\"[^\"]*\"")
    matches = list(pattern.finditer(b))
    if not matches: return b
    a = bytearray(b)
    for m in random.sample(matches, k=random.randint(1, min(3, len(matches)))):
        start, end = m.span()
        num = b"9" * random.randint(64, 8192)
        a[start:end] = b"=\"" + num + b"\""
    return bytes(a)

def m_ampersand_noise(b):
    toks = [b"&", b"&#", b"&x", b"&#x", b"&;", b"&#;"]
    payload = b"".join(random.choices(toks, k=random.randint(1, 50)))
    return b_insert(b, payload)

MUTS = [
    # basic
    flip_bytes, insert_block, delete_block, sprinkle_xml_symbols, inject_dict,
    # advanced
    m_toggle_quote_style, m_duplicate_attrs, m_break_attr_eq,
    m_insert_xml_decl_variant, m_namespace_noise, m_processing_instruction,
    m_comment_storm, m_bom_insertion, m_invalid_utf8, m_surrogate_entities,
    m_entity_nesting_bomb, m_cdata_edgecases, m_rename_tags,
    m_drop_closing_tags, m_whitespace_noise, m_crossover_with_generated,
    m_long_number_attrs, m_ampersand_noise, m_fmt_spray
]

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

# ==== 仅 stdin 投喂 ====
def run_once(data, timeout=0.5):
    try:
        p = subprocess.run(
            [TARGET],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout
        )
        return p, False, "stdin"
    except subprocess.TimeoutExpired as e:
        return e, True, "stdin"

# ==== 崩溃判定：仅 rc < 0 ====
def is_crash(x, timed_out):
    if hasattr(x, "returncode"):
        rc = x.returncode
        return (rc is not None) and (rc < 0)
    return False

def out_path():
    name = "bad_xml1.txt"  # 如需与 TARGET 对齐可改为 bad_xml3.txt
    return os.path.join("/fuzzer_output", name) if os.path.isdir("/fuzzer_output") else name

def main():
    seed = read_seed(SEED_FILE)
    out  = out_path()
    for i in range(1, 1001):
        data = make_payload(seed)
        r, to, mode = run_once(data)
        if is_crash(r, to):
            rc = getattr(r, "returncode", None)
            os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
            open(out, "wb").write(data)
            print(f"[CRASH] attempt #{i} via {mode} -> {out} | rc={rc}")
            return
        if i % 200 == 0:
            print(f"[{i}] attempts...")
    print("[*] No crash within 1000 attempts.")

if __name__ == "__main__":
    main()
