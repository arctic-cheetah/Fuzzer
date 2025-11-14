# xml_fuzzer.py
"""
XML-focused mutational fuzzer (payload generation only).

This module builds structured and mutated XML payloads to stress parsers.
It DOES NOT execute the target or handle timeouts/crash detection — the caller
(e.g., Fuzzer.run_binary) is responsible for invoking the binary via stdin.

Key design:
- First payload is a pure 193-depth nested document to hit "depth > 192" BOF.
- High-weight pure structured samples (deep/wide) without destructive injection.
- Seed-based mutations (dictionary/symbols/blocks/flip) explore other surfaces.
"""
import random
import string
from typing import List, Callable, Optional

from fuzzer_core import Fuzzer, b_insert, random_bytes

# --------------------------------------------------------------------
# Classic tokens to stress XML parsers (DTD/entities/CDATA/malformed).
# NOTE: These are used in mutation phase; pure-structure samples avoid them.
# --------------------------------------------------------------------
DICT: List[bytes] = [
    b"<?xml version='1.0'?>",
    b"<?xml version='1.1'?>",
    b"<!DOCTYPE r [<!ELEMENT r ANY>]>",                          # DTD baseline
    b"<!DOCTYPE r [<!ENTITY a 'AAAA'>]><r>&a;</r>",              # internal entity
    b"<!DOCTYPE r [<!ENTITY a SYSTEM 'http://0.0.0.0/'>]><r>&a;</r>",  # XXE probe
    b"<![CDATA[" + b"A" * 4096 + b"]]>",
    b"<r " + b"a=" + b"\"" + b"A" * 4096 + b"\"" + b"></r>",
    b"<a><b></a>",                      # tag mismatch
    b"&unknown;",                        # undefined entity
    b"<r>&#xFFFFFFFF;</r>",             # oversized char ref
    b"<r>&#-1;</r>",                    # negative char ref
    b"<r>\x00\x01\x02\x03</r>",         # control bytes
    b'<a href="',                       # for fmt spray
    b"</a>",
]

ASCII = (string.ascii_letters + string.digits + "_-").encode()

# --------------------------------------------------------------------
# Helpers: printable runs, attribute blocks, deep/wide structured docs
# --------------------------------------------------------------------
def long_ascii(lo: int = 256, hi: int = 8192) -> bytes:
    n = random.randint(lo, hi)
    return bytes(random.choice(ASCII) for _ in range(n))

def rand_attr_block() -> bytes:
    k = random.randint(1, 16)
    parts: List[bytes] = []
    for _ in range(k):
        name = long_ascii(3, 12)
        val  = long_ascii(1, 4096)
        parts.append(name + b"=\"" + val + b"\"")
    return b" ".join(parts)

def deep_doc(depth: int = 193, tag: bytes = b"a") -> bytes:
    """Pure, legal, single-root deep nesting: <a>…</a> repeated 'depth' times."""
    pre = (b"<%s>" % tag) * depth
    suf = (b"</%s>" % tag) * depth
    return pre + b"X" + suf

def wide_doc(n: int = 200, tag: bytes = b"a") -> bytes:
    """Pure, legal, single-root wide fan-out: <r><a/>...<a/></r> with n siblings."""
    body = b"".join(b"<%s/>" % tag for _ in range(n))
    return b"<r>" + body + b"</r>"

# --------------------------------------------------------------------
# Structured generators (NO injection for deep/wide to keep them valid)
# --------------------------------------------------------------------
def gen_xml_payload() -> bytes:
    r = random.random()
    # 60%: pure deep nesting around the 192–193 threshold band
    if r < 0.60:
        return deep_doc(random.randint(188, 210), tag=random.choice([b"a", b"x"]))
    # 20%: pure wide fan-out (covers global-node-array implementations)
    elif r < 0.80:
        return wide_doc(random.randint(193, 240), tag=random.choice([b"a", b"x"]))
    # 10%: large attributes on a single element
    elif r < 0.90:
        return b"<r " + rand_attr_block() + b"></r>"
    # 9%: long PCDATA in a simple container
    elif r < 0.99:
        return b"<r>" + long_ascii(256, 16384) + b"</r>"
    # 1%: dictionary token sample
    else:
        return random.choice(DICT)

# --------------------------------------------------------------------
# Mutation operators (used only in seed-based exploration path)
# --------------------------------------------------------------------
def sprinkle_xml_symbols(b: bytes) -> bytes:
    a = bytearray(b)
    # include short fragments; caller must NOT use this on pure deep/wide
    sym = [b"<", b">", b"&", b"\"", b"'", b"</", b"/>"]
    for _ in range(random.randint(1, 24)):
        s = random.choice(sym)
        pos = random.randrange(0, len(a) + 1)
        a[pos:pos] = s
    return bytes(a)

def flip_bytes(b: bytes) -> bytes:
    if not b:
        return b
    a = bytearray(b)
    n = max(1, len(a) // 32)
    for _ in range(random.randint(1, n)):
        i = random.randrange(len(a))
        a[i] = random.randint(0, 255)
    return bytes(a)

def insert_block(b: bytes) -> bytes:
    blk = random_bytes(random.randint(16, 2048))
    return b_insert(b, blk)

def delete_block(b: bytes) -> bytes:
    if len(b) <= 8:
        return b
    i = random.randrange(0, len(b) - 1)
    j = random.randrange(i + 1, min(len(b), i + 1 + random.randint(1, 4096)))
    return b[:i] + b[j:]

def inject_dict(b: bytes) -> bytes:
    a = bytearray(b)
    for _ in range(random.randint(1, 6)):
        tok = random.choice(DICT)
        pos = random.randrange(0, len(a) + 1)
        a[pos:pos] = tok
    return bytes(a)

def m_fmt_spray(b: bytes) -> bytes:
    """Format-string spray into href attribute (seed exploration only)."""
    toks = [b"%n", b"%p", b"%x", b"%s"]
    spray = b"".join(random.choices(toks, k=random.randint(4, 40)))
    return b.replace(b'href="', b'href="' + spray)

# --------------------------------------------------------------------
# Fuzzer class: first send pure 193-depth, then round of structured/mutation
# --------------------------------------------------------------------
class XML_Mutational_Fuzzer(Fuzzer):
    """
    Strategy:
    - First payload: deep_doc(193) — pure, legal, single-root deep nesting.
    - Afterwards:
        * 70%: structured gen (mostly deep/wide) with NO injection or corruption.
        * 30%: seed-based mutation path (DICT/symbols/flip/blocks) for breadth.
    """

    def __init__(self, path_to_input: str, binary_path: str):
        super().__init__(path_to_input, binary_path)
        self.mutators: List[Callable[[bytes], bytes]] = [
            flip_bytes,
            insert_block,
            delete_block,
            sprinkle_xml_symbols,
            inject_dict,
            m_fmt_spray,
        ]
        self._primed: bool = False  # ensure first packet is pure 193-depth

    # Seed-exploration mutations (destructive allowed here by design)
    def mutate(self, seed: bytes) -> bytes:
        d = seed
        if random.random() < 0.6:
            d = inject_dict(d)
        for _ in range(random.randint(1, 3)):
            d = random.choice(self.mutators)(d)
        return d

    # Main generator used by the scheduler (run_binary calls self.make_payload)
    def make_payload(self, seed: bytes) -> bytes:
        # 1) Prime with a guaranteed pure 193-depth nested document
        if not self._primed:
            self._primed = True
            return deep_doc(193, tag=b"a")

        # 2) Prefer structured pure samples (deep/wide/no injection)
        if random.random() < 0.7:
            return gen_xml_payload()

        # 3) Else explore mutations starting from seed (destructive OK)
        return self.mutate(seed)

    # Optional convenience alias
    def next_payload(self, seed: bytes) -> bytes:
        return self.make_payload(seed)
