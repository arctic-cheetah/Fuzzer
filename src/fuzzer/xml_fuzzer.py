# xml_fuzzer.py
"""
XML-focused mutational fuzzer (payload generation only).

This module defines dictionary tokens, structural generators, and mutation
operators tailored for XML. It **does not** execute target binaries or perform
any I/O. Execution, timeouts, and crash detection are handled by the caller.
"""
import random
import string
from typing import List, Callable

from fuzzer_core import Fuzzer, b_insert, random_bytes

# Classic tokens to stress XML parsers (DTD/entities/CDATA/malformed tags/etc.).
DICT: List[bytes] = [
    b"<?xml version='1.0'?>",
    b"<?xml version='1.1'?>",
    b"<!DOCTYPE r [<!ELEMENT r ANY]>",
    b"<!DOCTYPE r [<!ENTITY a 'AAAA'>]><r>&a;</r>",
    b"<!DOCTYPE r [<!ENTITY a SYSTEM 'http://0.0.0.0/'>]><r>&a;</r>",  # XXE probe
    b"<![CDATA[" + b"A" * 4096 + b"]]>",
    b"<r " + b"a=" + b"\"" + b"A" * 4096 + b"\"" + b"></r>",
    b"<a><b></a>",                 # tag mismatch
    b"&unknown;",                   # undefined entity
    b"<r>&#xFFFFFFFF;</r>",         # oversized char ref
    b"<r>&#-1;</r>",                # negative char ref
    b"<r>\x00\x01\x02\x03</r>",     # control bytes
    b'<a href="',
    b'</a>'
]

ASCII = (string.ascii_letters + string.digits + "_-").encode()


def long_ascii(lo: int = 256, hi: int = 8192) -> bytes:
    n = random.randint(lo, hi)
    return bytes(random.choice(ASCII) for _ in range(n))


def deep_nesting(depth: int | None = None) -> bytes:
    if depth is None:
        depth = random.randint(16, 256)
    tag = random.choice([b"a", b"node", b"x"])
    pre = (b"<%s>" % tag) * depth
    suf = (b"</%s>" % tag) * depth
    return pre + b"X" + suf


def rand_attr_block() -> bytes:
    k = random.randint(1, 16)
    parts: List[bytes] = []
    for _ in range(k):
        # attribute names and values as long ASCII (stress lexer/allocations)
        name = long_ascii(3, 12)
        val = long_ascii(1, 4096)
        parts.append(name + b"=\"" + val + b"\"")
    return b" ".join(parts)


def gen_xml_payload() -> bytes:
    r = random.random()
    if r < 0.25:
        return deep_nesting()
    elif r < 0.50:
        return b"<r " + rand_attr_block() + b"></r>"
    elif r < 0.75:
        return b"<r>" + long_ascii(256, 16384) + b"</r>"
    else:
        return random.choice(DICT)


# --- Mutation operators ---
def sprinkle_xml_symbols(b: bytes) -> bytes:
    a = bytearray(b)
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
    
def m_fmt_spray(b):
    toks = [b"%n", b"%p", b"%x", b"%s"]
    spray = b"".join(random.choices(toks, k=random.randint(4, 40)))
    return b.replace(b'href="', b'href="' + spray)


class XML_Mutational_Fuzzer(Fuzzer):
    """
    XML mutational fuzzer:
    - `mutate(seed)` performs 1–3 random mutations (often preceded by dictionary injection).
    - `make_payload(seed)` picks between purely generated XML or a mutated seed,
       and may inject dictionary tokens again to increase structural pressure.
    """

    def __init__(self, path_to_input: str, binary_path: str):
        super().__init__(path_to_input, binary_path)
        self.mutators: List[Callable[[bytes], bytes]] = [
            flip_bytes,
            insert_block,
            delete_block,
            sprinkle_xml_symbols,
            inject_dict,
            m_fmt_spray
        ]

    def mutate(self, seed: bytes) -> bytes:
        d = seed
        if random.random() < 0.6:
            d = inject_dict(d)
        for _ in range(random.randint(1, 3)):
            d = random.choice(self.mutators)(d)
        return d

    def make_payload(self, seed: bytes) -> bytes:
        if random.random() < 0.6:
            return self.mutate(seed)
        base = gen_xml_payload()
        if random.random() < 0.8:
            base = inject_dict(base)
        return base

    # Optional convenience alias some schedulers prefer:
    def next_payload(self, seed: bytes) -> bytes:
        return self.make_payload(seed)
