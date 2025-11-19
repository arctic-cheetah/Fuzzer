# elf_fuzzer.py
"""
ELF-focused mutational fuzzer (payload generation only).

This module mutates ELF headers and surrounding structures to stress ELF
parsers/loaders. It DOES NOT execute the target or handle crash detection;
the caller (e.g. Fuzzer.run_binary) is responsible for running the binary.

Key design:
- Keep ELF magic (0x7f 'ELF') intact so the target actually parses the file.
- First payload: aggressive header corruption (e_shoff / e_shnum).
- Afterwards:
    * ~70%: structured header field mutations (offsets/counts/sizes).
    * ~30%: generic byte-level mutations (flip/insert/delete blocks).
"""

import random
from typing import List, Callable

from fuzzer_core import Fuzzer, b_insert, random_bytes

ELF_MAGIC = b"\x7fELF"


# --------------------------------------------------------------------
# Helpers: LE patching, magic enforcement
# --------------------------------------------------------------------
def ensure_elf_magic(b: bytes) -> bytes:
    """Force first 4 bytes to be 0x7f 'E' 'L' 'F'."""
    a = bytearray(b)
    if len(a) < 4:
        a.extend(b"\x00" * (4 - len(a)))
    a[0:4] = ELF_MAGIC
    return bytes(a)


def patch_le(a: bytearray, off: int, size: int, val: int) -> None:
    """Patch little-endian integer at offset `off`."""
    if off + size > len(a):
        return
    for i in range(size):
        a[off + i] = (val >> (8 * i)) & 0xFF


def read_le(a: bytearray, off: int, size: int) -> int:
    """Best-effort little-endian read; returns 0 on OOB."""
    if off + size > len(a):
        return 0
    v = 0
    for i in range(size):
        v |= int(a[off + i]) << (8 * i)
    return v


# --------------------------------------------------------------------
# Generic mutators (bit flips / insert / delete) with ELF-aware guards
# --------------------------------------------------------------------
def flip_bytes(b: bytes) -> bytes:
    """Randomly flip bytes, but never touch the ELF magic."""
    if len(b) <= 4:
        return b
    a = bytearray(b)
    # keep flips fairly sparse; we want structural but not total chaos
    n = max(1, len(a) // 64)
    for _ in range(random.randint(1, n)):
        i = random.randrange(4, len(a))  # skip magic
        a[i] = random.randint(0, 255)
    return ensure_elf_magic(bytes(a))


def insert_block(b: bytes) -> bytes:
    """Insert a random block somewhere after the ELF header."""
    blk = random_bytes(random.randint(8, 1024))
    if len(b) <= 0x40:
        pos = len(b)
    else:
        pos = random.randint(0x40, len(b))
    out = b_insert(b, blk)
    return ensure_elf_magic(out)


def delete_block(b: bytes) -> bytes:
    """Delete a random block from the body (preserve the first 0x40 bytes)."""
    if len(b) <= 0x50:
        return b
    header = b[:0x40]
    body = b[0x40:]
    if len(body) <= 1:
        return b
    i = random.randrange(0, len(body))
    j = random.randrange(i + 1, min(len(body), i + 1 + random.randint(1, 4096)))
    body = body[:i] + body[j:]
    return ensure_elf_magic(header + body)


# --------------------------------------------------------------------
# Structured ELF header mutations
# --------------------------------------------------------------------
def mutate_elf_header(b: bytes) -> bytes:
    """
    Corrupt ELF header fields (offsets/counts/sizes) with extreme values.

    Targets fields such as:
    - e_phoff / e_shoff  (program/section header table offsets)
    - e_phnum / e_shnum  (number of entries)
    - e_ehsize / e_phentsize / e_shentsize (entry sizes)
    """
    a = bytearray(b)
    if len(a) < 0x40:
        return ensure_elf_magic(b)

    elf_class = a[4]  # 1 = 32-bit, 2 = 64-bit
    is64 = (elf_class == 2)

    if is64:
        # ELF64 header layout
        e_phoff_off = 32
        e_shoff_off = 40
        e_flags_off = 48
        e_ehsize_off = 52
        e_phentsize_off = 54
        e_phnum_off = 56
        e_shentsize_off = 58
        e_shnum_off = 60
    else:
        # ELF32 header layout
        e_phoff_off = 28
        e_shoff_off = 32
        e_flags_off = 36
        e_ehsize_off = 40
        e_phentsize_off = 42
        e_phnum_off = 44
        e_shentsize_off = 46
        e_shnum_off = 48

    # Extreme values for header fields
    extreme_16 = [0, 1, 0xFFFF]
    extreme_32 = [0, 1, 0xFFFF, 0xFFFFFFFF, len(a), len(a) * 2]
    extreme_64 = [0, 1, 0xFFFF, 0xFFFFFFFF, len(a), len(a) * 4]

    targets = ["phoff", "shoff", "phnum", "shnum", "ehsize", "phentsize", "shentsize", "flags"]
    choice = random.choice(targets)

    if choice == "phoff":
        patch_le(a, e_phoff_off, 8 if is64 else 4,
                 random.choice(extreme_64 if is64 else extreme_32))
    elif choice == "shoff":
        patch_le(a, e_shoff_off, 8 if is64 else 4,
                 random.choice(extreme_64 if is64 else extreme_32))
    elif choice == "phnum":
        patch_le(a, e_phnum_off, 2, random.choice(extreme_16))
    elif choice == "shnum":
        patch_le(a, e_shnum_off, 2, random.choice(extreme_16))
    elif choice == "ehsize":
        patch_le(a, e_ehsize_off, 2, random.choice(extreme_16))
    elif choice == "phentsize":
        patch_le(a, e_phentsize_off, 2, random.choice(extreme_16))
    elif choice == "shentsize":
        patch_le(a, e_shentsize_off, 2, random.choice(extreme_16))
    elif choice == "flags":
        patch_le(a, e_flags_off, 4, random.choice(extreme_32))

    return ensure_elf_magic(bytes(a))


def first_payload(seed: bytes) -> bytes:
    """
    Deterministic first payload:
    - Force e_shoff to near end-of-file
    - Force e_shnum to 0xFFFF

    This tends to trigger "loop over section headers" style bugs quickly.
    """
    a = bytearray(seed)
    if len(a) < 0x40:
        a.extend(b"\x00" * (0x40 - len(a)))

    elf_class = a[4]
    is64 = (elf_class == 2)

    if is64:
        e_shoff_off = 40
        e_shnum_off = 60
    else:
        e_shoff_off = 32
        e_shnum_off = 48

    # Put section header table near the end, and exaggerate section count
    approx_off = max(0x40, len(a) - 0x100)
    patch_le(a, e_shoff_off, 8 if is64 else 4, approx_off)
    patch_le(a, e_shnum_off, 2, 0xFFFF)

    return ensure_elf_magic(bytes(a))


# --------------------------------------------------------------------
# ELF fuzzer class
# --------------------------------------------------------------------
class ELF_Mutational_Fuzzer(Fuzzer):
    """
    Strategy:
    - First payload: aggressive e_shoff/e_shnum corruption to push section
      header iteration logic over the edge.
    - Afterwards:
        * ~70%: structured header mutations (mutate_elf_header).
        * ~30%: generic byte-level corruption (flip/insert/delete).
    """

    def __init__(self, path_to_input: str, binary_path: str):
        super().__init__(path_to_input, binary_path)
        self.mutators: List[Callable[[bytes], bytes]] = [
            flip_bytes,
            insert_block,
            delete_block,
            mutate_elf_header,
        ]
        self._primed: bool = False

    def mutate(self, seed: bytes) -> bytes:
        """Seed-based mutations: apply 1–3 mutators in sequence."""
        d = seed
        for _ in range(random.randint(1, 3)):
            m = random.choice(self.mutators)
            d = m(d)
        return ensure_elf_magic(d)

    def make_payload(self, seed: bytes) -> bytes:
        # 1) First input: deterministic, strong header corruption.
        if not self._primed:
            self._primed = True
            return first_payload(seed)

        # 2) Majority of inputs: structured header-based mutations.
        if random.random() < 0.7:
            return mutate_elf_header(seed)

        # 3) Remaining: generic byte-level corruption pipeline.
        return self.mutate(seed)

    # Optional convenience alias (same style as XML fuzzer)
    def next_payload(self, seed: bytes) -> bytes:
        return self.make_payload(seed)
