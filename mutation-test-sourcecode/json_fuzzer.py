#!/usr/bin/env python3
"""
json_fuzzer.py — Aggressive mutation fuzzer for a JSON parser binary named `json1`.

Key traits:
- Seed: json1.txt
- Target: ./json1 (reads from stdin)
- Crash = timeout OR signal-terminated process (returncode < 0)
- On first crash, write bad_json1.txt and exit

Usage:
  python3 json_fuzzer.py --tries 500 --timeout 1.0
"""

import os
import random
import subprocess
import argparse

SEED_FILE = "json1.txt"
TARGET = "./json1"
OUTFILE_DEFAULT = "bad_json1.txt"

# ------------------------------
# Utilities
# ------------------------------
def read_seed(path: str) -> bytes:
    """Read the seed file in binary mode."""
    with open(path, "rb") as f:
        return f.read()

def b_insert(data: bytes, payload: bytes, pos: int | None = None) -> bytes:
    """Insert a payload at a given (or random) position in a bytes object."""
    if pos is None:
        pos = random.randint(0, len(data))
    return data[:pos] + payload + data[pos:]

def random_bytes(n: int) -> bytes:
    """Generate n random bytes."""
    return bytes(random.randint(0, 255) for _ in range(n))

# ------------------------------
# JSON-focused mutators (operate on bytes; many use lossy decode/encode)
# ------------------------------
def m_long_string(b: bytes) -> bytes:
    """Insert a very long string value (may stress length and allocation)."""
    long_str = ("A" * random.randint(2000, 12000)).encode()
    payload = b"\"" + long_str + b"\""
    return b_insert(b, payload)

def m_control_chars(b: bytes) -> bytes:
    """Inject raw control characters inside a quoted area or randomly."""
    junk = bytes([random.choice([0x00, 0x01, 0x02, 0x03, 0x0b, 0x0c, 0x1f]) for _ in range(random.randint(10, 200))])
    return b_insert(b, junk)

def m_break_quotes(b: bytes) -> bytes:
    """Break string quoting rules: stray quotes/backslashes."""
    payload = random.choice([
        b"\"\\", b"\\\"", b"\"\"\"", b"\\\\\\\\", b"\"\\u", b"\"\\xZZ"
    ])
    return b_insert(b, payload)

def m_trailing_commas(b: bytes) -> bytes:
    """Add trailing commas in objects/arrays (invalid in strict JSON)."""
    payload = random.choice([b",}", b",]", b", ,", b",,,"])
    return b_insert(b, payload)

def m_unbalanced_braces(b: bytes) -> bytes:
    """Insert or delete braces/brackets to break structure."""
    action = random.choice(["add", "del"])
    if action == "add":
        payload = random.choice([b"{", b"}", b"[", b"]"])
        return b_insert(b, payload)
    # delete a small random block (may remove a brace)
    a = bytearray(b)
    if len(a) <= 2: 
        return b
    start = random.randrange(0, len(a)-1)
    end = min(len(a), start + random.randint(1, 50))
    del a[start:end]
    return bytes(a)

def m_duplicate_keys(b: bytes) -> bytes:
    """Insert object snippet with duplicate keys (many parsers mishandle)."""
    snippet = b"\"dup\":1,\"dup\":2"
    payload = b"{" + snippet + b"}"
    return b_insert(b, payload)

def m_deep_nesting(b: bytes) -> bytes:
    """Insert very deep nesting of arrays/objects to stress recursion/stack."""
    depth = random.randint(50, 400)
    left = random.choice([b"[", b"{"])
    right = b"]" if left == b"[" else b"}"
    payload = left * depth + b"0" + right * depth
    return b_insert(b, payload)

def m_numeric_edgecases(b: bytes) -> bytes:
    """Insert large numbers, exponents, NaN/Infinity (non-standard)."""
    choice = random.choice([
        b"9999999999999999999999999",
        b"-12345678901234567890",
        b"1e9999",
        b"-1e9999",
        b"NaN",
        b"Infinity",
        b"-Infinity",
    ])
    return b_insert(b, choice)

def m_random_block(b: bytes) -> bytes:
    """Insert a random byte block that may violate encoding/structure."""
    size = random.randint(32, 4096)
    return b_insert(b, random_bytes(size))

def m_shuffle_array_items(b: bytes) -> bytes:
    """
    Try to create/perturb arrays by inserting a synthetic array with many items,
    or reorder a small chunk. This is a lossy heuristic but often effective.
    """
    items = b",".join(str(random.randint(-10, 10)).encode() for _ in range(random.randint(50, 500)))
    payload = b"[" + items + b"]"
    return b_insert(b, payload)

def m_break_unicode(b: bytes) -> bytes:
    """Insert broken unicode escape sequences."""
    broken = random.choice([b"\\uD800", b"\\uZZZZ", b"\\u000", b"\\u", b"\\u10FFFF"])
    return b_insert(b, b"\"" + broken + b"\"")

def m_delete_random_block(b: bytes) -> bytes:
    """Delete a random block; triggers truncation/EOF edge cases."""
    a = bytearray(b)
    if len(a) <= 4:
        return b
    start = random.randrange(0, len(a)-1)
    end = random.randrange(start+1, min(len(a), start+1+random.randint(1, 2000)))
    del a[start:end]
    return bytes(a)

def m_repeat_token(b: bytes) -> bytes:
    """Repeat common JSON tokens excessively: true/false/null/:/,/{}[]."""
    token = random.choice([b"true", b"false", b"null", b":", b",", b"{}", b"[]"])
    rep = token * random.randint(50, 1000)
    return b_insert(b, rep)

# Registry of mutators
MUTATORS = [
    m_long_string,
    m_control_chars,
    m_break_quotes,
    m_trailing_commas,
    m_unbalanced_braces,
    m_duplicate_keys,
    m_deep_nesting,
    m_numeric_edgecases,
    m_random_block,
    m_shuffle_array_items,
    m_break_unicode,
    m_delete_random_block,
    m_repeat_token,
]

def mutate(seed: bytes) -> bytes:
    """Apply 1–4 random mutators in random order."""
    data = seed
    for _ in range(random.randint(1, 4)):
        fn = random.choice(MUTATORS)
        try:
            data = fn(data)
        except Exception:
            # If one mutator fails (e.g., decode hiccup), skip it.
            pass
    return data

# ------------------------------
# Runner & crash detection
# ------------------------------
def run_once(target: str, data: bytes, timeout: float):
    """Run target with data via stdin; return (proc_or_exception, timed_out_flag)."""
    try:
        p = subprocess.run([target], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return p, False
    except subprocess.TimeoutExpired as e:
        return e, True
    except Exception:
        raise  # propagate unexpected errors (missing binary, perms, etc.)

def is_crash(proc, timed_out: bool) -> bool:
    """
    Crash definition:
    - timed out => treat as crash/hang
    - returncode < 0 => terminated by signal => crash
    """
    if timed_out:
        return True
    if hasattr(proc, "returncode"):
        rc = proc.returncode
        if rc is None:
            return True
        if rc < 0:
            return True
    return False

# ------------------------------
# Main
# ------------------------------
def main():
    ap = argparse.ArgumentParser(description="Aggressive JSON mutation fuzzer (stdin mode)")
    ap.add_argument("--tries", "-t", type=int, default=500, help="Number of attempts")
    ap.add_argument("--timeout", type=float, default=1.0, help="Per-run timeout (seconds)")
    ap.add_argument("--out", "-o", default=OUTFILE_DEFAULT, help="Crash sample filename to write")
    args = ap.parse_args()

    # Basic checks
    if not os.path.exists(SEED_FILE):
        print("seed not found:", SEED_FILE); return
    if not os.path.exists(TARGET) or not os.access(TARGET, os.X_OK):
        print("target not found or not executable:", TARGET); return

    seed = read_seed(SEED_FILE)
    for i in range(1, args.tries + 1):
        data = mutate(seed)
        proc, timed_out = run_once(TARGET, data, args.timeout)

        if is_crash(proc, timed_out):
            with open(args.out, "wb") as f:
                f.write(data)
            print(f"[CRASH] saved {args.out} on attempt {i}")
            try:
                rc = proc.returncode if hasattr(proc, "returncode") else None
                out = proc.stdout if hasattr(proc, "stdout") else b""
                err = proc.stderr if hasattr(proc, "stderr") else b""
                print("returncode:", rc)
                print("stdout (trunc):", out[:200])
                print("stderr (trunc):", err[:200])
            except Exception:
                pass
            return

        if i % 50 == 0:
            print(f"[{i}] tried, no crash yet")

    print("Done. no crash found in", args.tries)

if __name__ == "__main__":
    main()
