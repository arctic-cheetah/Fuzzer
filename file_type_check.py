#!/usr/bin/env python3
"""
file_type_check.py
---------------------
Given the input file type, check if it is JSON or CSV (comma-separated). Else,
return 'unknown'.

This code does NOT rely on filename extensions.

Strategy:
  1) Try to decode as UTF-8 (tolerant; ignores errors) and strip BOM.
  2) Quick "text-likeness" check to reject obviously-binary blobs.
  3) JSON: attempt json.loads() on the (trimmed) text.
  4) CSV: use csv.Sniffer on a sample + basic column consistency checks.

Returns: (type_hint, confidence)
  type_hint ∈ {'json', 'csv', 'unknown'}
  confidence ∈ [0..100]
"""

from __future__ import annotations
import sys
import json
import csv
import os
from typing import Tuple

# How much to sample for sniffing (large enough for structure, small for speed)
SAMPLE_BYTES = 128 * 1024  # 128 KiB

'''
def _decode_utf8_lossy(data: bytes) -> str:
    """Decode as UTF-8, ignoring errors; strip UTF-8 BOM if present."""
    # DEPRECATED: TOOD: CHECK 
    s = data.decode("utf-8", errors="ignore")
    if s.startswith("\ufeff"):
        s = s.lstrip("\ufeff")
    return s
'''


def _is_json(text: str) -> bool:
    """
    JSON check: trim leading whitespace and try json.loads().
    Accepts either object or array roots.
    """
    t = text.lstrip()
    if not t or (t[0] not in "{["):
        # Quick shape check: typical JSON starts with '{' or '['
        return False
    try:
        json.loads(text)
        return True
    except Exception:
        return False


def _is_csv(text: str) -> bool:
    """
    CSV check (comma-separated):
      - Must contain at least one newline and at least one comma.
      - csv.Sniffer identifies a consistent dialect with comma delimiter.
      - Basic column-count sanity across several lines.
    """
    if (("\n" not in text) and ("\r" not in text)) or ("," not in text):
        return False

    # Limit to a sample for faster sniffing
    sample = text[:SAMPLE_BYTES]

    # csv.Sniffer may raise on pathological inputs — guard with try/except.
    try:
        sniffer = csv.Sniffer()
        dialect = sniffer.sniff(sample)
    except Exception:
        return False
    # Only accept comma-separated delimiter for CSV.
    if getattr(dialect, "delimiter", None) != ",":
        return False

    # Verify column-count consistency across a few non-empty rows.
    try:
        rows = list(csv.reader(sample.splitlines(), dialect))
    except Exception:
        return False

    # Filter out completely empty rows
    rows = [r for r in rows if r]
    if len(rows) < 2:
        return False

    # Must have at least 2 columns somewhere
    if max(len(r) for r in rows) < 2:
        return False

    # Allow some variance, but reject wildly inconsistent shapes
    first_n = rows[:50]  # check first N rows
    lens = [len(r) for r in first_n if r]
    if not lens:
        return False
    # If more than ~6 distinct widths in first 50 rows, treat as irregular text
    if len(set(lens)) > 6:
        return False

    return True


def detect_input_file_type(binary_file_path: str, input_file_path: str) -> str:
    """
    Args:
        binary_file_path: Rerpesents the path to the binary
        input_file_path: represents the path to the input file
    Returns:
        The file type in string format as seen in the ass specs
    """
    try:
        with open(input_file_path, "rb") as f:
            blob = f.read()
            f.seek(0)
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            # NOTE: CHECK decoding format here
            blob = blob.decode("utf-8")
    except OSError as e:
        print(f"Error reading input file: {e}", file=sys.stderr)
        sys.exit(2)
    # DO NOT READ IN PARTS OF THE FILE OTHERWISE PARSER NO WORK
    # TODO: CHECK IF WE NEED IF INPUT FILE SIZE IS PROBLEM, ASK LECTURER
    # PREFORM MAGIC BYTE CHECKING HERE.

    if _is_json(blob):
        return "json"

    # Then CSV (looser, but with structural checks)
    elif _is_csv(blob):
        return "csv"

    # TODO: CHECK OTHER FILE TYPES LATE
    else:
        return "txt"


# TODO: Test code
# --- CLI usage for convenience ---
if __name__ == "__main__":
    # Assume directory structure is in fuzzer
    DEFAULT_BINARY = "binaries/challenge1"
    DEFAULT_INPUT = "example_inputs/csv1.txt"
    DEFAULT_INPUT = "example_inputs/json1.txt"

    res = detect_input_file_type(DEFAULT_BINARY, DEFAULT_INPUT)
    print(res)
