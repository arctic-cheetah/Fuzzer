#!/usr/bin/env python3
from __future__ import annotations
import sys
import json
import csv
import os
import xml.etree.ElementTree as ET


"""
file_type_check.py
---------------------
Given the input file type, check if it is JSON or CSV (comma-separated). Else,
return 'unknown'.

This code does NOT rely on filename extensions.

Strategy:
  1) Use magic bytes to identify input file types accorrding to assignment
  2) JSON: attempt json.loads() on the (trimmed) text.
  3) XML: use xml to parse and if an xml file
  4) CSV: use csv.Sniffer on a sample + basic column consistency checks and herusitic
  5) Else is just a text
"""

# TODO: Check if this sample size is okay
SAMPLE_BYTES = 128 * 1024  # 128 KiB


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


def _is_jpg(data: bytes) -> bool:
    """
    Check if the given data is a JPEG file by looking for the JPEG magic numbers.

    Args:
        data: The byte data to check.
    Preconditions:
        JPG file is at least 12 bytes
    """
    # https://en.wikipedia.org/wiki/List_of_file_signatures

    # JPEG files start with FF D8 FF and can end with several...
    # Only 4 types!
    start = data[:12]
    if start[0:4] == b"\xff\xd8\xff\xee":
        return True
    elif start[0:4] == b"\xff\xd8\xff\xe0":
        return True
    elif start[0:4] == b"\xff\xd8\xff\xdb":
        return True
    elif start == b"\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01":
        return True
    return False


def _is_elf(data: bytes) -> bool:
    """
    Check if data is a ELF file by looking for the ELF magic number.

    Args:
        data: The byte data to check.
    Preconditions:
        ELF file is at least 4 bytes
    """
    start = data[:4]
    return start == b"\x7fELF"


def _is_pdf(data: bytes) -> bool:
    """
    Check if data a PDF file by looking for the PDF magic number.

    Args:
        data: The byte data to check.
    Preconditions:
        PDF file is at least 5 bytes
    """
    start = data[:5]
    return start == b"%PDF-"


# WARNING TODO: XML file appears to be HTML. IS THIS OKAY?
def _is_xml(data: str) -> bool:
    """
    Check if data a XML file by using lxml parse
    Args:
        data: The byte data to check.
    Postcondition:
        return a boolean if xml or not
    """
    try:
        ET.fromstring(data)
    except Exception as err:
        print(f"File most likely not XML!")
        print(f"XML parser error: {err}")
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
            blob_str = blob.decode("utf-8")
    except OSError as e:
        print(f"Error reading input file: {e}", file=sys.stderr)
        sys.exit(2)
    # DO NOT READ IN PARTS OF THE FILE OTHERWISE PARSER NO WORK
    # TODO: CHECK IF WE NEED IF INPUT FILE SIZE CAN BE BIG
    # IS PROBLEM, ASK LECTURER
    # PREFORM MAGIC BYTE CHECKING HERE.

    if _is_elf(blob):
        return "elf"
    elif _is_jpg(blob):
        return "jpg"
    elif _is_pdf(blob):
        return "pdf"
    elif _is_xml(blob_str):
        return "xml"
    elif _is_json(blob_str):
        return "json"
    # CSV has structural checks and heuristic
    elif _is_csv(blob_str):
        return "csv"
    # TODO: CHECK OTHER FILE TYPES LATE
    else:
        return "txt"


# If binary accepts particular file... Then of course it should
# Read meta data and magic num for checking
# TODO: Test code
# --- CLI usage for convenience ---
if __name__ == "__main__":
    # Assume directory structure is in fuzzer
    DEFAULT_BINARY = "binaries/challenge1"
    DEFAULT_INPUT = "example_inputs/csv1.txt"
    DEFAULT_INPUT = "example_inputs/json1.txt"
    DEFAULT_INPUT = "example_inputs/xml1.txt"

    res = detect_input_file_type(DEFAULT_BINARY, DEFAULT_INPUT)
    print(f"File is most likely: {res}")
