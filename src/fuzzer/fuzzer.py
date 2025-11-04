import random
import subprocess
import os
from typing import List, Callable
import re
from globals import mount_point


NUM_TO_RUN = 50_000
TIMEOUT = 1


def b_insert(b: bytes, payload: bytes) -> bytes:
    """Insert payload into b at a random position [0..len(b)]."""
    pos = random.randint(0, len(b))
    return b[:pos] + payload + b[pos:]


def random_bytes(size: int) -> bytes:
    """Generate `size` random bytes."""
    return os.urandom(size)


def is_crash(proc, timeout) -> bool:
    """
    Crash definition:
    - timed out => treat as crash/hang
    - returncode < 0 => terminated by signal => crash
    """
    if timeout:
        return True
    if hasattr(proc, "returncode"):
        rc = proc.returncode
        if rc is None:
            return True
        if rc < 0:
            return True
    return False


class Fuzzer:
    mutators: List[Callable] = []
    path_to_input: str = ""
    binary_path: str = ""
    binary_name: str = ""

    def __init__(self, path_to_input: str, binary_path: str):
        self.path_to_input = path_to_input
        self.binary_path = binary_path
        self.binary_name = re.search(r"(\w+)$", self.binary_path)[0]
        self.mutators = [
            # add more as we make strategies
        ]

    def run_binary(self):
        # Apply 1-4 random mutators in random order.
        seed = b""
        with open(self.path_to_input, mode="rb") as f:
            seed = f.read()

        for x in range(0, NUM_TO_RUN):

            try:
                # TODO: MAKE MUTATER SMART HERE
                # chain mutater here!
                data = self.mutate(seed)
                # ---------------
                proc = subprocess.run(
                    [self.binary_path],
                    input=data,
                    capture_output=True,
                    timeout=TIMEOUT,
                    check=False,
                )

                rc = proc.returncode
                # print(proc.returncode)
                crashed = rc < 0
                signal = -rc if rc < 0 else None
                result = {
                    "input_file": str(self.path_to_input),
                    "exit_code": rc,
                    "signal": signal,
                    "timed_out": False,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                    "crashed": crashed,
                }
                if crashed:
                    print(f"________________________________")
                    print(f"Crashed at the {x} input")
                    print(f"Information: {result}")
                    self.log_crash(data)
                    print(f"________________________________")
                    return

                if (x % 50) == 0:
                    print(f"Tried {x} inputs")

            except subprocess.TimeoutExpired as e:
                result = {
                    "input_file": str(self.path_to_input),
                    "exit_code": None,
                    "signal": None,
                    "timed_out": True,
                    "stdout": e.stdout or b"",
                    "stderr": e.stderr or b"",
                    "crashed": False,
                }

                print(f"________________________________")
                print(f"Crashed at the {x} input")
                print(f"Information: {result}")
                print(f"________________________________")

            except Exception as err:
                print(err)
                # TODO: CHECK SYS CALL HERE ERROR
                # ignore mutator failures and continue
                pass

    def log_crash(self, data: bytes):
        with open(
            mount_point(f"fuzzer_output/bad_{self.binary_name}.txt"),
            "w+",
            encoding="latin-1",
        ) as f:
            f.write(data.decode("latin-1"))

    # def run_binary(self, data: bytes):
    #     try:
    #         p = subprocess.run([self.binary_path], data,capture_output=True,timeout=1000,check=False,)
    #     except subprocess.TimeoutExpired as e:

    def mutate(self, data: bytes):
        # Chain 1 to 6 random mutators:
        for _ in range(1, random.randint(1, 6)):
            func = random.choice(self.mutators)
            try:
                data = func(data)
            except Exception:
                print(f"Mutator failed {func}")
                return b""
        return data

    # def replace_rand_str(self):
    #     pass

    # def add_to_corpus(self, to_add: str):
    #     self.corpus.write("\n" + to_add)

    # def __del__(self):
    #     self.corpus.close()

    # def generate_rand_str(
    #     self, max_length: int = 100, char_start: int = 32, char_range: int = 32
    # ) -> str:
    #     """adapted from fuzzing book"""
    #     out = ""
    #     chars: range = random.randrange(0, max_length + 1)
    #     for i in chars:
    #         out += chr(random.randrange(char_start, char_start + char_range))
    #     return out


# class JSON_Mutational_Fuzzer(Fuzzer):

#     def __init__(self, path_to_input: str, binary_path: str):
#         super().__init__(path_to_input, binary_path)

#         self.mutators = [
#             self.long_string,
#             self.control_chars,
#             self.break_quotes,
#             self.trailing_commas,
#             self.unbalanced_braces,
#             self.duplicate_keys,
#             self.deep_nesting,
#             self.numeric_edgecases,
#             self.random_block,
#             self.shuffle_array_items,
#             self.break_unicode,
#             self.delete_random_block,
#             self.repeat_token,
#         ]
#         self.path_to_input = path_to_input

#     def run_binary(self):
#         super().run_binary()

#     def long_string(self, b):
#         """Insert a very long string value (may stress length and allocation)."""
#         long_str = ("A" * random.randint(2000, 12000)).encode()
#         payload = b'"' + long_str + b'"'
#         return b_insert(b, payload)

#     def control_chars(self, b):
#         """Inject raw control characters inside a quoted area or randomly."""
#         junk = bytes(
#             [
#                 random.choice([0x00, 0x01, 0x02, 0x03, 0x0B, 0x0C, 0x1F])
#                 for _ in range(random.randint(10, 200))
#             ]
#         )
#         return b_insert(b, junk)

#     def break_quotes(self, b):
#         """Break string quoting rules: stray quotes/backslashes."""
#         payload = random.choice(
#             [b'"\\', b'\\"', b'"""', b"\\\\\\\\", b'"\\u', b'"\\xZZ']
#         )
#         return b_insert(b, payload)

#     def trailing_commas(self, b):
#         """Add trailing commas in objects/arrays (invalid in strict JSON)."""
#         payload = random.choice([b",}", b",]", b", ,", b",,,"])
#         return b_insert(b, payload)

#     def unbalanced_braces(self, b):
#         """Insert or delete braces/brackets to break structure."""
#         action = random.choice(["add", "del"])
#         if action == "add":
#             payload = random.choice([b"{", b"}", b"[", b"]"])
#             return b_insert(b, payload)
#         # delete a small random block (may remove a brace)
#         a = bytearray(b)
#         if len(a) <= 2:
#             return b
#         start = random.randrange(0, len(a) - 1)
#         end = min(len(a), start + random.randint(1, 50))
#         del a[start:end]
#         return bytes(a)

#     def duplicate_keys(self, b):
#         """Insert object snippet with duplicate keys (many parsers mishandle)."""
#         snippet = b'"dup":1,"dup":2'
#         payload = b"{" + snippet + b"}"
#         return b_insert(b, payload)

#     def deep_nesting(self, b):
#         """Insert very deep nesting of arrays/objects to stress recursion/stack."""
#         depth = random.randint(50, 400)
#         left = random.choice([b"[", b"{"])
#         right = b"]" if left == b"[" else b"}"
#         payload = left * depth + b"0" + right * depth
#         return b_insert(b, payload)

#     def numeric_edgecases(self, b):
#         """Insert large numbers, exponents, NaN/Infinity (non-standard)."""
#         choice = random.choice(
#             [
#                 b"9999999999999999999999999",
#                 b"-12345678901234567890",
#                 b"1e9999",
#                 b"-1e9999",
#                 b"NaN",
#                 b"Infinity",
#                 b"-Infinity",
#             ]
#         )
#         return b_insert(b, choice)

#     def random_block(self, b):
#         """Insert a random byte block that may violate encoding/structure."""
#         size = random.randint(32, 4096)
#         return b_insert(b, random_bytes(size))

#     def shuffle_array_items(self, b):
#         """
#         Try to create/perturb arrays by inserting a synthetic array with many items,
#         or reorder a small chunk. This is a lossy heuristic but often effective.
#         """
#         items = b",".join(
#             str(random.randint(-10, 10)).encode()
#             for _ in range(random.randint(50, 500))
#         )
#         payload = b"[" + items + b"]"
#         return b_insert(b, payload)

#     def break_unicode(self, b):
#         """Insert broken unicode escape sequences."""
#         broken = random.choice(
#             [b"\\uD800", b"\\uZZZZ", b"\\u000", b"\\u", b"\\u10FFFF"]
#         )
#         return b_insert(b, b'"' + broken + b'"')

#     def delete_random_block(self, b):
#         """Delete a random block; triggers truncation/EOF edge cases."""
#         a = bytearray(b)
#         if len(a) <= 4:
#             return b
#         start = random.randrange(0, len(a) - 1)
#         end = random.randrange(
#             start + 1, min(len(a), start + 1 + random.randint(1, 2000))
#         )
#         del a[start:end]
#         return bytes(a)

#     def repeat_token(self, b):
#         """Repeat common JSON tokens excessively: true/false/null/:/,/{}[]."""
#         token = random.choice([b"true", b"false", b"null", b":", b",", b"{}", b"[]"])
#         rep = token * random.randint(50, 1000)
#         return b_insert(b, rep)

#     # Registry of mutators (A-style names)


# TODO: Do mutational fuzzer for XML, JPEG, and other file types from assignment


# class CSV_Mutational_Fuzzer(Fuzzer):

#     def __init__(self, path_to_input: str, binary_path: str):
#         super().__init__(path_to_input, binary_path)

#         self.mutators = [
#             self.overwrite_chunk,
#             self.insert_repeated_pattern,
#             self.delete_random_block,
#             self.duplicate_line_many_times,
#             self.insert_0xCC_junk,
#             self.insert_random_block,
#             self.long_utf8_sequence,
#             self.random_byte_mutation,
#             self.swap_chunks,
#         ]
#         self.path_to_input = path_to_input

#     def run_binary(self):
#         super().run_binary()

#     def overwrite_chunk(self, b):
#         a = bytearray(b)
#         if not a:
#             return b
#         # Overwrite a random chunk with random bytes.
#         # Length may be up to a portion of the original length; may append bytes.
#         # This aims to corrupt structure or insert unexpected byte values.
#         start = random.randrange(0, len(a))
#         length = random.randint(1, max(1, min(2000, len(a) // 2)))
#         for i in range(length):
#             if start + i < len(a):
#                 a[start + i] = random.randint(0, 255)
#             else:
#                 a.append(random.randint(0, 255))
#         return bytes(a)

#     def insert_repeated_pattern(self, b):
#         # Insert a long repeated pattern (e.g., many 'A's) at a random position.
#         # Useful to trigger length/overflow issues.
#         a = bytearray(b)
#         pat = b"," + (b"A" * random.randint(500, 5000)) + b","
#         pos = random.randint(0, len(a))
#         return bytes(a[:pos] + pat + a[pos:])

#     def delete_random_block(self, b):
#         # Remove a random block from the data (cut). Triggers boundary conditions on truncated inputs.
#         a = bytearray(b)
#         if len(a) <= 4:
#             return b
#         start = random.randrange(0, len(a) - 1)
#         end = random.randrange(
#             start + 1, min(len(a), start + 1 + random.randint(1, 2000))
#         )
#         del a[start:end]
#         return bytes(a)

#     def duplicate_line_many_times(self, b):
#         # Pick a line and duplicate it many times (heavy repetition).
#         # Useful to exercise line-parsing logic or resource exhaustion.
#         try:
#             text = b.decode(errors="ignore")
#         except Exception:
#             return b
#         lines = text.splitlines(True)
#         if not lines:
#             return b
#         line = random.choice(lines)
#         rep = line * random.randint(50, 200)
#         pos = random.randint(0, len(b))
#         return b[:pos] + rep.encode() + b[pos:]

#     def insert_0xCC_junk(self, b):
#         # Insert many 0xCC bytes (int3 opcode) or other high bytes. May provoke
#         # weird handling in parsers that inspect raw byte values.
#         a = bytearray(b)
#         junk = bytes([0xCC] * random.randint(100, 5000))
#         pos = random.randint(0, len(a))
#         return bytes(a[:pos] + junk + a[pos:])

#     def insert_random_block(self, b):
#         # Insert a random byte block of variable size to disturb encoding/structure.
#         a = bytearray(b)
#         size = random.randint(10, 4000)
#         junk = bytes([random.randint(0, 255) for _ in range(size)])
#         pos = random.randint(0, len(a))
#         return bytes(a[:pos] + junk + a[pos:])

#     def long_utf8_sequence(self, b):
#         # Insert a long multibyte UTF-8 sequence (e.g., emojis) to test encoding boundaries.
#         a = bytearray(b)
#         seq = ("😀" * random.randint(100, 1000)).encode("utf-8")
#         pos = random.randint(0, len(a))
#         return bytes(a[:pos] + seq + a[pos:])

#     def random_byte_mutation(self, b):
#         # run_binary a number of random bytes in the buffer.
#         a = bytearray(b)
#         n = max(1, len(a) // 20)
#         for _ in range(random.randint(1, n)):
#             i = random.randrange(0, len(a))
#             a[i] = random.randint(0, 255)
#         return bytes(a)

#     def swap_chunks(self, b):
#         # Swap two small chunks to disturb byte ordering.
#         a = bytearray(b)
#         if len(a) < 8:
#             return b
#         i = random.randrange(0, len(a) // 2)
#         j = random.randrange(len(a) // 2, len(a) - 1)
#         l = random.randint(1, min(100, len(a) // 4))
#         chunk1 = a[i : i + l]
#         chunk2 = a[j : j + l]
#         a[i : i + l] = chunk2
#         a[j : j + l] = chunk1
#         return bytes(a)
