from fuzzer import b_insert, random_bytes, Fuzzer, random


class JSON_Mutational_Fuzzer(Fuzzer):

    def __init__(self, path_to_input: str, binary_path: str):
        super().__init__(path_to_input, binary_path)

        self.mutators = [
            self.long_string,
            self.control_chars,
            self.break_quotes,
            self.trailing_commas,
            self.unbalanced_braces,
            self.duplicate_keys,
            self.deep_nesting,
            self.numeric_edgecases,
            self.random_block,
            self.shuffle_array_items,
            self.break_unicode,
            self.delete_random_block,
            self.repeat_token,
        ]
        self.path_to_input = path_to_input

    def run_binary(self):
        super().run_binary()

    def long_string(self, b):
        """Insert a very long string value (may stress length and allocation)."""
        long_str = ("A" * random.randint(2000, 12000)).encode()
        payload = b'"' + long_str + b'"'
        return b_insert(b, payload)

    def control_chars(self, b):
        """Inject raw control characters inside a quoted area or randomly."""
        junk = bytes(
            [
                random.choice([0x00, 0x01, 0x02, 0x03, 0x0B, 0x0C, 0x1F])
                for _ in range(random.randint(10, 200))
            ]
        )
        return b_insert(b, junk)

    def break_quotes(self, b):
        """Break string quoting rules: stray quotes/backslashes."""
        payload = random.choice(
            [b'"\\', b'\\"', b'"""', b"\\\\\\\\", b'"\\u', b'"\\xZZ']
        )
        return b_insert(b, payload)

    def trailing_commas(self, b):
        """Add trailing commas in objects/arrays (invalid in strict JSON)."""
        payload = random.choice([b",}", b",]", b", ,", b",,,"])
        return b_insert(b, payload)

    def unbalanced_braces(self, b):
        """Insert or delete braces/brackets to break structure."""
        action = random.choice(["add", "del"])
        if action == "add":
            payload = random.choice([b"{", b"}", b"[", b"]"])
            return b_insert(b, payload)
        # delete a small random block (may remove a brace)
        a = bytearray(b)
        if len(a) <= 2:
            return b
        start = random.randrange(0, len(a) - 1)
        end = min(len(a), start + random.randint(1, 50))
        del a[start:end]
        return bytes(a)

    def duplicate_keys(self, b):
        """Insert object snippet with duplicate keys (many parsers mishandle)."""
        snippet = b'"dup":1,"dup":2'
        payload = b"{" + snippet + b"}"
        return b_insert(b, payload)

    def deep_nesting(self, b):
        """Insert very deep nesting of arrays/objects to stress recursion/stack."""
        depth = random.randint(50, 400)
        left = random.choice([b"[", b"{"])
        right = b"]" if left == b"[" else b"}"
        payload = left * depth + b"0" + right * depth
        return b_insert(b, payload)

    def numeric_edgecases(self, b):
        """Insert large numbers, exponents, NaN/Infinity (non-standard)."""
        choice = random.choice(
            [
                b"9999999999999999999999999",
                b"-12345678901234567890",
                b"1e9999",
                b"-1e9999",
                b"NaN",
                b"Infinity",
                b"-Infinity",
            ]
        )
        return b_insert(b, choice)

    def random_block(self, b):
        """Insert a random byte block that may violate encoding/structure."""
        size = random.randint(32, 4096)
        return b_insert(b, random_bytes(size))

    def shuffle_array_items(self, b):
        """
        Try to create/perturb arrays by inserting a synthetic array with many items,
        or reorder a small chunk. This is a lossy heuristic but often effective.
        """
        items = b",".join(
            str(random.randint(-10, 10)).encode()
            for _ in range(random.randint(50, 500))
        )
        payload = b"[" + items + b"]"
        return b_insert(b, payload)

    def break_unicode(self, b):
        """Insert broken unicode escape sequences."""
        broken = random.choice(
            [b"\\uD800", b"\\uZZZZ", b"\\u000", b"\\u", b"\\u10FFFF"]
        )
        return b_insert(b, b'"' + broken + b'"')

    def delete_random_block(self, b):
        """Delete a random block; triggers truncation/EOF edge cases."""
        a = bytearray(b)
        if len(a) <= 4:
            return b
        start = random.randrange(0, len(a) - 1)
        end = random.randrange(
            start + 1, min(len(a), start + 1 + random.randint(1, 2000))
        )
        del a[start:end]
        return bytes(a)

    def repeat_token(self, b):
        """Repeat common JSON tokens excessively: true/false/null/:/,/{}[]."""
        token = random.choice([b"true", b"false", b"null", b":", b",", b"{}", b"[]"])
        rep = token * random.randint(50, 1000)
        return b_insert(b, rep)

    # Registry of mutators (A-style names)
