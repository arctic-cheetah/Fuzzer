# csv_fuzzer.py
import random
from fuzzer_core import Fuzzer, b_insert, random_bytes

class CSV_Mutational_Fuzzer(Fuzzer):
    def __init__(self, path_to_input: str, binary_path: str):
        super().__init__(path_to_input, binary_path)
        self.mutators = [
            self.overwrite_chunk, self.insert_repeated_pattern,
            self.delete_random_block, self.duplicate_line_many_times,
            self.insert_0xCC_junk, self.insert_random_block,
            self.long_utf8_sequence, self.random_byte_mutation, self.swap_chunks,
        ]

    def overwrite_chunk(self, b):
        a = bytearray(b)
        if not a: return b
        start = random.randrange(0, len(a))
        length = random.randint(1, max(1, min(2000, len(a)//2)))
        for i in range(length):
            if start+i < len(a): a[start+i] = random.randint(0,255)
            else: a.append(random.randint(0,255))
        return bytes(a)

    def insert_repeated_pattern(self, b):
        pat = b"," + (b"A" * random.randint(500, 5000)) + b","
        pos = random.randint(0, len(b))
        return b[:pos] + pat + b[pos:]

    def delete_random_block(self, b):
        a = bytearray(b)
        if len(a) <= 4: return b
        s = random.randrange(0, len(a)-1)
        e = random.randrange(s+1, min(len(a), s+1+random.randint(1,2000)))
        del a[s:e]
        return bytes(a)

    def duplicate_line_many_times(self, b):
        try:
            text = b.decode(errors="ignore")
        except Exception:
            return b
        lines = text.splitlines(True)
        if not lines: return b
        line = random.choice(lines)
        rep = line * random.randint(50, 200)
        pos = random.randint(0, len(b))
        return b[:pos] + rep.encode() + b[pos:]

    def insert_0xCC_junk(self, b):
        junk = bytes([0xCC] * random.randint(100, 5000))
        pos = random.randint(0, len(b))
        return b[:pos] + junk + b[pos:]

    def insert_random_block(self, b):
        size = random.randint(10, 4000)
        junk = bytes([random.randint(0,255) for _ in range(size)])
        pos = random.randint(0, len(b))
        return b[:pos] + junk + b[pos:]

    def long_utf8_sequence(self, b):
        seq = ("😀" * random.randint(100, 1000)).encode("utf-8")
        pos = random.randint(0, len(b))
        return b[:pos] + seq + b[pos:]

    def random_byte_mutation(self, b):
        a = bytearray(b)
        n = max(1, len(a)//20)
        for _ in range(random.randint(1, n)):
            i = random.randrange(0, len(a))
            a[i] = random.randint(0,255)
        return bytes(a)

    def swap_chunks(self, b):
        a = bytearray(b)
        if len(a) < 8: return b
        i = random.randrange(0, len(a)//2)
        j = random.randrange(len(a)//2, len(a)-1)
        l = random.randint(1, min(100, len(a)//4))
        c1, c2 = a[i:i+l], a[j:j+l]
        a[i:i+l], a[j:j+l] = c2, c1
        return bytes(a)
