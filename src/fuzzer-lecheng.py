import json
import random
import csv
import io
from typing import List, Optional, Tuple


class Fuzzer:
    def __init__(self, path_to_input: str):
        self.corpus = open(
            path_to_input, "rw"
        )  # doesn't have to be a file, can be loaded into memory, the
        self.mutators = [
            # add more as we make strategies
        ]

    def generate_rand_str(
        self, max_length: int = 100, char_start: int = 32, char_range: int = 32
    ) -> str:
        """adapted from fuzzing book"""
        out = ""
        chars: range = random.randrange(0, max_length + 1)
        for i in chars:
            out += chr(random.randrange(char_start, char_start + char_range))
        return out

    def replace_rand_str(self):
        pass

    def add_to_corpus(self, to_add: str):
        self.corpus.write("\n" + to_add)

    def __del__(self):
        self.corpus.close()

    def mutate(self, s: str, repeat=1):
        """the function the harness will call, to produce an input"""

        mutator = random.choice(self.mutators)
        mutation = mutator(s)
        if repeat == 1:
            return mutation
        return self.mutate(mutation, repeat - 1)


class JSON_Mutational_Fuzzer(Fuzzer):

    def __init__(self, path_to_input):
        super().__init__(path_to_input)
        self.grammar = json.load(self.corpus.read())  # assuming one input intitially
        self.mutators = [
            self.delete_random_field,
            self.change_a_field,
        ]

    def delete_random_field(self):
        pass

    def change_a_field(self):
        pass

    def json_safe_load(self, text: str):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def json_safe_dumps(obj) -> str:
        return json.dumps(obj, ensure_ascii=False)

    def json_delete_key(self, text: str, key_path: Optional[str] = None) -> str:
        """
        key_path: dot-separated path like 'user.profile.age'; if None picks a random top-level key.
        """
        obj = json_safe_load(text)
        if obj is None or not isinstance(obj, dict):
            return text
        keys = list(obj.keys())
        if not keys:
            return text
        if key_path is None:
            k = random.choice(keys)
            obj.pop(k, None)
            return json_safe_dumps(obj)
        # navigate
        parts = [p for p in key_path.split(".") if p]
        cur = obj
        for p in parts[:-1]:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return text
        if isinstance(cur, dict) and parts[-1] in cur:
            del cur[parts[-1]]
        return json_safe_dumps(obj)

    def json_add_key(text: str, key_path: Optional[str] = None, value=None) -> str:
        """
        Adds key with provided value (default random short string). Creates intermediate dicts if necessary.
        """
        obj = json_safe_load(text)
        if obj is None:
            return text
        if value is None:
            value = "mutated"
        if key_path is None:
            # add random top-level key
            k = "mut_" + str(random.randrange(10000, 99999))
            if isinstance(obj, dict):
                obj[k] = value
            return json_safe_dumps(obj)
        parts = [p for p in key_path.split(".") if p]
        cur = obj
        for p in parts[:-1]:
            if not isinstance(cur, dict):
                return text
            if p not in cur or not isinstance(cur[p], dict):
                cur[p] = {}
            cur = cur[p]
        if isinstance(cur, dict):
            cur[parts[-1]] = value
        return json_safe_dumps(obj)

    def json_move_key(text: str, src_path: str, dst_path: str) -> str:
        obj = json_safe_load(text)
        if obj is None:
            return text
        src_parts = [p for p in src_path.split(".") if p]
        dst_parts = [p for p in dst_path.split(".") if p]
        if not src_parts or not dst_parts:
            return text
        # get src parent
        cur = obj
        for p in src_parts[:-1]:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return text
        if not isinstance(cur, dict) or src_parts[-1] not in cur:
            return text
        value = cur[src_parts[-1]]
        del cur[src_parts[-1]]
        # create dst parent
        cur = obj
        for p in dst_parts[:-1]:
            if p not in cur or not isinstance(cur[p], dict):
                cur[p] = {}
            cur = cur[p]
        cur[dst_parts[-1]] = value
        return json_safe_dumps(obj)


# TODO: Do mutational fuzzer for XML, JPEG, and other file types from assignment


class XML_Mutational_Fuzzer(Fuzzer):

    def __init__(self, path_to_input):
        super().__init__(path_to_input)
        self.grammar = self.corpus.read()  # assuming one input intitially
        self.mutators = [
            self.delete_random_field,
            self.change_a_field,
        ]

    def delete_random_field(self):
        pass

    def change_a_field(self):
        pass

    def parse_csv(text: str) -> Tuple[Optional[List[str]], List[List[str]]]:
        buf = io.StringIO(text)
        reader = csv.reader(buf)
        rows = list(reader)
        if not rows:
            return None, []
        # heuristic: consider first row header if any non-empty string
        first = rows[0]
        header_like = any(cell.strip() != "" for cell in first) and len(rows) > 1
        if header_like:
            return first, rows[1:]
        return None, rows

    def dump_csv(header: Optional[List[str]], rows: List[List[str]]) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        if header is not None:
            writer.writerow(header)
        for r in rows:
            writer.writerow(r)
        return buf.getvalue()

    def normalize_rows(rows: List[List[str]], width: int) -> List[List[str]]:
        out = []
        for r in rows:
            if len(r) < width:
                out.append(r + [""] * (width - len(r)))
            else:
                out.append(r[:width])
        return out

    # CSV mutators (simple, deterministic)
    def csv_delete_column(text: str, col_idx: Optional[int] = None) -> str:
        header, rows = parse_csv(text)
        # determine width
        width = 0
        if header is not None:
            width = max(len(header), *(len(r) for r in rows)) if rows else len(header)
        else:
            width = max((len(r) for r in rows), default=0)
        if width == 0:
            return text
        if col_idx is None:
            col_idx = random.randrange(0, width)
        rows = normalize_rows(rows, width)
        new_rows = []
        for r in rows:
            new_rows.append(r[:col_idx] + r[col_idx + 1 :])
        new_header = (
            header[:col_idx] + header[col_idx + 1 :] if header is not None else None
        )
        return dump_csv(new_header, new_rows)

    def csv_add_column(
        text: str,
        col_idx: Optional[int] = None,
        header_name: str = "new",
        default_val: str = "",
    ) -> str:
        header, rows = parse_csv(text)
        width = max((len(r) for r in rows), default=0)
        if header is not None:
            width = max(width, len(header))
        if col_idx is None:
            col_idx = random.randrange(0, width + 1)
        rows = normalize_rows(rows, width)
        new_rows = []
        for r in rows:
            left = r[:col_idx] if col_idx <= len(r) else r
            right = r[col_idx:] if col_idx <= len(r) else []
            new_rows.append(left + [default_val] + right)
        if header is not None:
            h_left = header[:col_idx] if col_idx <= len(header) else header
            h_right = header[col_idx:] if col_idx <= len(header) else []
            new_header = h_left + [header_name] + h_right
        else:
            new_header = None
        return dump_csv(new_header, new_rows)

    def csv_swap_columns(
        text: str, a: Optional[int] = None, b: Optional[int] = None
    ) -> str:
        header, rows = parse_csv(text)
        width = max((len(r) for r in rows), default=0)
        if header is not None:
            width = max(width, len(header))
        if width == 0:
            return text
        if a is None or b is None:
            a = random.randrange(0, width)
            b = random.randrange(0, width)
        rows = normalize_rows(rows, width)
        new_rows = []
        for r in rows:
            r2 = r.copy()
            while len(r2) <= max(a, b):
                r2.append("")
            r2[a], r2[b] = r2[b], r2[a]
            new_rows.append(r2)
        if header is not None:
            h = header.copy()
            while len(h) <= max(a, b):
                h.append("")
            h[a], h[b] = h[b], h[a]
            new_header = h
        else:
            new_header = None
        return dump_csv(new_header, new_rows)
