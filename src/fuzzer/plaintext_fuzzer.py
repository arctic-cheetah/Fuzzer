# plaintext_fuzzer.py
import os
import random
import string
import subprocess
from typing import List, Tuple

from fuzzer_core import Fuzzer, b_insert, random_bytes, TIMEOUT, NUM_TO_RUN

# 统一字符集（用于可打印长串）
ASCII = (string.ascii_letters + string.digits + "_- ").encode()

# —— 保留/复用的格式化字典（命中 plaintext1 的核心）——
FORMAT_STR_DICT = [
    b"%n", b"%hn", b"%hhn", b"%ln", b"%lln",
    b"%p%p%p%p", b"%x%x%x%x", b"%08x%08x%08x",
    b"%s%s%s%s", b"%*s", b"%.10240s", b"%99999999s",
    b"%d%d%d%d", b"%#n", b"%hhn%n", b"%s%n",
]

# 常用长度边界
LEN_EDGES = [63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025]

# ----------------- 公共小工具（仅本文件内） -----------------
def _read_seed_lines(path: str) -> Tuple[bytes, List[bytes]]:
    try:
        raw = open(path, "rb").read()
    except Exception:
        # 为 two-line 策略提供安全回退
        raw = b"trivial\n2\n"
    parts = raw.split(b"\n")
    first = parts[0] if parts else b""
    rest = parts[1:] if len(parts) > 1 else []
    return first, rest

def _long_ascii(lo: int = 64, hi: int = (1 << 20)) -> bytes:
    n = random.randint(lo, hi)
    return bytes(random.choice(ASCII) for _ in range(n))

def _inject_fmt(buf: bytes, kmin: int = 1, kmax: int = 8) -> bytes:
    """使用公共 b_insert 注入 fmt 令牌，避免自写拼接逻辑"""
    out = buf
    for _ in range(random.randint(kmin, kmax)):
        out = b_insert(out, random.choice(FORMAT_STR_DICT))
    return out

def _encoding_noise_block() -> bytes:
    # 控制/非法编码序列（与 fmt 组合更容易触边界）
    choice = random.choice([
        b"\x00" * random.randint(1, 8192),          # NUL
        b"\xEF\xBB\xBF" * random.randint(1, 4096),  # BOM
        b"\xC0\xAF" * random.randint(1, 4096),      # 非法 UTF-8
        b"\xF5\x80\x80\x80" * random.randint(1, 1024),  # 超标 UTF-8
    ])
    return choice

# ----------------- 策略 0：单行（plaintext1 / fmt-heavy） -----------------
def payload_single_line() -> bytes:
    base = random.choice([
        _long_ascii(32, 4096),
        b"A" * random.choice(LEN_EDGES),
        b"",  # 允许纯 fmt
    ])
    if random.random() < 0.8:
        base = _inject_fmt(base, 4, 24)
    if random.random() < 0.5:
        # 在边界附近插入控制字节
        pos = min(len(base), random.choice([64, 128, 256, 512, 1024]))
        base = base[:pos] + _encoding_noise_block() + base[pos:]
    return base.rstrip(b"\n") + b"\n"

# ----------------- 策略 1：两行（plaintext2 / 口令+ID） -----------------
def _id_neg_edges() -> bytes:
    return random.choice([
        b"-1", b"-2", b"-3", b" -1", b"\t-1", b"+-1",
        b"-2147483648", b"-9223372036854775808",
    ])

def _id_pos_edges() -> bytes:
    return random.choice([
        b"2147483647", b"2147483648", b"4294967295",
        b"9223372036854775807", b"18446744073709551615",
        b"0x7fffffff", b"0xffffffff", b"9" * 10240,
    ])

def _id_len_edges() -> bytes:
    return b"9" * random.choice(LEN_EDGES + [4095, 4096, 4097])

def _id_nonnumeric_or_fmt() -> bytes:
    return random.choice([
        b"NaN", b"inf", b"--", b"+", b"e10", b"1e309",
        _long_ascii(1, 1024),
        _inject_fmt(b"", 2, 12),
    ])

def _id_with_ctrl() -> bytes:
    base = random.choice([b"0", b"1", b"2", b"3", b"-1"])
    noise = random.choice([_encoding_noise_block(), _inject_fmt(b"", 2, 12)])
    return (noise + base) if random.random() < 0.5 else (base + noise)

def _id_fmt_heavy() -> bytes:
    base = random.choice([_id_pos_edges(), _id_neg_edges(), _long_ascii(32, 4096), b""])
    return _inject_fmt(base, 4, 24)

def _second_line_payload() -> bytes:
    gen = random.choice([
        _id_pos_edges, _id_neg_edges, _id_len_edges,
        _id_nonnumeric_or_fmt, _id_with_ctrl, _id_fmt_heavy,
    ])
    return gen().rstrip(b"\n") + b"\n"

def _tail_lines() -> bytes:
    tails: List[bytes] = []
    if random.random() < 0.5:
        tails.append(b"A" * random.choice([32, 64, 128, 256]))
        tails.append(_inject_fmt(b"B" * random.choice([200000, 600000, 1200000]), 1, 10))
        tails.append(b"")
        tails.append(_inject_fmt(b"C" * random.choice([500000, 1500000]), 1, 10))
    else:
        tails.append(_inject_fmt(_encoding_noise_block(), 4, 24))
    return b"".join(t + b"\n" for t in tails)

def payload_two_line(password: bytes) -> bytes:
    pwd = (password or b"trivial").rstrip(b"\n")
    data = pwd + b"\n" + _second_line_payload()
    if random.random() < 0.5:
        data += _tail_lines()
    return data

# ----------------- 策略 2：JPG 头（plaintext3 / 8x8 优先） -----------------
def payload_img_header() -> bytes:
    r = random.random()
    if r < 0.7:
        w, h = 0x08, 0x08
    elif r < 0.9:
        w, h = 0xF8, 0xF8
    else:
        candidates = [(6, 7), (7, 6), (16, 20), (20, 16), (12, 12), (1, 200), (200, 1), (32, 10), (10, 32)]
        w, h = random.choice(candidates) if random.random() < 0.5 else (random.randint(0, 255), random.randint(0, 255))
    eol = b"\n" if random.random() < 0.5 else b"\r"
    buf = b"JPG" + bytes([w & 0xFF, h & 0xFF]) + eol
    # 20% 追加载荷（非必须）
    if random.random() < 0.2:
        plen = (w & 0xFF) * (h & 0xFF) * 10
        buf += random_bytes(min(plen, 2_000_000))  # 复用公共 random_bytes
    return buf

# ----------------- 主类：按 0/1/2 轮询 -----------------
class Plaintext_Mutational_Fuzzer(Fuzzer):
    """
    0 = 单行（fmt 重喷）      → plaintext1
    1 = 两行（口令 + ID）     → plaintext2
    2 = JPG 头（优先 8×8）    → plaintext3
    仅 stdin；rc < 0 视为 crash；命中即 log_crash() 落盘。
    """
    def __init__(self, path_to_input: str, binary_path: str):
        super().__init__(path_to_input, binary_path)
        # 使用自定义轮询策略，不依赖基类 mutate()
        self.mutators = []

    def run_binary(self):
        seed_first, _ = _read_seed_lines(self.path_to_input)

        for x in range(1, NUM_TO_RUN + 1):
            idx = (x - 1) % 3
            if idx == 0:
                data = payload_single_line()
            elif idx == 1:
                data = payload_two_line(seed_first)
            else:
                data = payload_img_header()

            try:
                proc = subprocess.run(
                    [self.binary_path],
                    input=data,
                    capture_output=True,
                    timeout=TIMEOUT,
                    check=False,
                )
                rc = proc.returncode
                if rc is not None and rc < 0:
                    print("________________________________")
                    print(f"[CRASH] idx={idx} attempt={x}")
                    print({"exit_code": rc, "stderr": proc.stderr})
                    self.log_crash(data)   # 复用公共落盘逻辑
                    print("________________________________")
                    return

                if (x % 200) == 0:
                    print(f"[{x}] attempts... last_rc={rc} next_idx={(x) % 3}")

            except subprocess.TimeoutExpired as e:
                # 你的口径：超时不算 crash
                print("________________________________")
                print(f"[TIMEOUT] idx={idx} attempt={x}")
                print({"timed_out": True, "stderr": getattr(e, "stderr", b"")})
                print("________________________________")
            except Exception as err:
                print(f"[ERROR] idx={idx} attempt={x} err={err}")
                continue
