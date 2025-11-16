#!/usr/bin/env python3
"""
更积极的变异 fuzzer（替换版）
- 读取 seed: csv1.txt
- 将变异数据通过 stdin 传给 ./csv1
- 更换了多种变异策略（覆盖插入、覆盖、重复、删除、随机块、长 UTF/emoji、0xCC/0xFF 垃圾等）
- 若检测到 crash（超时或被信号终止），保存 bad_csv1.txt 并退出
"""
import os, random, subprocess, time, argparse

SEED_FILE = "csv1.txt"
TARGET = "./csv1"
OUTFILE = "bad_csv1.txt"

def read_seed(path):
    with open(path, "rb") as f:
        return f.read()

# --- 高冲击力变异策略 ---
def overwrite_chunk(b):
    a = bytearray(b)
    if not a:
        return b
    # 从随机位置覆盖一段，长度可大到原长度的一半
    start = random.randrange(0, len(a))
    length = random.randint(1, max(1, min(2000, len(a)//2)))
    for i in range(length):
        if start + i < len(a):
            a[start + i] = random.randint(0, 255)
        else:
            a.append(random.randint(0, 255))
    return bytes(a)

def insert_repeated_pattern(b):
    a = bytearray(b)
    pat = b"," + (b"A" * random.randint(500, 5000)) + b","
    pos = random.randint(0, len(a))
    return bytes(a[:pos] + pat + a[pos:])

def delete_random_block(b):
    a = bytearray(b)
    if len(a) <= 4:
        return b
    start = random.randrange(0, len(a)-1)
    end = random.randrange(start+1, min(len(a), start+1+random.randint(1, 2000)))
    del a[start:end]
    return bytes(a)

def duplicate_line_many_times(b):
    text = b.decode(errors="ignore")
    lines = text.splitlines(True)
    if not lines:
        return b
    line = random.choice(lines)
    rep = line * random.randint(50, 200)
    pos = random.randint(0, len(b))
    return b[:pos] + rep.encode() + b[pos:]

def insert_0xCC_junk(b):
    # 0xCC 常作为断点指令，注入大量 0xCC/0xFF 来触发解析器异常
    a = bytearray(b)
    junk = bytes([0xCC] * random.randint(100, 5000))
    pos = random.randint(0, len(a))
    return bytes(a[:pos] + junk + a[pos:])

def insert_random_block(b):
    a = bytearray(b)
    size = random.randint(10, 4000)
    junk = bytes([random.randint(0,255) for _ in range(size)])
    pos = random.randint(0, len(a))
    return bytes(a[:pos] + junk + a[pos:])

def long_utf8_sequence(b):
    # 插入大量多字节 UTF-8（emoji 等），可能触发编码相关错误
    a = bytearray(b)
    seq = ("😀" * random.randint(100, 1000)).encode('utf-8')
    pos = random.randint(0, len(a))
    return bytes(a[:pos] + seq + a[pos:])

def random_byte_mutation(b):
    a = bytearray(b)
    n = max(1, len(a)//20)
    for _ in range(random.randint(1, n)):
        i = random.randrange(0, len(a))
        a[i] = random.randint(0,255)
    return bytes(a)

def swap_chunks(b):
    a = bytearray(b)
    if len(a) < 8:
        return b
    i = random.randrange(0, len(a)//2)
    j = random.randrange(len(a)//2, len(a)-1)
    # swap small chunks
    l = random.randint(1, min(100, len(a)//4))
    chunk1 = a[i:i+l]
    chunk2 = a[j:j+l]
    a[i:i+l] = chunk2
    a[j:j+l] = chunk1
    return bytes(a)

MUTATORS = [
    overwrite_chunk,
    insert_repeated_pattern,
    delete_random_block,
    duplicate_line_many_times,
    insert_0xCC_junk,
    insert_random_block,
    long_utf8_sequence,
    random_byte_mutation,
    swap_chunks
]

# --- 控制/辅助 ---
def mutate(seed):
    data = seed
    # 应用 1-4 个变异器，顺序随机
    for _ in range(random.randint(1,4)):
        fn = random.choice(MUTATORS)
        try:
            data = fn(data)
        except Exception:
            # 任何变异异常都直接跳过该变异
            pass
    return data

def is_crash(proc, timed_out):
    if timed_out:
        return True
    # subprocess.run 返回的对象有 returncode; TimeoutExpired 用 exception 捕获
    if hasattr(proc, "returncode"):
        rc = proc.returncode
        if rc is None:
            return True
        if rc < 0:
            return True
    return False

def run_once(target, data, timeout):
    try:
        p = subprocess.run([target], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return p, False
    except subprocess.TimeoutExpired as e:
        return e, True
    except Exception as e:
        # 若 binary 找不到或不可执行，抛出
        raise

def main():
    parser = argparse.ArgumentParser(description="Aggressive mutation fuzzer (simple)")
    parser.add_argument("--tries", "-t", type=int, default=500, help="试验次数")
    parser.add_argument("--timeout", type=float, default=1.0, help="每次执行超时（秒）")
    parser.add_argument("--out", "-o", default=OUTFILE, help="崩溃样本输出文件名")
    args = parser.parse_args()

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
                print("stdout:", out[:200])
                print("stderr:", err[:200])
            except Exception:
                pass
            return
        if i % 50 == 0:
            print(f"[{i}] tried, no crash yet")
    print("Done. no crash found in", args.tries)

if __name__ == "__main__":
    import argparse
    main()
