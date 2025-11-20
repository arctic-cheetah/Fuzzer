import os, re, random, subprocess
import asyncio
from typing import List, Callable
from globals import mount_point
import zmq

NUM_TO_RUN = 50_000
TIMEOUT = 1

def b_insert(b: bytes, payload: bytes) -> bytes:
    pos = random.randint(0, len(b))
    return b[:pos] + payload + b[pos:]

def random_bytes(size: int) -> bytes:
    return os.urandom(size)

class Fuzzer:
    mutators: List[Callable] = []
    path_to_input: str = ""
    binary_path: str = ""
    binary_name: str = ""

    def __init__(self, path_to_input: str, binary_path: str):
        self.path_to_input = path_to_input
        self.binary_path = binary_path
        self.binary_name = re.search(r"(\w+)$", self.binary_path)[0]
        self.mutators = []

    def run_binary(self):
        with open(self.path_to_input, "rb") as f:
            seed = f.read()

        events = zmq.socket(zmq.SUB)
        events.connect("ipc:///tmp/fuzzer-events")
        events.setsockopt_string(zmq.SUBSCRIBE, "")

        cmds = zmq.socket(zmq.REQ)
        cmds.connect("ipc:///tmp/fuzzer")

        pipe = open("/tmp/fuzzer-pipe1", "wb")

        for x in range(NUM_TO_RUN):
            try:
                if hasattr(self, "make_payload"):
                    data = self.make_payload(seed)
                else:
                    data = self.mutate(seed)

                # Notify harness to process input
                cmds.send(f"exec;{self.binary_path}".encode())
                pipe_name = cmds.recv()  # Wait for acknowledgment
                print(f"sending input {x} to harness via {pipe_name.decode()}")
                
                # Send data to harness via pipe
                size_bytes = len(data).to_bytes(4, byteorder="little")
                pipe.write(size_bytes)
                pipe.write(data)
                pipe.flush()

                print(events.recv().decode())  # Wait for harness to signal completion
            except:
                print(f"Error during fuzzing iteration {x}")
                continue

        '''for x in range(NUM_TO_RUN):
            try:
                if hasattr(self, "make_payload"):
                    data = self.make_payload(seed)  # <-- deep_* 会在这条路径里被用到
                else:
                    data = self.mutate(seed)
                proc = subprocess.run(
                    [self.binary_path],
                    input=data,
                    capture_output=True,
                    timeout=TIMEOUT,
                    check=False,
                )
                rc = proc.returncode
                if rc < 0:
                    print("________________________________")
                    print(f"Crashed at the {x} input")
                    print({"exit_code": rc, "stderr": proc.stderr})
                    self.log_crash(data)
                    print("________________________________")
                    return

                if (x % 50) == 0:
                    print(f"Tried {x} inputs")

            except subprocess.TimeoutExpired as e:
                print("________________________________")
                print(f"Timed out at the {x} input")
                print({"timed_out": True, "stderr": e.stderr})
                print("________________________________")

            except Exception as err:
                print(err)
                pass'''

    def log_crash(self, data: bytes):
        out = mount_point(f"fuzzer_output/bad_{self.binary_name}.txt")
        with open(out, "w+", encoding="latin-1") as f:
            f.write(data.decode("latin-1"))

    def mutate(self, data: bytes):
        for _ in range(1, random.randint(1, 6)):
            func = random.choice(self.mutators)
            try:
                data = func(data)
            except Exception:
                return b""
        return data
