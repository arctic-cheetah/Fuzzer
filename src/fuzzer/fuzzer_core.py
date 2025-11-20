import os, re, random, subprocess
import asyncio
from typing import List, Callable
from globals import mount_point
import sys
import zmq
import zmq.asyncio
import json

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
        
        self.ctx = zmq.asyncio.Context()

    def run_binary(self):
        with open(self.path_to_input, "rb") as f:
            seed = f.read()

        return asyncio.run(self._run_binary(seed))

    async def _run_binary(self, seed: bytes):
        events = self.ctx.socket(zmq.SUB)
        events.connect("ipc:///tmp/fuzzer-events")
        events.setsockopt_string(zmq.SUBSCRIBE, "")

        cmds = self.ctx.socket(zmq.REQ)
        cmds.connect("ipc:///tmp/fuzzer")

        for x in range(NUM_TO_RUN):
            try:
                # clear the line and print progress
                print(f"\rFuzzing {self.binary_name}: {x}/{NUM_TO_RUN}", end="", flush=True)

                if hasattr(self, "make_payload"):
                    data = self.make_payload(seed)
                else:
                    data = self.mutate(seed)

                # Make a pipe to send data to harness
                pipe_name = f"/tmp/fuzzer-pipe-{os.getpid()}-{x}"
                os.mkfifo(pipe_name, 0o666)
                
                # Send data to harness via pipe
                def write_pipe():
                    try:
                        with open(pipe_name, "wb") as p:
                            p.write(data)
                            p.flush()
                    except BrokenPipeError:
                        pass
                    except Exception as e:
                        print(f"Error writing to pipe: {e}")

                async def pipe_coroutine():
                    try:
                        await asyncio.to_thread(write_pipe)
                    except asyncio.CancelledError:
                        pass

                c1 = asyncio.create_task(pipe_coroutine())

                # Notify harness to process input
                await cmds.send(f"exec;{self.binary_path};{pipe_name}".encode())
                pid = await cmds.recv()  # Wait for acknowledgment
                pid = int(pid.decode())

                if pid == 0:
                    if c1 is not None:
                        c1.cancel()
                    print(f"Failed to execute binary for iteration {x}")
                    continue

                async def read_event():
                    msg = await events.recv()

                    if c1 is not None:
                        c1.cancel()

                    return msg

                c2 = asyncio.create_task(read_event())

                await asyncio.gather(c1, c2)

                msg = c2.result()
                msg_str = msg.decode()

                try:
                    success_pid = int(msg_str)
                except Exception:
                    run_info = json.loads(msg_str)

                    if run_info.get("status") == "signal":
                        signum = run_info.get("signal")

                        # ignore aborts
                        if signum == 6:
                            continue
                        print("________________________________")
                        print(f"Crashed at the {x} input")
                        print(run_info)

                        self.log_crash(run_info)

            except Exception as x:
                print(f"Error during fuzzing iteration {x}")
                sys.exit(0)
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
