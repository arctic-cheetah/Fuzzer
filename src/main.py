#!/usr/bin/env -S uv run --script
"""
this is the entry point of the fuzzer, i.e. the scheduler.

"""
# We will run your fuzzer with the run_fuzzer.sh script in the example fuzzer. You cannot modify this file.

# Run docker build to build your submitted Dockerfile
# Run the docker container with
# All binaries mounted at /binaries
# i.e.: /binaries/plaintext1, /binaries/plaintext2
# All example inputs mounted at /example_inputs/
# i.e.: /binaries/plaintext1.txt, /binaries/plaintext2.txt
# Create a folder in the Docker Container called /fuzzer_output which your fuzzer must write text files to which will cause a given program to crash.
# The files must be called bad_{progname}.txt.
# i.e. For /binaries/xml2 your fuzzer should create /fuzzer_output/bad_xml2.txt.
# Note: Your fuzzer will have 60 seconds per challenge (on average). If there are 10 binaries, you fuzzer will be stopped after 600 seconds (10 minutes)

import struct
from time import sleep
import file_type
import os
from multiprocessing import Pool
import subprocess
import mmap
import shared_memory

PATH_TO_HARNESS = "src/harness/harness"

file_type.run_challenge1_against_examples()


def main():
    bin_dir_path = os.getenv("FUZZER_BIN_DIR", "Not Set")
    seed_dir_path = os.getenv("FUZZER_SEED_DIR", "Not Set")
    out_dir_path = os.getenv("FUZZER_OUT_DIR", "Not Set")
    # 1) Fork the harness so the shm is set
    # Env is not really neeeded
    env = os.environ.copy()
    env["SHM_NAME"] = shared_memory.SHM_NAME
    env["SHM_SIZE"] = str(shared_memory.SHM_SIZE)
    subprocess.Popen([PATH_TO_HARNESS], env=env)

    # Wait for harness to allocate memory
    sleep(0.01)

    # 2) Read from shm
    fd = os.open(shared_memory.SHM_PATH, os.O_RDWR)
    mm = mmap.mmap(fd, shared_memory.SHM_SIZE)

    shm = shared_memory.SharedMemoryStruct.from_buffer(mm)

    print(f"Input_len: {shm.input_len}")
    print(f"Process_flag: {shm.process_flag}")
    print(f"Return_code_flag: {shm.return_code_flag}")
    print(f"Bitmap: {shm.bitmap}")
    print(f"Input: {shm.input}")
    # input_len = struct.unpack_from("I", shm, 0)
    # process_flag = struct.unpack_from("I", shm, 4)
    # return_code_flag = struct.unpack_from("I", shm, 8)
    # bitmap =

    print("Hello from src!")


if __name__ == "__main__":
    main()
