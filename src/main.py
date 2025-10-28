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

from pathlib import Path
import struct
from time import sleep
from file_type_check import fileTypeCheck
from fuzzer import Fuzzer
import os
from multiprocessing import Pool
import subprocess
import mmap
import shared_memory

PATH_TO_HARNESS = PROGRAM_PATH = (
    (Path(__file__).parent / "harness/harness").resolve().__str__()
)


def main():
    # 1) Fork the harness so the shm is set
    # print(f"Starting harness at {PATH_TO_HARNESS}")
    # TODO: refactor input to generalise later:
    example_inputs = (
        (Path(__file__).parent.parent.parent / "example_inputs").resolve().__str__()
    )
    binary_path = (Path(__file__).parent.parent.parent / "binaries").resolve().__str__()

    # TODO:ASK LECTURER IF NAME OF INPUT AND BINARY FILE ARE THE SAME!
    input_arr = [example_inputs + "/csv1.txt", example_inputs + "/json1.txt"]
    bin_arr = [
        binary_path + "/csv1",
        binary_path + "/json1",
    ]
    test_arr = [input_arr, bin_arr]

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
    # print(os.getcwd())

    shm = shared_memory.SharedMemoryStruct.from_buffer(mm)

    # print(f"Input_len: {shm.input_len}")
    # print(f"Process_flag: {shm.process_flag}")
    # print(f"Return_code_flag: {shm.return_code_flag}")
    # print(f"Bitmap: {shm.bitmap}")
    # print(f"Input: {shm.input}")

    # 3) Mutation/Fuzz here
    check_file_type = fileTypeCheck()

    # TODO: Parallelise here later!
    for x in range(0, len(test_arr)):

        in_data = input_arr[x]
        binary_path = bin_arr[x]
        # TODO: CALL FUZZER HERE
        file_type = check_file_type.detect_input_file_type(in_data)
        print(file_type)
        fuzzer = Fuzzer.FuzzerFactory(file_type, in_data, binary_path)
        fuzzer.mutate()

    # input_len = struct.unpack_from("I", shm, 0)
    # process_flag = struct.unpack_from("I", shm, 4)
    # return_code_flag = struct.unpack_from("I", shm, 8)
    # bitmap =

    # file_type.run_challenge1_against_examples(example_inputs, binary_path)


if __name__ == "__main__":
    main()
