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
from globals import PATH_TO_HARNESS, mount_point
import struct
from time import sleep
from file_type_check import fileTypeCheck
from fuzzer import make_fuzzer
import os
from multiprocessing import Pool
import subprocess
import mmap
import shared_memory


def main():
    # 1) Fork the harness so the shm is set
    # print(f"Starting harness at {PATH_TO_HARNESS}")
    # TODO: refactor input to generalise later:
    # GET_progname
    example_inputs = mount_point("example_inputs")
    binary_path = mount_point("binaries")

    # TODO:ASK LECTURER IF NAME OF INPUT AND BINARY FILE ARE THE SAME!
    input_arr = [ example_inputs + "/csv1.txt",example_inputs + "/csv2.txt",example_inputs + "/json1.txt",example_inputs + "/json2.txt",example_inputs + "/xml1.txt",example_inputs + "/xml3.txt",example_inputs + "/plaintext1.txt",example_inputs + "/plaintext2.txt", example_inputs + "/plaintext3.txt"]
    bin_arr = [
        binary_path + "/csv1",
        binary_path + "/csv2",
        binary_path + "/json1",
        binary_path + "/json2",
        binary_path + "/xml1",
        binary_path + "/xml3",
        binary_path + "/plaintext1",
        binary_path + "/plaintext2",
        binary_path + "/plaintext3"
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
    for x in range(0, len(bin_arr)):

        in_data = input_arr[x]
        binary_path = bin_arr[x]
        # TODO: CALL FUZZER HERE
        file_type = check_file_type.detect_input_file_type(in_data)
        print(f"Discovered input type is: {file_type}")
        fuzzer = make_fuzzer(file_type, in_data, binary_path)
        fuzzer.run_binary()

    # input_len = struct.unpack_from("I", shm, 0)
    # process_flag = struct.unpack_from("I", shm, 4)
    # return_code_flag = struct.unpack_from("I", shm, 8)
    # bitmap =

    # file_type.run_challenge1_against_examples(example_inputs, binary_path)


if __name__ == "__main__":
    main()
