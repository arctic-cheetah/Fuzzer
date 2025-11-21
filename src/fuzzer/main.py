#!/usr/bin/env -S uv run --script

# /// script
# dependencies = [
#   "pyzmq"
# ]
# ///

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
# example_inputs + "/plaintext1.txt", 
    bin_arr = []
    input_arr = []
    for filename in os.listdir(binary_path):
        bin_arr.append(os.path.join(binary_path, filename))
        input_arr.append(os.path.join(example_inputs, filename))
    
    test_arr = [input_arr, bin_arr]

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
