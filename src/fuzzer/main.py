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

import argparse
from pathlib import Path
from globals import PATH_TO_HARNESS, mount_point
import struct
from time import sleep
import file_type_check
from fuzzer import make_fuzzer
import os
from multiprocessing import Pool
import subprocess
import mmap
import shared_memory


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', help='binary path')
    parser.add_argument("--input", help='input path')
    args = parser.parse_args()
    binary_path = args.bin
    in_data = args.input
    file_type = file_type_check.detect_input_file_type(in_data)
    print(f"Discovered input type is: {file_type}")
    fuzzer = make_fuzzer(file_type, in_data, binary_path)
    fuzzer.run_binary()


if __name__ == "__main__":
    main()
