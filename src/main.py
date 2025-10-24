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

import file_type
import os
from multiprocessing import Pool
import subprocess


file_type.run_challenge1_against_examples()


def main():
    bin_dir_path = os.getenv("FUZZER_BIN_DIR", "Not Set")
    seed_dir_path = os.getenv("FUZZER_SEED_DIR", "Not Set")
    out_dir_path = os.getenv("FUZZER_OUT_DIR", "Not Set")
    print("Hello from src!")


if __name__ == "__main__":
    main()
