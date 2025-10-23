#!/usr/bin/env -S uv run --script
"""
    this is the entry point of the fuzzer, i.e. the scheduler.

"""
import os
from multiprocessing import Pool
import subprocess

def main():
    bin_dir_path = os.getenv('FUZZER_BIN_DIR', 'Not Set')
    seed_dir_path = os.getenv('FUZZER_SEED_DIR', 'Not Set')
    out_dir_path = os.getenv('FUZZER_OUT_DIR', 'Not Set')
    print("Hello from src!")




if __name__ == "__main__":
    main()
