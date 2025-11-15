import random

from fuzzer_core import Fuzzer
import os


class PDF_Fuzzer(Fuzzer):
    def __init__(self, path_to_input: str, binary_path: str):
        super().__init__(path_to_input, binary_path)
        self.mutators = []
        # Open pdf file
        # with open(path_to_input) as f:

    # TODO: Parse the pdf input!

    # edit fields metadata of the pdf fuzzer

    # Override run_binary!
