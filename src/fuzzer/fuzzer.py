# fuzzer.py
from jpeg_core import JPEG
from json_fuzzer import JSON_Mutational_Fuzzer
from csv_fuzzer import  CSV_Mutational_Fuzzer
from xml_fuzzer import XML_Mutational_Fuzzer
from plaintext_fuzzer import Plaintext_Mutational_Fuzzer
from elf_fuzzer import ELF_Mutational_Fuzzer 
from jpeg_fuzzer import JPEG_Fuzzer
from pdf_fuzzer import PDF_Fuzzer
def make_fuzzer(file_type: str, path_to_input: str, binary_path: str):
    ft = file_type.lower()
    if   ft == "json": return JSON_Mutational_Fuzzer(path_to_input, binary_path)
    elif ft == "csv" : return CSV_Mutational_Fuzzer(path_to_input, binary_path)
    elif ft == "xml" : return XML_Mutational_Fuzzer(path_to_input, binary_path)
    elif ft == "plaintext" : return Plaintext_Mutational_Fuzzer(path_to_input, binary_path)
    elif ft == "pdf": return PDF_Fuzzer(path_to_input, binary_path)
    elif ft == "elf": return ELF_Mutational_Fuzzer(path_to_input, binary_path)
    elif ft == "jpg" : return JPEG_Fuzzer(path_to_input, binary_path)
    else:
        raise NotImplementedError(f"unsupported file type: {file_type}")
