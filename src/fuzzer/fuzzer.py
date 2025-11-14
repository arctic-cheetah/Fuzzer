# fuzzer.py
from json_fuzzer import JSON_Mutational_Fuzzer
from csv_fuzzer import  CSV_Mutational_Fuzzer
from xml_fuzzer import XML_Mutational_Fuzzer
from plaintext_fuzzer import Plaintext_Mutational_Fuzzer
def make_fuzzer(file_type: str, path_to_input: str, binary_path: str):
    ft = file_type.lower()
    if   ft == "json": return JSON_Mutational_Fuzzer(path_to_input, binary_path)
    elif ft == "csv" : return CSV_Mutational_Fuzzer(path_to_input, binary_path)
    elif ft == "xml" : return XML_Mutational_Fuzzer(path_to_input, binary_path)
    elif ft == "plaintext" : return Plaintext_Mutational_Fuzzer(path_to_input, binary_path)
    else:
        raise NotImplementedError(f"unsupported file type: {file_type}")
