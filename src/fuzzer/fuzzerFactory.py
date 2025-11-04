from CSV_Fuzzer import JSON_Mutational_Fuzzer
from JSON_Fuzzer import CSV_Mutational_Fuzzer


# We need this file to stop circular dependency!
def FuzzerFactory(file_type: str, path_to_input: str, binary_path: str):
    if file_type == "json":
        return JSON_Mutational_Fuzzer(path_to_input, binary_path)
    elif file_type == "csv":
        return CSV_Mutational_Fuzzer(path_to_input, binary_path)
    else:
        raise Exception("TODO TXT HERE")
    # TODO: DO THE TEXT HERE!
