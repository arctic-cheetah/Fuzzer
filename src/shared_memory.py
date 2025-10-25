import ctypes as C
from multiprocessing import shared_memory


MAX_DATA_LEN = 1 << 20  # 1 MB
BIT_MAP_LEN = 1 << 16  # 64 KB


class SharedMemoryStruct(C.Structure):
    _fields_ = [
        ("input_len", C.c_uint32),
        ("process_flag", C.c_uint32),  # represents the status of the current input
        # process_flag values:
        # 0=new_cov
        # 1=new_input
        # 2=crash
        # 3=timeout
        # 4=exit
        (
            "return_code_flag",
            C.c_uint32,
        ),  # represnts the return code of the executed input
        ("exec_id", C.c_uint32),  # Identify the input type
        (
            "bitmap",
            C.c_uint8 * BIT_MAP_LEN,
        ),  # Bitmap represents code coverage (need to set to zero)
        ("input", C.c_uint8 * MAX_DATA_LEN),  # input data
    ]


SHM_SIZE = C.sizeof(SharedMemoryStruct)
SHM_NAME = "/comp6447_fuzzer_shm"
SHM_PATH = "/dev/shm" + SHM_NAME


def attach_or_create_shm(name):
    pass


# The fuzzer will always fork the harness
def main():
    pass
