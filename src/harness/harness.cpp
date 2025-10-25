#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstdint>
#include <atomic>
#include <string.h>
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <iostream>
#include "harness.h"
#include <errno.h>

#define MAX_DATA_LEN (1 << 20) // 1MB
#define BIT_MAP_LEN (1 << 16)  // 64KB

// Shared memory structure
typedef struct
{
    uint32_t input_len;
    uint32_t process_flag; // represents the status of the current input
    // process_flag values:
    // 0=new_cov
    // 1=new_input
    // 2=crash
    // 3=timeout
    // 4=exit
    uint32_t return_code_flag;   // represents the return code of the executed input
    uint32_t exec_id;            // Identify the input type
    uint8_t bitmap[BIT_MAP_LEN]; // Bitmap represents code coverage (need to set to zero)
    uint8_t input[MAX_DATA_LEN]; // input data
} shm_t;

// TODO: SHOULD THIS PATH BE STATIC?
// TODO; CHECK IF SHM PATH IS CORRECT
static const char *SHM_PATH = "/comp6447_shared";

int init_shared_memory();

// Harness to execute test casesq
int main()
{
    const size_t SHM_SIZE = sizeof(shm_t);
    printf("%s\n", SHM_PATH);
    // 1)Create or open the SHM
    int shm_fd = shm_open(SHM_PATH, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    // Error checking
    shm_error_check(shm_fd, SHM_SIZE);

    // 3) Get a typed view of the SHM
    shm_t *shm_ptr = (shm_t *)mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    // 4) Initialise shm once
    // TODO: Check error checking here!
    memset(shm_ptr, 0, SHM_SIZE);
    shm_ptr->input_len = 0;
    shm_ptr->process_flag = 0;
    shm_ptr->return_code_flag = 0;
    shm_ptr->exec_id = 0;

    // 5) Make process_flag and return_code_flag atomic C++ 20 compliant
    auto *process_flag = reinterpret_cast<std::atomic<uint32_t> *>(&shm_ptr->process_flag);
    auto *return_code_flag = reinterpret_cast<std::atomic<uint32_t> *>(&shm_ptr->return_code_flag);

    // 6) Read from objdump the code regions to obtain disassembly code

    // 8)Event loop here to do tasks!
    std::cout << "Harness is running!\n"
              << std::endl;
    while (true)
    {
        // Wait for the fuzzer to write input and set process_flag
        while (process_flag->load() != 1 && process_flag->load() != 4)
            ;

        // Exit program
        if (process_flag->load() == 4)
            break;

        std::cout << "New input obtained from fuzzer!\n";
        // 9) TODO: Execute the provided binary! via QEMU

        process_flag->store(0); // Send new coverage
    }
    // TODO: When to close fd? When we send data to the fuzzer
    close(shm_fd);
    // remove SHM_PATH
    shm_unlink(SHM_PATH);
    return 0;
}

void shm_error_check(int shm_fd, const size_t SHM_SIZE)
{
    if (shm_fd == -1)
    {
        fprintf(stderr, "shm_open failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    // 2) Set the size of the SHM
    if (ftruncate(shm_fd, SHM_SIZE) == -1)
    {
        perror("SHM truncate and setting file size failed!\n");
        exit(EXIT_FAILURE);
    }
}
