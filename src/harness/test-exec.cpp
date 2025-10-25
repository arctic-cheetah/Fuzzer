#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstdint>

#define MAX_DATA_LEN (1 << 20) // 1MB
#define BIT_MAP_LEN (1 << 16)  // 64KB
// Shared memory structure
typedef struct
{
    uint32_t input_len;
    uint32_t process_flag;       // represents the status of the current input
    uint32_t return_code_flag;   // represents the return code of the executed input
    uint32_t exec_id;            // Identify the input type
    uint8_t bitmap[BIT_MAP_LEN]; // Bitmap represents code coverage (need to set to zero)
    uint8_t input[MAX_DATA_LEN]; // input data
} shm_t;
// Harness to execute test cases
int main()
{
    printf("Hello, World!\n");
    return 0;
}