#include <stdlib.h>
#include <stdint.h>

int main() {
    int x = 5 * 5;

    uint64_t *fuck = (uint64_t*)malloc(32);
    uint64_t *shit = (uint64_t*)malloc(32);

    free(shit);
    free(fuck);

    fuck[0] = 0x6767676767676700 ^ ((uint64_t)&fuck[0] >> 12);
    //fuck[1] = 0x6767676767676700 ^ (uint64_t)&fuck[1];
    //fuck[2] = 0x6767676767676700 ^ (uint64_t)&fuck[2];
    //fuck[3] = 0x6767676767676700 ^ (uint64_t)&fuck[3];
    //fuck[4] = 0x6767676767676700 ^ (uint64_t)&fuck[4];

    malloc(32);
    malloc(32);
    malloc(32);
    malloc(32);
    malloc(32);
    malloc(32);
    malloc(32);
    malloc(32);

    return x;
}