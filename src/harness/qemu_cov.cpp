// qcov_plugin.c - QEMU TCG plugin: AFL-style edge coverage to shared memory

#define _GNU_SOURCE
#include <qemu-plugin.h> // QEMU's plugin API (TB/instruction callbacks, etc.)
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>    // for shm
#include <sys/mman.h> // mmap
#include <sys/stat.h>
#include <unistd.h> // close
#include <cstdlib>

// TODO: TEST THIS CODE
// Pointer to the *coverage bitmap* living inside a shared memory object.
// The bitmap is not allocated here; we map an existing POSIX SHM region
static uint8_t *bitmap = 0;

// Size of the bitmap (defaults to 64 KiB like AFL).
static size_t map_len = (1u << 16);
static uint32_t map_mask = (1u << 16) - 1;

// Thread-local "previous location" used to compute *edge* coverage.
// QEMU calls us per vCPU/thread, so we keep this TLS to avoid locking.
static __thread uint32_t prev_loc;

// Cheap 64→32-bit mixer to spread TB PCs across the map.
static inline uint32_t mix64(uint64_t x)
{
    // A few xorshifts: good enough to decorrelate low bits of PCs.
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    return (uint32_t)x;
}

// === TB execution callback FUCKING QEMU 7.2: (qemu_plugin_vcpu_udata_cb_t)
// Called on TB execution;
// receives vCPU index
// and the per TB udata we attached at translate time.
static void tb_exec_cb(unsigned int vcpu_index, void *udata)
{
    // Recover the precomputed "current location" value from udata.
    uint32_t cur = (uint32_t)(uintptr_t)udata;

    // AFL-style edge index: prev_loc XOR cur_loc (then mask into the bitmap).
    uint32_t idx = (prev_loc ^ cur) & map_mask;

    // Saturating increment of an 8-bit counter at that index.
    // (This enables hitcount buckets which are useful guidance for fuzzers.)
    uint8_t v = bitmap[idx];
    bitmap[idx] = (v == 255) ? 255 : (uint8_t)(v + 1);

    // Prepare for the next edge: right-shift the current loc to decorrelate.
    prev_loc = cur >> 1;
}

// Register per-TB exec callback during translation and pass per-TB udata.
static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    uint32_t cur = mix64(pc);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec_cb, QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)(uintptr_t)cur);
}

// === Plugin entry point ===
// QEMU loads the shared object and calls this once.
// We parse arguments, map the SHM region, and register our TB translation callback.
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    // Expected args:
    //   argv[0] : shm name (e.g., "/comp6447_cov")
    //   argv[1] : optional "off=<bytes>"  (offset into SHM where bitmap lives)
    //   argv[2] : optional "len=<bytes>"  (bitmap length; default 65536)

    // TODO: Dont hardcode this, just make it shared across all function
    const char *SHM_PATH = "/comp6447_fuzzer_shm";
    size_t off = 0;

    // 1) Parse args
    if (argc > 0 && argv[0] && argv[0][0])
        SHM_PATH = argv[0];
    for (int i = 1; i < argc; i++)
    {
        if (!strncmp(argv[i], "off=", 4))
        {
            off = (size_t)strtoull(argv[i] + 4, 0, 0);
        }
        else if (!strncmp(argv[i], "len=", 4))
        {
            map_len = (size_t)strtoull(argv[i] + 4, 0, 0);
            map_mask = (uint32_t)(map_len - 1);
        }
        // TODO: parse text_lo/text_hi here to restrict PCs.
    }

    // 2) Open the existing SHM.
    int fd = shm_open(SHM_PATH, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        perror("plugin shm_open");
        return 1;
    }

    // 3) Map enough bytes to cover [off .. off+map_len).
    void *p = mmap(NULL, off + map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
    {
        perror("plugin mmap");
        return 2;
    }

    // 4) Our bitmap pointer to the specified offset.
    bitmap = (uint8_t *)p + off;

    // 5) Register a translation callback; per TB we attach an exec callback with udata.
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);

    return 0;
}
