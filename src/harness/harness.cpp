#include <cstdint>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <map>
#include <string.h>
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <iostream>
#include "harness.h"
#include <sys/wait.h>
#include <sys/user.h>
#include <print>
#include <list>
#include <elf.h>
#include <vector>

#include <sys/ptrace.h>

#include "hash.h"
#include "elf.h"
#include "region.h"

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
static const char *SHM_PATH = "/comp6447_fuzzer_shm";

int init_shared_memory();

std::map<std::string, uint64_t> get_registers(pid_t pid) {
    auto regs = user_regs_struct{};
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    return {
        {"rax", regs.rax}, {"rbx", regs.rbx}, {"rcx", regs.rcx},
        {"rdx", regs.rdx}, {"rsi", regs.rsi}, {"rdi", regs.rdi},
        {"rbp", regs.rbp}, {"rsp", regs.rsp}, {"rip", regs.rip},
        {"r8", regs.r8}, {"r9", regs.r9}, {"r10", regs.r10},
        {"r11", regs.r11}, {"r12", regs.r12}, {"r13", regs.r13},
        {"r14", regs.r14}, {"r15", regs.r15}
    };
}

void execute_task_ptrace(elf_exe_cache &cache, std::string binary){
    char *real_path = realpath(binary.c_str(), nullptr);
    if (!real_path) {
        perror("realpath");
        exit(EXIT_FAILURE);
    }

    auto exe = cache.get_executable(real_path);
    
    free(real_path);

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        std::print(stderr, "waiting for ptrace\n");
        asm volatile("int3");
        std::print(stderr, "starting {}\n", binary);

        // replace stdout with /dev/null for now
        close(STDOUT_FILENO);
        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null == -1) {
            perror("open /dev/null");
            exit(EXIT_FAILURE);
        }

        dup2(dev_null, STDOUT_FILENO);
        close(dev_null);

        // Execute the binary with input data
        execl(binary.c_str(), binary.c_str(), nullptr);
        perror("execl");
        exit(EXIT_FAILURE);
    } else {
        ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);

        int status;
        int signal = 0;
        std::map<std::string, uint64_t> registers;

        while (true) {
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                std::print(std::cerr, "exited with status: {}\n", WEXITSTATUS(status));
                break; // Child has exited
            }

            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);
                std::print(stderr, "trapped: {}\n", strsignal(sig));

                if (sig != SIGTRAP) {
                    if (sig == SIGSEGV || sig == SIGABRT || sig == SIGFPE) {
                        std::print(stderr, "Crashed with signal: {}\n", strsignal(sig));

                        signal = sig;
                        registers = get_registers(pid);
                        break;
                    } else {
                        std::print(stderr, "Continuing after signal: {}\n", strsignal(sig));
                        ptrace(PTRACE_CONT, pid, nullptr, sig);
                        continue;
                    }
                }

                ptrace(PTRACE_CONT, pid, nullptr, nullptr);
                continue;
            }

            ptrace(PTRACE_CONT, pid, nullptr, nullptr);
        }

        if (signal != 0) {
            auto regions = get_memory_regions(pid);

            std::print(std::cerr, "Crash detected!\n");

            auto rbp = registers["rbp"];
            auto rsp = registers["rsp"];

            std::print(std::cerr, "RBP: {:#x}, RSP: {:#x}\n", rbp, rsp);

            // make a trace
            std::list<uint64_t> stack_trace {registers["rip"]};
            
            uint64_t current_rbp = rbp;
            while (current_rbp != 0) {
                auto return_address = ptrace(PTRACE_PEEKDATA, pid, current_rbp + 8, nullptr);
                stack_trace.push_back(return_address);
                current_rbp = ptrace(PTRACE_PEEKDATA, pid, current_rbp, nullptr);
            }

            std::list<uint64_t> trace_offsets;
            for (const auto& addr : stack_trace) {
                auto *region = region_for_address(regions, addr);
                if (region) {
                    trace_offsets.push_back(addr - region->start + region->offset);
                } else {
                    trace_offsets.push_back(addr);
                }
            }

            auto hash = hash_trace(trace_offsets);

            std::print(std::cerr, "Stack trace hash: {:#x}\n", hash);

            std::print(std::cerr, "Stack trace:\n");
            for (const auto& addr : stack_trace) {
                auto *region = region_for_address(regions, addr);
                if (region) {
                    std::print(std::cerr, "  {:#x} ({}+{:#x})\n", addr, region->pathname,
                               addr - region->start + region->offset);
                } else {
                    std::print(std::cerr, "  {:#x} (unknown region)\n", addr);
                }
            }

            system(std::format("cat /proc/{}/maps", pid).c_str());

            FILE *auxv_file = fopen(std::format("/proc/{}/auxv", pid).c_str(), "rb");
            if (!auxv_file) {
                perror("fopen auxv");
                return;
            }
            
            std::vector<Elf64_auxv_t> auxv_data;

            size_t read_bytes;
            Elf64_auxv_t entry;
            while ((read_bytes = fread(&entry, sizeof(Elf64_auxv_t), 1, auxv_file)) == 1){
                auxv_data.push_back(entry);
            }

            auto auxv = get_important_auxv(auxv_data);
            auto image_base = figure_out_image_base(*exe, auxv);

            std::print("image base: {:#x}\n", image_base);

            struct user u;
            if (ptrace(PTRACE_PEEKUSER, pid, nullptr, &u) < 0) {
                perror("ptrace PEEKUSER");
                return;
            }

            std::print(".text base: {:#x}\n", u.start_code);

            auto log_filepath = std::format("fuzzer-{:x}-{}.json", hash, pid);
            std::print(std::cerr, "Writing crash log to: {}\n", log_filepath);

            std::ofstream dumpfile;
            dumpfile.open(log_filepath, std::ios::out);

            std::print(dumpfile, R"({{ "hash": "{:x}", "pid": {}, "signal": {}, "registers": {{)", hash, pid, signal);

            bool first = true;
            for (const auto& [reg, value] : registers) {
                if (!first) {
                    std::print(dumpfile, ", ");
                } else {
                    first = false;
                }

                std::print(dumpfile, R"("{}": {})", reg, value);
            }
            std::print(dumpfile, R"(}}, "return_code": {} }})", WEXITSTATUS(status));
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }

    elf_exe_cache cache;
    execute_task_ptrace(cache, argv[1]);

    return 0;

}

std::vector<memory_region> get_memory_regions(pid_t pid) {
    std::vector<memory_region> regions;
    std::ifstream maps_file(std::format("/proc/{}/maps", pid));
    std::string line;

    while (std::getline(maps_file, line)) {
        memory_region region;
        uint64_t offset;

        // split the line by spaces
        auto parts = std::vector<std::string>{};
        std::string part;
        auto start = line.begin();
        auto it = line.begin();
        while (it != line.end()) {
            auto start = it;
            while (it != line.end() && *it != ' ') {
                it++;
            }
            parts.push_back(std::string(start, it));
            while (it != line.end() && *it == ' ') {
                it++;
            }
        }

        sscanf(parts[0].c_str(), "%lx-%lx", &region.start, &region.end);
        sscanf(parts[2].c_str(), "%lx", &region.offset);
        region.permissions = parts[1];

        // some mappings don't have a pathname??
        region.pathname = parts.size() >= 6 ? parts[5] : "";

        regions.push_back(region);
    }

    return regions;
}

memory_region *region_for_address(std::vector<memory_region> &regions, uint64_t address) {
    for (auto &region : regions) {
        if (address >= region.start && address < region.end) {
            return &region;
        }
    }
    return nullptr;
}
