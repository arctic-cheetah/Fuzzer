#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <atomic>
#include <map>
#include <string.h>
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <iostream>
#include "harness.h"
#include <errno.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <print>
#include <list>

#if USE_QEMU
#include <qemu-plugin.h>
#else
#include <sys/ptrace.h>
#endif

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

void execute_task_ptrace(std::string binary){
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        std::print(std::cout, "waiting for ptrace\n");
        asm volatile("int3");
        std::print(std::cout, "starting {}\n", binary);

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
                std::print(std::cerr, "trapped: {}\n", strsignal(sig));

                if (sig != SIGTRAP) {
                    if (sig == SIGSEGV || sig == SIGABRT || sig == SIGFPE) {
                        std::print(std::cerr, "Crashed with signal: {}\n", strsignal(sig));

                        signal = sig;
                        registers = get_registers(pid);
                        break;
                    } else {
                        std::print(std::cerr, "Continuing after signal: {}\n", strsignal(sig));
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
            std::print(std::cerr, "Crash detected!\n");
            std::print(R"({{ "signal": {}, "registers": {{)", signal);

            bool first = true;
            for (const auto& [reg, value] : registers) {
                if (!first) {
                    std::print(", ");
                } else {
                    first = false;
                }

                std::print(R"("{}": {})", reg, value);
            }
            std::print(R"(}}, "return_code": {} }})", WEXITSTATUS(status));

            auto rbp = registers["rbp"];
            auto rsp = registers["rsp"];

            std::print(std::cerr, "RBP: {:#x}, RSP: {:#x}\n", rbp, rsp);

            // make a trace
            std::list<uint64_t> stack_trace;
            
            uint64_t current_rbp = rbp;
            while (current_rbp != 0) {
                auto return_address = ptrace(PTRACE_PEEKDATA, pid, current_rbp + 8, nullptr);
                stack_trace.push_back(return_address);
                current_rbp = ptrace(PTRACE_PEEKDATA, pid, current_rbp, nullptr);
            }

            std::print(std::cerr, "Stack trace:\n");
            for (const auto& addr : stack_trace) {
                std::print(std::cerr, "  {:#x}\n", addr);
            }

            system(std::format("cat /proc/{}/maps", pid).c_str());
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }

    execute_task_ptrace(argv[1]);

    return 0;

}
