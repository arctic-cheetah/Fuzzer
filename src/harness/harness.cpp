#include <assert.h>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <fstream>
#include <mutex>
#include <stdio.h>
#include <stdlib.h>
#include <string>
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
#include <stack>
#include <thread>

#include "cppzmq/zmq.hpp"

#include <sys/ptrace.h>

#include "hash.h"
#include "elf.h"
#include "region.h"

#define debug_print(...) std::print(stderr, __VA_ARGS__)

#define IPC_MSG_LEN 1024
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

struct job_result {
    int return_code;
    int pid;

    std::map<std::string, uint64_t> registers;
    std::vector<memory_region> regions;

    enum {
        exit,
        timeout,
        signal,
    } status;

    struct {
        int signal;
        std::map<std::string, uint64_t> registers;
        std::list<uint64_t> stack_trace;
        uint64_t hash;
    } crash_info;

    static job_result exited(int return_code, int pid) {
        return job_result{
            .return_code = return_code,
            .pid = pid,
            .status = exit
        };
    }

    static job_result timed_out(int pid) {
        return job_result{
            .pid = pid,
            .status = timeout
        };
    }

    static job_result crashed(int signal, std::map<std::string, uint64_t> registers,
                             std::list<uint64_t> stack_trace, uint64_t hash, int pid) {
        return job_result{
            .pid = pid,
            .status = job_result::signal,
            .crash_info = {
                .signal = signal,
                .registers = registers,
                .stack_trace = stack_trace,
                .hash = hash
            }
        };
    }
};

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

struct job_result execute_task_ptrace(elf_exe_cache &cache, std::string binary, int pipe_fd){
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

        close(STDIN_FILENO);
        dup2(pipe_fd, STDIN_FILENO);
        close(pipe_fd);

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
                debug_print("exited with status: {}\n", WEXITSTATUS(status));
                return job_result::exited(WEXITSTATUS(status), pid);
            }

            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);
                debug_print("trapped: {}\n", strsignal(sig));

                if (sig != SIGTRAP) {
                    if (sig == SIGSEGV || sig == SIGABRT || sig == SIGFPE) {
                        debug_print("Crashed with signal: {}\n", strsignal(sig));

                        signal = sig;
                        registers = get_registers(pid);
                        break;
                    } else {
                        debug_print("Continuing after signal: {}\n", strsignal(sig));
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

            debug_print("Crash detected!\n");

            auto rbp = registers["rbp"];
            auto rsp = registers["rsp"];

            debug_print("RBP: {:#x}, RSP: {:#x}\n", rbp, rsp);

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

            debug_print("Stack trace hash: {:#x}\n", hash);

            debug_print("Stack trace:\n");
            for (const auto& addr : stack_trace) {
                auto *region = region_for_address(regions, addr);
                if (region) {
                    debug_print("  {:#x} ({}+{:#x})\n", addr, region->pathname,
                               addr - region->start + region->offset);
                } else {
                    debug_print("  {:#x} (unknown region)\n", addr);
                }
            }

            system(std::format("cat /proc/{}/maps", pid).c_str());

            FILE *auxv_file = fopen(std::format("/proc/{}/auxv", pid).c_str(), "rb");
            if (!auxv_file) {
                perror("fopen auxv");
                exit(1);
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
                exit(1);
            }

            std::print(".text base: {:#x}\n", u.start_code);

            return job_result::crashed(signal, registers, stack_trace, hash, pid);
        }
    }

    __builtin_unreachable();
}

void write_dump(std::ostream &dumpfile, const job_result &result) {
    std::print(dumpfile, R"({{ "pid": {}, "status": "{}", )", result.pid,
               result.status == job_result::exit ? "exited" :
               result.status == job_result::timeout ? "timeout" : "signal");

    if (result.status == job_result::exit) {
        std::print(dumpfile, R"("return_code": {} )", result.return_code);
    } else if (result.status == job_result::timeout) {
        // nothing more to add
    } else if (result.status == job_result::signal) {
        std::print(dumpfile, R"("signal": {}, "hash": "{:x}", "registers": {{)",
                   result.crash_info.signal, result.crash_info.hash);

        bool first = true;
        for (const auto& [reg, value] : result.crash_info.registers) {
            if (!first) {
                std::print(dumpfile, ", ");
            } else {
                first = false;
            }

            std::print(dumpfile, R"("{}": {})", reg, value);
        }
        std::print(dumpfile, R"(}}, "stack_trace": [)");

        first = true;
        for (const auto& addr : result.crash_info.stack_trace) {
            if (!first) {
                std::print(dumpfile, ", ");
            } else {
                first = false;
            }

            std::print(dumpfile, R"({})", addr);
        }
        std::print(dumpfile, R"(] )");
    }

    std::print(dumpfile, R"(}})");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::print(stderr, "Usage: {} <num-of-threads>\n", argv[0]);
        return 1;
    }

    struct job {
        std::string binary;
    };

    int num_threads = atoi(argv[1]);
    assert(num_threads > 0);

    // create the named pipes so the python fuzzer can
    // give input to the binary

    std::list<std::string> pipes;
    for (int i = 0; i < num_threads; i++) {
        auto name = (std::format("/tmp/fuzzer-{}", i));

        if (mkfifo(name.c_str(), 0666) < 0) {
            perror("mkfifo");
            return 1;
        }

        pipes.push_back(name);
    }

    zmq::context_t ctx{1};
    zmq::socket_t socket{ctx, zmq::socket_type::rep};
    zmq::socket_t event_socket{ctx, zmq::socket_type::pub};

    socket.bind("ipc:///tmp/fuzzer");
    event_socket.bind("ipc:///tmp/fuzzer-events");

    std::mutex event_socket_mutex;
    std::mutex job_mutex;
    std::condition_variable jobs_on_queue;
    std::condition_variable job_queue_empty;

    std::map<std::string, std::thread> threads;
    std::deque<job> jobs;

    elf_exe_cache cache;

    auto runner_thread = [&](std::string pipe) {
        auto fd = open(pipe.c_str(), O_RDONLY);
        if (fd < 0) {
            perror("open");
            return 1;
        }

        for (;;) {
            std::string binary;
            {
                std::unique_lock lock{job_mutex};
                // get a job off the queue
                jobs_on_queue.wait(lock, [&jobs]() {
                    return !jobs.empty();
                });

                auto job = std::move(jobs.front());
                jobs.pop_front();

                binary = job.binary;

                socket.send(zmq::buffer(pipe), zmq::send_flags::none);

                job_queue_empty.notify_one();
            }

            // run the binary
            auto res = execute_task_ptrace(cache, binary, fd);
            
            {
                std::unique_lock lock{event_socket_mutex};
                auto msg = std::string{};
                {
                    std::ostringstream oss;
                    write_dump(oss, res);
                    msg = oss.str();
                }
                event_socket.send(zmq::buffer(msg), zmq::send_flags::none);
            }
        }
    };

    std::thread thread = std::thread(runner_thread, pipes.front());

    for (;;) {
        zmq::message_t request{IPC_MSG_LEN};

        std::unique_lock lock{job_mutex};
        job_queue_empty.wait(lock, [&jobs]() {
            return jobs.empty();
        });

        // Wait for the next request from client
        auto res = socket.recv(request, zmq::recv_flags::none);
        if (!res) {
            // probably got an EAGAIN
            continue;
        }

        auto size = res.value();
        assert(size <= IPC_MSG_LEN);

        // <cmd>;<args>
        auto msg = std::string(static_cast<char *>(request.data()), size);
        
        auto delimiter_pos = msg.find(';');
        auto cmd = msg.substr(0, delimiter_pos);
        
        if (cmd == "exec") {
            auto binary = msg.substr(delimiter_pos + 1);
            
            jobs.push_back(job{.binary = binary});
            jobs_on_queue.notify_one();
        }
    }

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
