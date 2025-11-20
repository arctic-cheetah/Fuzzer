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
#include <unordered_map>
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

#ifdef DEBUG
#define debug_print(...) std::print(stderr, __VA_ARGS__)
#else
#define debug_print
#endif

#define IPC_MSG_LEN 1024
#define MAX_PROCCESSES 128
#define PROCESS_TIMEOUT 500

struct job_result get_crash_result_for_pid(int pid, int sig, elf_exe_cache &cache, std::string binary_path);

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

pid_t execute_task_ptrace(elf_exe_cache &cache, std::string binary, int pipe_fd){
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
        raise(SIGSTOP);

        // replace stdout with /dev/null for now
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null == -1) {
            perror("open /dev/null");
            exit(EXIT_FAILURE);
        }

        dup2(dev_null, STDOUT_FILENO);
        dup2(dev_null, STDERR_FILENO);
        close(dev_null);

        close(STDIN_FILENO);
        dup2(pipe_fd, STDIN_FILENO);
        close(pipe_fd);

        execl(binary.c_str(), binary.c_str(), nullptr);
        perror("execl");
        exit(EXIT_FAILURE);
    }

    debug_print("Started process with PID: {}\n", pid);
    return pid;
}

void write_dump(std::ostream &dumpfile, const job_result &result) {
    if (result.status == job_result::exit) {
        // no need to dump successful exits
        dumpfile << std::format("{}", result.pid);
        return;
    }

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
    zmq::context_t ctx{1};
    zmq::socket_t socket{ctx, zmq::socket_type::rep};
    zmq::socket_t event_socket{ctx, zmq::socket_type::pub};

    socket.bind("ipc:///tmp/fuzzer");
    event_socket.bind("ipc:///tmp/fuzzer-events");

    std::map<std::string, std::thread> threads;

    elf_exe_cache cache;

    std::mutex pid_mutex;
    std::condition_variable should_waitpid;
    std::condition_variable pid_handled;

    std::list<pid_t> running_pids;
    std::unordered_map<pid_t, bool> attached;
    std::unordered_map<pid_t, std::string> pid_to_binary;

    std::mutex results_mutex;
    std::condition_variable pending_results;
    std::deque<job_result> results;

    auto waitpid_loop = [&]() {
        for (;;) {
            {
                std::unique_lock lock{pid_mutex};
                should_waitpid.wait(lock, [&]() {
                    return !running_pids.empty();
                });
            }

            int status;
            debug_print("waiting for children\n");
            pid_t pid = waitpid(-1, &status, WUNTRACED);
            if (pid < 0) {
                if (errno == ECHILD) {
                    // no more child processes
                    debug_print("No child processes\n");
                    continue;
                } else {
                    perror("waitpid");
                    exit(1);
                }
            }

            if (pid == 0) {
                continue;
            }
            
            debug_print("waitpid got pid: {}\n", pid);

            std::optional<job_result> result;

            if (WIFEXITED(status)) {
                debug_print("pid {} exited with status: {}\n", pid, WEXITSTATUS(status));

                result = job_result::exited(WEXITSTATUS(status), pid);
            } else if (WIFSTOPPED(status)) {
                auto sig = WSTOPSIG(status);
                debug_print("pid {} stopped by signal: {}\n", pid, strsignal(sig));

                std::unique_lock lock{pid_mutex};
                if (!attached[pid]) {
                    if (sig != SIGSTOP) {
                        ptrace(PTRACE_CONT, pid, nullptr, sig);
                        continue;
                    }

                    debug_print("Attaching to pid: {}\n", pid);
                    if (ptrace(PTRACE_SEIZE, pid, nullptr, 0) < 0) {
                        perror("ptrace seize");
                        exit(1);
                    }

                    attached[pid] = true;
                    ptrace(PTRACE_CONT, pid, nullptr, 0);
                    continue;
                }
                lock.unlock();

                if (sig == SIGSEGV || sig == SIGABRT || sig == SIGFPE) {
                    debug_print("pid {} crashed with signal: {}\n", pid, strsignal(sig));

                    result = get_crash_result_for_pid(pid, sig, cache, pid_to_binary[pid]);

                    ptrace(PTRACE_KILL, pid, nullptr, nullptr);
                    debug_print("Killed pid: {} after crash\n", pid);
                } else if (sig == SIGTRAP) {
                    ptrace(PTRACE_CONT, pid, nullptr, 0);
                    continue;  
                } else if (sig == SIGSTOP) {
                    ptrace(PTRACE_CONT, pid, nullptr, 0);
                    continue;
                } else {
                    debug_print("Continuing after signal: {}\n", strsignal(sig));
                    ptrace(PTRACE_CONT, pid, nullptr, sig);
                    continue;
                }
            } else if (WIFSIGNALED(status)) {
                auto sig = (WTERMSIG(status));
                debug_print("pid {} exited with signal: {}\n", pid, strsignal(sig));

                // 'when a program is terminated by an uncaught signal,
                // the exit status is calculated as 128 + <signal number>'
                result = job_result::exited(128 + sig, pid);
            }

            if (result) {
                {
                    std::unique_lock lock{results_mutex};
                    results.push_back(*result);
                    lock.unlock();
                    pending_results.notify_one();
                }

                {
                    std::unique_lock lock{pid_mutex};
                    running_pids.remove(pid);
                    attached.erase(pid);
                    pid_to_binary.erase(pid);
                    pid_handled.notify_one();
                }
            }
        }
    };

    auto broadcast_loop = [&]() {
        for (;;) {
            std::unique_lock lock{results_mutex};
            pending_results.wait(lock, [&]() {
                return !results.empty();
            });

            auto result = results.front();
            results.pop_front();
            lock.unlock();

            auto msg = std::string{};
            {
                auto s = std::ostringstream{};
                write_dump(s, result);
                msg = s.str();
            }

            debug_print("Broadcasting event: {}\n", msg);

            zmq::message_t event_msg{msg.size()};
            memcpy(event_msg.data(), msg.data(), msg.size());

            event_socket.send(event_msg, zmq::send_flags::none);
        }
    };

    std::thread waitpid_thread = std::thread(waitpid_loop);
    std::thread broadcast_thread = std::thread(broadcast_loop);

    debug_print("Harness is ready to receive jobs\n");
    for (;;) {
        zmq::message_t request{IPC_MSG_LEN};

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

        debug_print("Received message: {}\n", msg);
        
        // "exec;<binary>;<pipe>"
        auto delimiter_pos = msg.find(';');
        auto cmd = msg.substr(0, delimiter_pos);
        
        if (cmd == "exec") {
            zmq::message_t reply;
            auto next_delim = msg.find(';', delimiter_pos + 1);
            auto binary = msg.substr(delimiter_pos + 1, next_delim - delimiter_pos - 1);
            auto pipe_name = msg.substr(next_delim + 1);

            int fd = open(pipe_name.c_str(), O_RDONLY);
            if (fd < 0) {
                perror("open pipe");
                exit(1);
            }

            pid_t pid;
            {
                std::unique_lock lock{pid_mutex};

                //pid = execute_task_ptrace(cache, binary, fd);
                pid = 1;
                attached[pid] = false;
                close(fd);

                if (pid == 0) { // failed
                    socket.send(zmq::message_t("0"), zmq::send_flags::none);
                    continue;
                }

                std::unique_lock result_lock{results_mutex};
                results.push_back(job_result::exited(0, pid));
                pending_results.notify_one();

                //running_pids.push_back(pid);
               // pid_to_binary[pid] = binary;
                //should_waitpid.notify_one();
            }

            // reply with the pid
            reply = zmq::message_t(std::to_string(pid));

            // Send reply back to client
            socket.send(reply, zmq::send_flags::none);
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

job_result get_crash_result_for_pid(int pid, int sig, elf_exe_cache &cache, std::string binary_path) {
    auto *exe = cache.get_executable(binary_path);
    if (!exe) {
        debug_print("Failed to get executable for pid: {}\n", pid);
        exit(1);
    }

    auto registers = get_registers(pid);
    auto regions = get_memory_regions(pid);

    auto rbp = registers["rbp"];
    auto rsp = registers["rsp"];

    // make a trace
    std::list<uint64_t> stack_trace {registers["rip"]};
    
    uint64_t current_rbp = rbp;
    int max_frames = 128;
    while (current_rbp != 0) {
        debug_print("Reading stack frame at RBP: {:#x}\n", current_rbp);
        auto return_address = ptrace(PTRACE_PEEKDATA, pid, current_rbp + 8, nullptr);
        stack_trace.push_back(return_address);
        
        auto new_rbp = ptrace(PTRACE_PEEKDATA, pid, current_rbp, nullptr);
        if (new_rbp == current_rbp) {
            break;
        }
        current_rbp = new_rbp;

        if (--max_frames == 0) {
            debug_print("Max stack frames reached\n");
            break;
        }
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

    return job_result::crashed(sig, registers, stack_trace, hash, pid);
}

memory_region *region_for_address(std::vector<memory_region> &regions, uint64_t address) {
    for (auto &region : regions) {
        if (address >= region.start && address < region.end) {
            return &region;
        }
    }
    return nullptr;
}
