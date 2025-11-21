#pragma once

#include <elf.h>
#include <stdio.h>
#include <stdint.h>

#include <print>
#include <string>
#include <vector>
#include <map>
#include <memory>

struct elf_auxv {
    uint64_t interpreter_base;
    uint64_t program_hdr_base;
};

struct elf_executable {
    static elf_executable load(const std::string &filepath) {
        FILE *f = fopen(filepath.c_str(), "r");
        if (!f) {
            perror("fopen");
            exit(1);
        }

        Elf64_Ehdr header;
        if (fread(&header, sizeof(Elf64_Ehdr), 1, f) != 1) {
            if (ferror(f)) {
                perror("fread");
            } else {
                std::print(stderr, "Unexpected end of file\n");
            }
            exit(1);
        }

        auto ph_offset = header.e_phoff;
        auto ph_count = header.e_phnum;

        std::vector<Elf64_Phdr> program_headers;
        fseek(f, ph_offset, SEEK_SET);

        for (size_t i = 0; i < ph_count; ++i) {
            Elf64_Phdr ph;
            if (fread(&ph, sizeof(Elf64_Phdr), 1, f) != 1) {
                if (ferror(f)) {
                    perror("fread");
                } else {
                    std::print(stderr, "Unexpected end of file\n");
                }
                exit(1);
            }
            program_headers.push_back(ph);
        }

        return {
            header,
            std::move(program_headers)
        };
    }

    Elf64_Ehdr header;
    std::vector<Elf64_Phdr> program_headers;
};

inline elf_auxv get_important_auxv(std::vector<Elf64_auxv_t> &buf) {
    elf_auxv auxv = {};

    for (const auto &entry : buf) {
        switch (entry.a_type) {
            case AT_BASE:
                auxv.interpreter_base = entry.a_un.a_val;
                break;
            case AT_PHDR:
                auxv.program_hdr_base = entry.a_un.a_val;
                break;
            case AT_NULL:
                return auxv;
            default:
                break;
        }
    }

    return auxv;
}

struct elf_exe_cache {
    elf_executable *get_executable(std::string path) {
        auto it = cache.find(path);
        if (it != cache.end()) {
            return it->second.get();
        }

        auto exe = elf_executable::load(path);
        auto ptr = std::make_unique<elf_executable>(std::move(exe));

        auto ret = ptr.get();
        cache[path] = std::move(ptr);
        return ret;
    };

    std::map<std::string, std::unique_ptr<elf_executable>> cache;
};

inline uint64_t figure_out_image_base(const elf_executable &exe, const elf_auxv &auxv) {
    return auxv.program_hdr_base - exe.header.e_phoff;
}
