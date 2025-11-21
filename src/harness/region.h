#pragma once

#include <stdint.h>
#include <string>
#include <vector>

struct memory_region {
    uint64_t start;
    uint64_t end;
    std::string permissions;
    uint64_t offset;
    std::string pathname;
};

std::vector<memory_region> get_memory_regions(pid_t pid);
memory_region *region_for_address(std::vector<memory_region> &regions, uint64_t address);
