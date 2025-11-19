#pragma once

#include <stdint.h>
#include <stddef.h>
#include <list>

// FNV hash function implementation
namespace detail {

static constexpr uint32_t fnv_offset_32 = 0x811c9dc5;
static constexpr uint32_t fnv_prime_32 = 0x1000193;
static constexpr uint64_t fnv_offset_64 = 0xcbf29ce484222325;
static constexpr uint64_t fnv_prime_64 = 0x100000001b3;

consteval inline uint64_t bytes_hash(const char *str, size_t len, uint64_t hash) {
    if (len == 0) {
        return hash;
    }

    hash = (hash ^ *str) * detail::fnv_prime_64;

    return bytes_hash(str + 1, len - 1, hash);
}

constexpr inline uint64_t u64_hash(uint64_t val, uint64_t hash) {
    hash = (hash ^ (val & 0xff)) * detail::fnv_prime_64;
    hash = (hash ^ ((val >> 8) & 0xff)) * detail::fnv_prime_64;
    hash = (hash ^ ((val >> 16) & 0xff)) * detail::fnv_prime_64;
    hash = (hash ^ ((val >> 24) & 0xff)) * detail::fnv_prime_64;
    hash = (hash ^ ((val >> 32) & 0xff)) * detail::fnv_prime_64;
    hash = (hash ^ ((val >> 40) & 0xff)) * detail::fnv_prime_64;
    hash = (hash ^ ((val >> 48) & 0xff)) * detail::fnv_prime_64;
    hash = (hash ^ ((val >> 56) & 0xff)) * detail::fnv_prime_64;

    return hash;
}

}

consteval inline uint64_t fnv1a_hash(const void *bytes, size_t len) {
    return detail::bytes_hash((const char *)bytes, len, detail::fnv_offset_64);
}

inline uint64_t hash_trace(const std::list<uint64_t>& trace) {
    uint64_t hash = detail::fnv_offset_64;
    for (const auto& addr : trace) {
        hash = detail::u64_hash(addr, hash);
    }
    return hash;
}
