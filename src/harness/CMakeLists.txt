project(fuzzer-harness)

enable_language(CXX)
set(CMAKE_CXX_STANDARD 23)

add_subdirectory(cppzmq)

add_executable(harness
    harness.cpp
)

target_link_libraries(harness
    PRIVATE
        zmq
)
