cmake_minimum_required(VERSION 3.14)
project(MBOOrderBookParser LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_COMPILER "/opt/homebrew/bin/g++-14")
#set(CMAKE_CXX_COMPILER "/opt/homebrew/opt/llvm/bin/clang++")

message(STATUS "C++ Compiler: ${CMAKE_CXX_COMPILER}")

# Specify the source files
set(SOURCES
    src/main.cpp
    src/CBOEPcapParser.cpp
    src/DataExporter.cpp
    src/Order.cpp
    src/OrderBook.cpp
    src/OrderBookManager.cpp
    src/OrderStore.cpp
    src/StopWatch.cpp
    #src/ThreadPool.cpp
)

add_executable(MBOOrderBookParser ${SOURCES})

# Add warnings for GCC/Clang
target_compile_options(MBOOrderBookParser PRIVATE -O3 -march=native) # Use for debug: -O0 -g -Wall -Wextra -Wpedantic

target_include_directories(MBOOrderBookParser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include /opt/homebrew/include)

# Find and link the pcap library
find_library(PCAP_LIB pcap REQUIRED)  # Find the pcap library; this sets PCAP_LIB variable

# Link the found library
target_link_libraries(MBOOrderBookParser PRIVATE ${PCAP_LIB})