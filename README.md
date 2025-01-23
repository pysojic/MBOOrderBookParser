# MBO PCAP Parser

**MBO PCAP Parser** is a high-performance C++ application designed to parse PCAP files from the Exchange (current implementation is based on the CBOE Future Exchange), reconstruct MBO order books, and can be used to identify arbitrage opportunities and trading signals. It is optimized for macOS and Unix-like systems and uses CMake for build management.

## Features
- Parses PCAP data captured from the exchange network.
- Reconstructs MBO (L3) order books.
- Can exports reconstructed data for further analysis.
- Highly optimized for performance with `-O3` and `-march=native` compiler flags.

## Requirements
- macOS or Unix-like system.
- GCC or Clang (optional).
- [libpcap](https://www.tcpdump.org/) (PCAP library for parsing packet data).
- CMake (minimum version 3.14).

## Build Instructions

### Prerequisites
1. Install GCC or Clang.
   - GCC example:
     ```zsh
     brew install gcc
     ```
   - Clang example (optional):
     ```zsh
     brew install llvm
     ```
    
2. Install `CMake`:
   ```zsh
   brew install cmake
   ```

3. Install `libpcap` (if not already installed):
   ```zsh
   brew install libpcap
   ```
4. Install Boost C++ Libraries (https://www.boost.org/):
   ```zsh
   brew install boost
   ```

### Compilation
1. Clone the repository
  ```zsh
  git clone https://github.com/your-username/MBOOrderBookParser.git
  cd MBOOrderBookParser
  ```
2. Create a build directory:
  ```zsh
  mkdir build
  cd build
  ```
3. Configure the project with CMake:
  ```zsh
  cmake ..
  ```
4. Build the project:
  ```zsh
  cmake --build build
  ```

### Run the Program
After a successful build, the executable will be generated in the build directory. Run the following line to get the program usage:
  ```zsh
  build/MBOOrderBookParser --help
  ```

## Project Structure

```
MBOOrderBookParser/

├── build/ Build directory (generated after CMake)

├── include/

│   ├── CBOEPcapParser.hpp       # Pcap Parser 

│   ├── cfepitch.h               # CFE pitch specs

│   ├── Config.hpp               # Configuration of program options

│   ├── cxxopts.hpp              # Program options parser lib

│   ├── DataExporter.hpp         # Exporter of data (csv, bin, etc)

│   ├── MessageInfo.hpp          # Information struct

│   ├── Order.hpp                # Individual order class 

│   ├── OrderBook.hpp            # Individual order book class 

│   ├── OrderBookManager.hpp     # Order books manager class

│   ├── OrderStore.hpp           # Order objects store class

│   ├── StopWatch.hpp            # Timer

│   ├── Symbol.hpp               # Ticker symbol struct

│   └── ThreadPool.hpp           # Thread pool class

├── misc/ 

│   └── cfe-pitch.lua            # lua script dissector for Wireshark 

├── ref/ 

│   └── CFE Multicast PITCH Spec v1.2.8 2024-08-09.pdf        # CFE Pitch specs 

├── src/

│   ├── CBOEPcapParser.cpp       # Pcap Parser implementation

│   ├── DataExporter.cpp         # Exporter of data (csv, bin, etc) implementation

│   ├── main.cpp                 # Program entry point

│   ├── Order.cpp                # Individual order class implementation

│   ├── OrderBook.cpp            # Individual order book class implementation

│   ├── OrderBookManager.cpp     # Order books manager class implementation

│   ├── OrderStore.cpp           # Order objects store class implementation

│   ├── StopWatch.cpp            # Timer implementation

│   └── ThreadPool.cpp           # Thread pool class implementation
```
   

