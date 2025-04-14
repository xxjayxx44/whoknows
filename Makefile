# Compiler and flags
CXX       = g++
CXXFLAGS  = -std=c++17 -O3 -march=native -Wall -Wextra

# Linker flags
LDLIBS    = -lsecp256k1 -lssl -lcrypto

# Target binary
TARGET    = bitcoin_scanner

# Source file
SRC       = bitcoin_scanner.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET) address.txt
