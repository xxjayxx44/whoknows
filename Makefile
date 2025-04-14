# Compiler
CXX = g++
CXXFLAGS = -std=c++17 -O3

# Output binary
TARGET = bitcoin_scanner

# Source file
SRC = bitcoin_scanner.cpp

# Libraries
LDLIBS = -lsecp256k1 -lssl -lcrypto

# Build target
all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

# Clean
clean:
	rm -f $(TARGET)
