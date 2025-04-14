# Makefile

CXX       = g++
CXXFLAGS  = -std=c++17 -O3 -march=native -Wall -Wextra
LDLIBS    = -lsecp256k1 -lssl -lcrypto -lz

TARGET    = bitcoin_scanner
SRC       = bitcoin_scanner.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET) address.txt
