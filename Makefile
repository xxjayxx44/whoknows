# Makefile

CXX      = g++
CXXFLAGS = -std=c++17 -O3 -march=native -funroll-loops -fomit-frame-pointer -flto -Wall -Wextra
LDLIBS   = -lsecp256k1 -lssl -lcrypto -lz -pthread

TARGET   = bitcoin_scanner
SRC      = bitcoin_scanner.cpp

.PHONY: all clean

all: $(TARGET)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) $(LDLIBS)

clean:
	rm -f $(TARGET) addresses.txt
