CXX       = g++
CXXFLAGS  = -std=c++17 -Ofast -march=native -flto -Wall -Wextra
LDLIBS    = -lsecp256k1 -lssl -lcrypto -lz -pthread

TARGET    = bitcoin_scanner
SRC       = bitcoin_scanner.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET) addresses.txt
