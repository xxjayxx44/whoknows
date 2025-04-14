CXX = g++
CXXFLAGS = -std=c++17 -O3
TARGET = bitcoin_scanner
SRC = bitcoin_scanner.cpp
LDLIBS = -lsecp256k1 -lssl -lcrypto

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET)
