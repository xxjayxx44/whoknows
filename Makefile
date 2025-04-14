CXX      = g++
CXXFLAGS = -std=c++17 -O3 -march=native -Wall
LDLIBS   = -lsecp256k1 -lssl -lcrypto

TARGET   = bitcoin_scanner
SRC      = bitcoin_scanner.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET) address.txt
