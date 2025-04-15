# Compiler and flags
CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -Werror -march=native -fopenmp
LDFLAGS := -fopenmp
LIBS := -lsecp256k1 -lssl -lcrypto -lz -pthread

# Project structure
TARGET := bitcoin_scanner
SRC := bitcoin_scanner.cpp
OBJ := $(SRC:.cpp=.o)

# Build types
RELEASE_FLAGS := -O3 -flto -DNDEBUG
DEBUG_FLAGS := -g -O0 -DDEBUG

.PHONY: all release debug clean

all: release

release: CXXFLAGS += $(RELEASE_FLAGS)
release: $(TARGET)

debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(LDFLAGS) $^ -o $@ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) *.o

# Install dependencies (Ubuntu/Debian specific)
install-deps:
	sudo apt-get install -y \
		build-essential \
		libssl-dev \
		zlib1g-dev \
		libsecp256k1-dev \
		libomp-dev

# Run with high priority
run: release
	sudo nice -n -20 ./$(TARGET)

# For development
format:
	clang-format -i $(SRC)

# Include dependencies
-include $(OBJ:.o=.d)
