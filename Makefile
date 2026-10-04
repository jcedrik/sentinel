# sentinel - build and test
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -I include
SRC      := src/aho_corasick.cpp src/signature.cpp src/engine.cpp
MAIN     := src/main.cpp
BIN      := sentinel

.PHONY: all test clean run bench

all: $(BIN)

$(BIN): $(SRC) $(MAIN)
	$(CXX) $(CXXFLAGS) $(SRC) $(MAIN) -o $(BIN)

test: $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) tests/test_aho_corasick.cpp -o test_ac
	$(CXX) $(CXXFLAGS) $(SRC) tests/test_engine.cpp -o test_engine
	./test_ac
	./test_engine

run: $(BIN)
	./$(BIN) --rules signatures/default.rules --input samples/traffic.log

bench: $(SRC)
	$(CXX) $(CXXFLAGS) -O3 $(SRC) bench/bench.cpp -o bench_sentinel
	./bench_sentinel 32 | tee bench/results.csv

clean:
	rm -f $(BIN) test_ac test_engine bench_sentinel
