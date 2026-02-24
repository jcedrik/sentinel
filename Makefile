# sentinel - build
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -I include
SRC      := src/aho_corasick.cpp src/signature.cpp

.PHONY: test clean

test:
	$(CXX) $(CXXFLAGS) src/aho_corasick.cpp tests/test_aho_corasick.cpp -o test_ac
	$(CXX) $(CXXFLAGS) $(SRC) tests/test_engine.cpp -o test_engine
	./test_ac
	./test_engine

clean:
	rm -f test_ac test_engine
