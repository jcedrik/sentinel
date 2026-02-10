# sentinel - build (WIP)
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -I include

.PHONY: test clean

test:
	$(CXX) $(CXXFLAGS) src/aho_corasick.cpp tests/test_aho_corasick.cpp -o test_ac
	./test_ac

clean:
	rm -f test_ac
