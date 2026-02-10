#include "aho_corasick.hpp"

#include <cassert>
#include <iostream>
#include <set>
#include <string>

using namespace sentinel;

static int g_checks = 0;
#define CHECK(cond)                                                       \
    do {                                                                  \
        ++g_checks;                                                       \
        if (!(cond)) {                                                    \
            std::cerr << "FAIL: " << #cond << " (line " << __LINE__       \
                      << ")\n";                                           \
            std::exit(1);                                                 \
        }                                                                 \
    } while (0)

static void test_single_match() {
    AhoCorasick ac;
    ac.add_pattern("malware");
    ac.build();
    auto m = ac.search("this binary is malware indeed");
    CHECK(m.size() == 1);
    CHECK(m[0].pattern_id == 0);
    CHECK(m[0].end_pos == 21); // 'e' of malware
}

static void test_multiple_occurrences() {
    AhoCorasick ac;
    ac.add_pattern("ab");
    ac.build();
    auto m = ac.search("abab");
    CHECK(m.size() == 2);
    CHECK(m[0].end_pos == 1);
    CHECK(m[1].end_pos == 3);
}

static void test_no_match() {
    AhoCorasick ac;
    ac.add_pattern("exploit");
    ac.build();
    auto m = ac.search("perfectly benign traffic");
    CHECK(m.empty());
}

int main() {
    test_single_match();
    test_multiple_occurrences();
    test_no_match();
    std::cout << "aho_corasick: all " << g_checks << " checks passed\n";
    return 0;
}
