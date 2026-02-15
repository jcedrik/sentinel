#include "aho_corasick.hpp"

#include <cassert>
#include <iostream>
#include <set>
#include <string>

using namespace sentinel;

// Minimal test harness: count assertions so output is informative without
// pulling in a heavy framework. Each TEST prints a line; failures abort.
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

// Helper: collect the set of matched pattern ids from a search.
static std::set<std::size_t> matched_ids(const std::vector<Match>& m) {
    std::set<std::size_t> s;
    for (const auto& x : m) s.insert(x.pattern_id);
    return s;
}

static void test_single_match() {
    AhoCorasick ac;
    ac.add_pattern("malware");
    ac.build();
    auto m = ac.search("this binary is malware indeed");
    CHECK(m.size() == 1);
    CHECK(m[0].pattern_id == 0);
    CHECK(m[0].end_pos == 21); // 'e' of malware
}

static void test_multiple_patterns_overlap() {
    // Classic Aho-Corasick case: overlapping patterns sharing suffixes.
    AhoCorasick ac;
    ac.add_pattern("he");   // 0
    ac.add_pattern("she");  // 1
    ac.add_pattern("his");  // 2
    ac.add_pattern("hers"); // 3
    ac.build();
    auto ids = matched_ids(ac.search("ushers"));
    // "ushers" contains "she" (u-SHE-rs), "he" (us-HE-rs), "hers" (us-HERS)
    CHECK(ids.count(1) == 1); // she
    CHECK(ids.count(0) == 1); // he
    CHECK(ids.count(3) == 1); // hers
    CHECK(ids.count(2) == 0); // his not present
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

static void test_binary_safe() {
    // Detection works on raw bytes, including nulls and high bytes.
    AhoCorasick ac;
    std::string sig = std::string("\x90\x90\x90", 3); // NOP sled fragment
    ac.add_pattern(sig);
    ac.build();
    std::string payload = std::string("\x01\x90\x90\x90\xff", 5);
    auto m = ac.search(payload);
    CHECK(m.size() == 1);
}

int main() {
    test_single_match();
    test_multiple_patterns_overlap();
    test_multiple_occurrences();
    test_no_match();
    test_binary_safe();
    std::cout << "aho_corasick: all " << g_checks << " checks passed\n";
    return 0;
}
