#include "signature.hpp"

#include <cstdlib>
#include <iostream>
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

static void test_load_basic_rule() {
    auto set = SignatureSet::load_from_string(
        "SIG-1; high; exploit; Nmap scan; nmap\n");
    CHECK(set.size() == 1);
    const auto& s = set.signatures()[0];
    CHECK(s.sid == "SIG-1");
    CHECK(s.severity == Severity::High);
    CHECK(s.category == "exploit");
}

static void test_comments_and_blanks_ignored() {
    auto set = SignatureSet::load_from_string(
        "# this is a comment\n"
        "\n"
        "SIG-2; low; recon; User agent nmap; nmap\n");
    CHECK(set.size() == 1);
    CHECK(set.signatures()[0].sid == "SIG-2");
}

static void test_malformed_throws() {
    bool threw = false;
    try {
        SignatureSet::load_from_string("only; three; fields\n");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

int main() {
    test_load_basic_rule();
    test_comments_and_blanks_ignored();
    test_malformed_throws();
    std::cout << "engine: all " << g_checks << " checks passed\n";
    return 0;
}
