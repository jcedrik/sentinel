#include "engine.hpp"
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
        "SIG-1; high; exploit; Shellcode NOP sled; |90 90 90 90|\n");
    CHECK(set.size() == 1);
    const auto& s = set.signatures()[0];
    CHECK(s.sid == "SIG-1");
    CHECK(s.severity == Severity::High);
    CHECK(s.category == "exploit");
    CHECK(s.pattern.size() == 4);
    CHECK(static_cast<unsigned char>(s.pattern[0]) == 0x90);
}

static void test_comments_and_blanks_ignored() {
    auto set = SignatureSet::load_from_string(
        "# this is a comment\n"
        "\n"
        "SIG-2; low; recon; User agent nmap; nmap\n");
    CHECK(set.size() == 1);
    CHECK(set.signatures()[0].sid == "SIG-2");
}

static void test_mixed_text_and_hex() {
    auto set = SignatureSet::load_from_string(
        "SIG-3; medium; web; CRLF injection; GET |0d 0a|\n");
    const auto& p = set.signatures()[0].pattern;
    CHECK(p == std::string("GET \r\n"));
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

static void test_unterminated_hex_throws() {
    bool threw = false;
    try {
        SignatureSet::load_from_string("SIG-X; low; x; bad; GET |0d\n");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

static void test_engine_detects() {
    auto set = SignatureSet::load_from_string(
        "SIG-100; critical; malware; Eicar token; EICAR\n"
        "SIG-101; high; recon; Nmap scan; nmap\n");
    Engine eng(std::move(set));
    CHECK(eng.signature_count() == 2);

    std::vector<Record> recs = {
        Record{1, "test:1", "downloaded EICAR test string"},
        Record{2, "test:2", "ran nmap against the host"},
        Record{3, "test:3", "totally normal traffic"},
    };
    auto alerts = eng.scan_all(recs);
    CHECK(alerts.size() == 2);
    CHECK(alerts[0].record_index == 1);
    CHECK(alerts[0].signature.sid == "SIG-100");
    CHECK(alerts[1].record_index == 2);
    CHECK(alerts[1].signature.sid == "SIG-101");
}

static void test_engine_multiple_hits_one_record() {
    auto set = SignatureSet::load_from_string(
        "SIG-A; low; x; a token; attack\n"
        "SIG-B; low; x; b token; payload\n");
    Engine eng(std::move(set));
    std::vector<Record> recs = {
        Record{1, "s", "this attack carries a payload"},
    };
    auto alerts = eng.scan_all(recs);
    CHECK(alerts.size() == 2);
}

int main() {
    test_load_basic_rule();
    test_comments_and_blanks_ignored();
    test_mixed_text_and_hex();
    test_malformed_throws();
    test_unterminated_hex_throws();
    test_engine_detects();
    test_engine_multiple_hits_one_record();
    std::cout << "engine: all " << g_checks << " checks passed\n";
    return 0;
}
