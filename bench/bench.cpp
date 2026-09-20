// sentinel benchmark: Aho-Corasick vs naive per-pattern search.
//
// Measures scan throughput (MB/s) and build time as the number of signatures
// grows from 10 to 10,000, on the same 32 MB haystack. The naive baseline
// does what a loop over std::string::find per pattern would do, which is
// what a detection engine without an automaton effectively does.
//
// Build and run:  make bench
// Output: CSV on stdout, one row per (patterns, engine).
#include "aho_corasick.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace sentinel;
using clk = std::chrono::steady_clock;

static std::string random_bytes(std::size_t n, std::mt19937& rng) {
    // Printable-ish ASCII with a realistic alphabet size, so the automaton
    // actually follows failure links instead of resetting to root every byte.
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789 /.=&-_";
    std::uniform_int_distribution<int> d(0, sizeof(alphabet) - 2);
    std::string s(n, '\0');
    for (auto& c : s) c = alphabet[d(rng)];
    return s;
}

static std::vector<std::string> make_patterns(std::size_t n, std::mt19937& rng) {
    std::uniform_int_distribution<int> len(6, 24);
    std::vector<std::string> p;
    p.reserve(n);
    for (std::size_t i = 0; i < n; ++i) p.push_back(random_bytes(len(rng), rng));
    return p;
}

// Plant some patterns in the haystack so both engines report real matches
// and the match-reporting path is exercised, not only the miss path.
static void plant(std::string& hay, const std::vector<std::string>& pats, std::size_t count, std::mt19937& rng) {
    std::uniform_int_distribution<std::size_t> pos(0, hay.size() - 64);
    std::uniform_int_distribution<std::size_t> which(0, pats.size() - 1);
    for (std::size_t i = 0; i < count; ++i) {
        const auto& p = pats[which(rng)];
        hay.replace(pos(rng), p.size(), p);
    }
}

static std::size_t naive_search(const std::string& hay, const std::vector<std::string>& pats) {
    std::size_t matches = 0;
    for (const auto& p : pats) {
        const char* cur = hay.data();
        const char* end = hay.data() + hay.size();
        while (cur < end) {
            const void* hit = memmem(cur, end - cur, p.data(), p.size());
            if (!hit) break;
            ++matches;
            cur = static_cast<const char*>(hit) + 1;
        }
    }
    return matches;
}

int main(int argc, char** argv) {
    std::size_t mb = argc > 1 ? std::stoul(argv[1]) : 32;
    std::mt19937 rng(1337);
    std::string hay = random_bytes(mb * 1024 * 1024, rng);
    const double hay_mb = static_cast<double>(hay.size()) / (1024.0 * 1024.0);

    std::printf("patterns,engine,build_ms,scan_ms,mb_per_s,matches,table_mb,nodes,alphabet\n");
    for (std::size_t n : {10, 100, 1000, 10000}) {
        auto pats = make_patterns(n, rng);
        std::string h = hay;
        plant(h, pats, 2000, rng);

        // Aho-Corasick
        auto t0 = clk::now();
        AhoCorasick ac;
        for (const auto& p : pats) ac.add_pattern(p);
        ac.build();
        auto t1 = clk::now();
        auto m = ac.search(h);
        auto t2 = clk::now();
        double build_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        double scan_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
        std::printf("%zu,aho-corasick,%.1f,%.1f,%.1f,%zu,%.1f,%zu,%zu\n", n, build_ms, scan_ms, hay_mb / (scan_ms / 1000.0), m.size(),
                    ac.table_bytes() / (1024.0 * 1024.0), ac.node_count(), ac.alphabet_size());

        // Naive: one memmem pass per pattern. At 10,000 patterns on 32 MB
        // this is ~320 GB of scanning; cap the haystack so the run finishes
        // and scale the time back up.
        std::size_t cap = n >= 1000 ? h.size() / 16 : h.size();
        std::string hs = h.substr(0, cap);
        auto t3 = clk::now();
        std::size_t nm = naive_search(hs, pats);
        auto t4 = clk::now();
        double naive_ms = std::chrono::duration<double, std::milli>(t4 - t3).count() * (static_cast<double>(h.size()) / cap);
        std::printf("%zu,naive-memmem,0.0,%.1f,%.1f,%zu,,,\n", n, naive_ms, hay_mb / (naive_ms / 1000.0), nm * (h.size() / cap));
    }
    return 0;
}
