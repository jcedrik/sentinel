#ifndef SENTINEL_AHO_CORASICK_HPP
#define SENTINEL_AHO_CORASICK_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sentinel {

// A match reported by the automaton: which pattern matched, and the position
// in the input where the match ends (0-indexed, inclusive).
struct Match {
    std::size_t pattern_id;   // index into the list of added patterns
    std::size_t end_pos;      // byte offset in the haystack where match ends
};

// Aho-Corasick multi-pattern string matching automaton.
//
// Why this algorithm: a detection engine needs to test many signatures
// against the same byte stream. Running N separate substring searches is
// O(N * text). Aho-Corasick builds a single automaton from all patterns and
// finds every occurrence of every pattern in one pass over the text, in
// O(text + total_matches) after an O(total_pattern_length) build.
//
// Usage:
//   AhoCorasick ac;
//   ac.add_pattern("malware");
//   ac.add_pattern("exploit");
//   ac.build();
//   auto matches = ac.search(payload);
//
// The structure is build-once / search-many: add all patterns, call build()
// to compute failure links, then search() as many inputs as you like.
class AhoCorasick {
public:
    AhoCorasick();

    // Register a pattern. Returns the pattern's id (its insertion index).
    // Must be called before build(). Empty patterns are ignored (id still
    // returned for caller bookkeeping, but they never match).
    std::size_t add_pattern(std::string_view pattern);

    // Finalize the automaton by computing failure links (BFS over the trie).
    // Call exactly once after all patterns are added and before search().
    void build();

    // Find all matches of all patterns in `text`. Returns one Match per
    // occurrence. Safe to call repeatedly. Calling before build() throws.
    std::vector<Match> search(std::string_view text) const;

    // Number of patterns added.
    std::size_t pattern_count() const { return pattern_lengths_.size(); }

private:
    // Trie node. We use a flat vector of nodes indexed by int to keep cache
    // behavior good and avoid pointer chasing. Transitions use a 256-wide
    // table per node: this trades memory for O(1) transitions, which matters
    // because search() is the hot path.
    struct Node {
        std::vector<int> next;     // 256 transitions, -1 if absent (pre-build)
        int fail = 0;              // failure link (filled during build)
        std::vector<std::size_t> output; // pattern ids ending at this node
        Node() : next(256, -1) {}
    };

    std::vector<Node> nodes_;
    std::vector<std::size_t> pattern_lengths_;
    bool built_ = false;

    int root() const { return 0; }
};

} // namespace sentinel

#endif // SENTINEL_AHO_CORASICK_HPP
