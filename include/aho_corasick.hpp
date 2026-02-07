#ifndef SENTINEL_AHO_CORASICK_HPP
#define SENTINEL_AHO_CORASICK_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sentinel {

struct Match {
    std::size_t pattern_id;
    std::size_t end_pos;
};

// aho-corasick automaton. build once, search many.
// TODO: failure links, output merge
class AhoCorasick {
public:
    AhoCorasick();
    std::size_t add_pattern(std::string_view pattern);
    void build();
    std::vector<Match> search(std::string_view text) const;
    std::size_t pattern_count() const { return pattern_lengths_.size(); }

private:
    struct Node {
        std::vector<int> next;
        int fail = 0;
        std::vector<std::size_t> output;
        Node() : next(256, -1) {}
    };

    std::vector<Node> nodes_;
    std::vector<std::size_t> pattern_lengths_;
    bool built_ = false;

    int root() const { return 0; }
};

} // namespace sentinel

#endif
