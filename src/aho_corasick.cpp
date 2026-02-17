#include "aho_corasick.hpp"

#include <queue>
#include <stdexcept>

namespace sentinel {

AhoCorasick::AhoCorasick() {
    nodes_.emplace_back(); // root node at index 0
}

std::size_t AhoCorasick::add_pattern(std::string_view pattern) {
    const std::size_t id = pattern_lengths_.size();
    pattern_lengths_.push_back(pattern.size());

    if (pattern.empty()) {
        return id; // empty pattern: recorded but never matches
    }

    int cur = root();
    for (unsigned char ch : pattern) {
        if (nodes_[cur].next[ch] == -1) {
            nodes_[cur].next[ch] = static_cast<int>(nodes_.size());
            nodes_.emplace_back();
        }
        cur = nodes_[cur].next[ch];
    }
    nodes_[cur].output.push_back(id);
    return id;
}

void AhoCorasick::build() {
    // BFS over the trie to compute failure links. The failure link of a node
    // points to the longest proper suffix of the string reaching that node
    // which is also a prefix of some pattern. This is what lets the search
    // fall back gracefully instead of restarting.
    std::queue<int> q;

    // Initialize depth-1 nodes: their failure link is the root. Absent
    // transitions from the root loop back to the root (so the automaton is
    // always in a valid state).
    for (int ch = 0; ch < 256; ++ch) {
        int& nxt = nodes_[root()].next[ch];
        if (nxt == -1) {
            nxt = root();
        } else {
            nodes_[nxt].fail = root();
            q.push(nxt);
        }
    }

    while (!q.empty()) {
        int cur = q.front();
        q.pop();

        for (int ch = 0; ch < 256; ++ch) {
            int nxt = nodes_[cur].next[ch];
            if (nxt == -1) {
                // No edge: follow the current node's failure link. This is the
                // "goto" automaton trick: we make every transition defined by
                // pointing missing edges at where failure would send us.
                nodes_[cur].next[ch] = nodes_[nodes_[cur].fail].next[ch];
                continue;
            }
            // Edge exists: its failure link is found by following the parent's
            // failure link and taking the same character.
            nodes_[nxt].fail = nodes_[nodes_[cur].fail].next[ch];

            // Merge output sets: a node also reports everything its failure
            // target reports (suffix patterns that end here too).
            const auto& fail_out = nodes_[nodes_[nxt].fail].output;
            nodes_[nxt].output.insert(
                nodes_[nxt].output.end(), fail_out.begin(), fail_out.end());

            q.push(nxt);
        }
    }

    built_ = true;
}

std::vector<Match> AhoCorasick::search(std::string_view text) const {
    if (!built_) {
        throw std::logic_error("AhoCorasick::search called before build()");
    }

    std::vector<Match> matches;
    int cur = root();
    for (std::size_t i = 0; i < text.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(text[i]);
        cur = nodes_[cur].next[ch]; // always defined after build()
        for (std::size_t pid : nodes_[cur].output) {
            matches.push_back(Match{pid, i});
        }
    }
    return matches;
}

} // namespace sentinel
