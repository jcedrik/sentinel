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

    // Compress: remap the 256-wide rows onto the symbols actually used.
    bool used[256] = {};
    for (const auto& n : nodes_) {
        for (int ch = 0; ch < 256; ++ch) {
            if (n.next[ch] != root() && n.next[ch] != -1) used[ch] = true;
        }
    }
    // Symbol 0 is reserved for "byte in no pattern": it behaves exactly like
    // any other absent edge, which after the goto construction is a defined
    // transition (usually to the root, sometimes deeper via failure links).
    // We still need a real byte to read that transition from, so pick one
    // unused byte as the representative; if every byte is used, symbol 0 is
    // simply never hit.
    int representative = -1;
    for (int ch = 0; ch < 256; ++ch) if (!used[ch]) { representative = ch; break; }
    if (representative == -1) {
        // Every byte value appears in some pattern (binary rulesets can do
        // this). No compression possible: identity map, 256-wide rows.
        alphabet_ = 256;
        for (int ch = 0; ch < 256; ++ch) sym_[ch] = static_cast<uint8_t>(ch);
    } else {
        alphabet_ = 1;
        for (int ch = 0; ch < 256; ++ch) {
            if (used[ch]) sym_[ch] = static_cast<uint8_t>(alphabet_++);
            else sym_[ch] = 0;
        }
    }
    table_.assign(nodes_.size() * alphabet_, root());
    outputs_.resize(nodes_.size());
    for (std::size_t s = 0; s < nodes_.size(); ++s) {
        for (int ch = 0; ch < 256; ++ch) {
            if (used[ch]) table_[s * alphabet_ + sym_[ch]] = nodes_[s].next[ch];
        }
        if (representative >= 0) table_[s * alphabet_ + 0] = nodes_[s].next[representative];
        outputs_[s] = nodes_[s].output;
    }
    // The 256-wide rows are no longer needed for searching. Free them so the
    // automaton's resident size is the compact table, not the trie.
    for (auto& n : nodes_) { std::vector<int>().swap(n.next); std::vector<std::size_t>().swap(n.output); }

    built_ = true;
}

std::vector<Match> AhoCorasick::search(std::string_view text) const {
    if (!built_) {
        throw std::logic_error("AhoCorasick::search called before build()");
    }

    std::vector<Match> matches;
    const int32_t* table = table_.data();
    const std::size_t a = alphabet_;
    std::size_t cur = static_cast<std::size_t>(root());
    for (std::size_t i = 0; i < text.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(text[i]);
        cur = static_cast<std::size_t>(table[cur * a + sym_[ch]]); // one load per byte
        const auto& out = outputs_[cur];
        if (!out.empty()) {
            for (std::size_t pid : out) matches.push_back(Match{pid, i});
        }
    }
    return matches;
}

} // namespace sentinel
