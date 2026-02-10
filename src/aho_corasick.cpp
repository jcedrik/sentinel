#include "aho_corasick.hpp"

#include <queue>
#include <stdexcept>

namespace sentinel {

AhoCorasick::AhoCorasick() {
    nodes_.emplace_back();
}

std::size_t AhoCorasick::add_pattern(std::string_view pattern) {
    const std::size_t id = pattern_lengths_.size();
    pattern_lengths_.push_back(pattern.size());
    if (pattern.empty()) return id;

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
    // bfs to set failure links
    std::queue<int> q;
    for (int ch = 0; ch < 256; ++ch) {
        int nxt = nodes_[root()].next[ch];
        if (nxt != -1) {
            nodes_[nxt].fail = root();
            q.push(nxt);
        }
    }
    while (!q.empty()) {
        int cur = q.front(); q.pop();
        for (int ch = 0; ch < 256; ++ch) {
            int nxt = nodes_[cur].next[ch];
            if (nxt == -1) continue;
            int f = nodes_[cur].fail;
            while (f != root() && nodes_[f].next[ch] == -1) f = nodes_[f].fail;
            if (nodes_[f].next[ch] != -1 && nodes_[f].next[ch] != nxt)
                nodes_[nxt].fail = nodes_[f].next[ch];
            else
                nodes_[nxt].fail = root();
            q.push(nxt);
        }
    }
    built_ = true;
}

std::vector<Match> AhoCorasick::search(std::string_view text) const {
    if (!built_) throw std::logic_error("search before build");
    std::vector<Match> matches;
    int cur = root();
    for (std::size_t i = 0; i < text.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(text[i]);
        while (cur != root() && nodes_[cur].next[ch] == -1) cur = nodes_[cur].fail;
        if (nodes_[cur].next[ch] != -1) cur = nodes_[cur].next[ch];
        for (std::size_t pid : nodes_[cur].output) matches.push_back(Match{pid, i});
    }
    return matches;
}

} // namespace sentinel
