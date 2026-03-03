#include "engine.hpp"

#include <fstream>
#include <stdexcept>

namespace sentinel {

Engine::Engine(SignatureSet signatures) : sigs_(std::move(signatures)) {
    // Compile every signature pattern into the shared automaton. We record the
    // mapping from automaton pattern id -> signature index as we go.
    pattern_to_sig_.reserve(sigs_.size());
    for (const auto& sig : sigs_.signatures()) {
        std::size_t pid = automaton_.add_pattern(sig.pattern);
        // pid equals pattern_to_sig_.size() by construction, but store it.
        if (pid != pattern_to_sig_.size()) {
            // defensive: should never happen with sequential adds
            throw std::logic_error("pattern id / signature index desync");
        }
        pattern_to_sig_.push_back(sig.id);
    }
    automaton_.build();
}

void Engine::scan(const Record& rec, std::vector<Alert>& out) const {
    auto matches = automaton_.search(rec.payload);
    for (const auto& m : matches) {
        std::size_t sig_idx = pattern_to_sig_[m.pattern_id];
        const Signature& sig = sigs_.signatures()[sig_idx];
        out.push_back(Alert{rec.index, rec.source, sig, m.end_pos});
    }
}

std::vector<Alert> Engine::scan_all(const std::vector<Record>& records) const {
    std::vector<Alert> alerts;
    for (const auto& rec : records) {
        scan(rec, alerts);
    }
    return alerts;
}

std::vector<Record> read_records_from_lines(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open input file: " + path);
    }
    std::vector<Record> records;
    std::string line;
    std::size_t line_no = 0;
    while (std::getline(f, line)) {
        ++line_no;
        if (line.empty()) continue;
        // strip a trailing CR if the file used CRLF endings
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        Record r;
        r.index = line_no;
        r.source = path + ":" + std::to_string(line_no);
        r.payload = std::move(line);
        records.push_back(std::move(r));
    }
    return records;
}

} // namespace sentinel
