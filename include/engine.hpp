#ifndef SENTINEL_ENGINE_HPP
#define SENTINEL_ENGINE_HPP

#include "aho_corasick.hpp"
#include "signature.hpp"

#include <string>
#include <vector>

namespace sentinel {

// A record is one unit of input to inspect: a log line, a reassembled packet
// payload, a flow. We keep it simple: an id (line/packet number) and the raw
// bytes. Source metadata can be attached for richer reporting.
struct Record {
    std::size_t index = 0;   // 1-based position in the input
    std::string source;      // optional: src ip, filename:line, etc.
    std::string payload;     // raw bytes to scan
};

// An alert: signature X fired on record Y at offset Z.
struct Alert {
    std::size_t record_index;
    std::string source;
    Signature signature;     // copy of the rule that fired
    std::size_t offset;      // where in the payload the match ended
};

// The detection engine. Build it from a SignatureSet; it compiles all
// patterns into one Aho-Corasick automaton up front, then scans records.
//
// The whole point of using Aho-Corasick here is that adding more signatures
// does not slow down scanning per byte: all rules are tested simultaneously
// in a single pass over each record's payload.
class Engine {
public:
    explicit Engine(SignatureSet signatures);

    // Scan a single record, appending any alerts to `out`.
    void scan(const Record& rec, std::vector<Alert>& out) const;

    // Convenience: scan many records, returning all alerts.
    std::vector<Alert> scan_all(const std::vector<Record>& records) const;

    std::size_t signature_count() const { return sigs_.size(); }

private:
    SignatureSet sigs_;
    AhoCorasick automaton_;
    // Maps an automaton pattern id back to the signature index. They line up
    // 1:1 here because we add patterns in signature order, but keeping the
    // map explicit makes the relationship clear and refactor-safe.
    std::vector<std::size_t> pattern_to_sig_;
};

// Reads records from a text file, one per line. Each line becomes a record
// whose source is "path:lineno". Blank lines are skipped. This is the simple
// log-scanning entry point.
std::vector<Record> read_records_from_lines(const std::string& path);

} // namespace sentinel

#endif // SENTINEL_ENGINE_HPP
