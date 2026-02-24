#ifndef SENTINEL_SIGNATURE_HPP
#define SENTINEL_SIGNATURE_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace sentinel {

// Severity levels for a signature, ordered so the worst can be selected.
enum class Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 };

const char* severity_name(Severity s);
Severity severity_from_string(const std::string& s);

// One detection rule. A signature matches when its byte pattern appears in a
// record's payload. This is deliberately close to how real IDS rules work
// (Snort/Suricata "content" matches), but pared down to the essentials.
struct Signature {
    std::size_t id = 0;          // assigned on load, index into ruleset
    std::string sid;             // human rule id, e.g. "SIG-1001"
    std::string name;            // short description
    std::string pattern;        // raw byte pattern to match (the "content")
    Severity severity = Severity::Medium;
    std::string category;        // e.g. "exploit", "malware", "recon"
};

// Loads signatures from a rules file. Format is one rule per line:
//
//   sid; severity; category; name; pattern
//
// Fields are separated by semicolons. Lines starting with '#' and blank
// lines are ignored.
//
// Throws std::runtime_error on a malformed line, with the line number, so a
// bad ruleset fails loudly instead of silently skipping detections.
class SignatureSet {
public:
    // Parse rules from the given file path. Returns the loaded set.
    static SignatureSet load_from_file(const std::string& path);

    // Parse rules from an in-memory string (used by tests).
    static SignatureSet load_from_string(const std::string& text);

    const std::vector<Signature>& signatures() const { return sigs_; }
    std::size_t size() const { return sigs_.size(); }

private:
    std::vector<Signature> sigs_;
};

} // namespace sentinel

#endif // SENTINEL_SIGNATURE_HPP
