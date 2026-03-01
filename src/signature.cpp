#include "signature.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace sentinel {

const char* severity_name(Severity s) {
    switch (s) {
        case Severity::Info: return "INFO";
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

Severity severity_from_string(const std::string& s) {
    if (s == "info" || s == "INFO") return Severity::Info;
    if (s == "low" || s == "LOW") return Severity::Low;
    if (s == "medium" || s == "MEDIUM") return Severity::Medium;
    if (s == "high" || s == "HIGH") return Severity::High;
    if (s == "critical" || s == "CRITICAL") return Severity::Critical;
    throw std::runtime_error("unknown severity: " + s);
}

namespace {
// Trim leading/trailing ASCII whitespace.
std::string trim(const std::string& s) {
    std::size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    std::size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

int hex_val(char c, int line_no) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::runtime_error(
        "bad hex digit on line " + std::to_string(line_no));
}
} // namespace

std::string SignatureSet::decode_pattern(const std::string& raw, int line_no) {
    // Walk the pattern. Outside |..| we copy bytes verbatim. Inside, we read
    // space-separated hex pairs and emit the corresponding bytes. This mirrors
    // Snort/Suricata content syntax: "GET |0d 0a|" -> "GET\r\n".
    std::string out;
    bool in_hex = false;
    std::string hex_acc;

    for (std::size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c == '|') {
            in_hex = !in_hex;
            if (!in_hex && !hex_acc.empty()) {
                // closing a hex block that still has buffered text is fine;
                // tokens were already flushed on spaces below
            }
            continue;
        }
        if (!in_hex) {
            out.push_back(c);
            continue;
        }
        // inside hex section
        if (c == ' ') {
            continue; // separators between byte tokens
        }
        // expect a pair of hex digits
        if (i + 1 >= raw.size()) {
            throw std::runtime_error(
                "truncated hex byte on line " + std::to_string(line_no));
        }
        int hi = hex_val(c, line_no);
        int lo = hex_val(raw[i + 1], line_no);
        out.push_back(static_cast<char>((hi << 4) | lo));
        ++i; // consumed two chars
    }

    if (in_hex) {
        throw std::runtime_error(
            "unterminated | hex block on line " + std::to_string(line_no));
    }
    return out;
}

SignatureSet SignatureSet::load_from_string(const std::string& text) {
    SignatureSet set;
    std::istringstream in(text);
    std::string line;
    int line_no = 0;

    while (std::getline(in, line)) {
        ++line_no;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;

        // Split on ';' into exactly 5 fields.
        std::vector<std::string> fields;
        std::string cur;
        std::istringstream ls(t);
        while (std::getline(ls, cur, ';')) {
            fields.push_back(trim(cur));
        }
        if (fields.size() != 5) {
            throw std::runtime_error(
                "expected 5 fields (sid; severity; category; name; pattern) "
                "on line " + std::to_string(line_no));
        }

        Signature sig;
        sig.id = set.sigs_.size();
        sig.sid = fields[0];
        sig.severity = severity_from_string(fields[1]);
        sig.category = fields[2];
        sig.name = fields[3];
        sig.pattern = decode_pattern(fields[4], line_no);

        if (sig.pattern.empty()) {
            throw std::runtime_error(
                "empty pattern on line " + std::to_string(line_no));
        }
        set.sigs_.push_back(std::move(sig));
    }
    return set;
}

SignatureSet SignatureSet::load_from_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open rules file: " + path);
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return load_from_string(ss.str());
}

} // namespace sentinel
