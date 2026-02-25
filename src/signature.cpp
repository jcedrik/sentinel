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
std::string trim(const std::string& s) {
    std::size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    std::size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
} // namespace

SignatureSet SignatureSet::load_from_string(const std::string& text) {
    SignatureSet set;
    std::istringstream in(text);
    std::string line;
    int line_no = 0;

    while (std::getline(in, line)) {
        ++line_no;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;

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
        sig.pattern = fields[4];

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
