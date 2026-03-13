#include "engine.hpp"
#include "signature.hpp"

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <string>
#include <unistd.h> // isatty

using namespace sentinel;

namespace {

struct Args {
    std::string rules_path;
    std::string input_path;
    bool json = false;
    bool ok = false;
    std::string error;
};

Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-r" || arg == "--rules") {
            if (++i >= argc) { a.error = "missing value for --rules"; return a; }
            a.rules_path = argv[i];
        } else if (arg == "-i" || arg == "--input") {
            if (++i >= argc) { a.error = "missing value for --input"; return a; }
            a.input_path = argv[i];
        } else if (arg == "--json") {
            a.json = true;
        } else if (arg == "-h" || arg == "--help") {
            a.error = "help";
            return a;
        } else {
            a.error = "unknown argument: " + arg;
            return a;
        }
    }
    if (a.rules_path.empty() || a.input_path.empty()) {
        a.error = "both --rules and --input are required";
        return a;
    }
    a.ok = true;
    return a;
}

void print_usage() {
    std::cout <<
        "sentinel - multi-signature detection engine\n\n"
        "Usage:\n"
        "  sentinel --rules <file> --input <file> [--json]\n\n"
        "Options:\n"
        "  -r, --rules <file>   signature ruleset to load\n"
        "  -i, --input <file>   input to scan (one record per line)\n"
        "      --json           emit alerts as JSON\n"
        "  -h, --help           show this help\n\n"
        "Exit codes: 0 = no alerts, 1 = alerts found, 2 = error\n";
}

const char* color_for(Severity s, bool use_color) {
    if (!use_color) return "";
    switch (s) {
        case Severity::Critical: return "\033[95m";
        case Severity::High: return "\033[91m";
        case Severity::Medium: return "\033[93m";
        case Severity::Low: return "\033[94m";
        case Severity::Info: return "\033[90m";
    }
    return "";
}

void escape_json(const std::string& in, std::string& out) {
    for (char c : in) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c & 0xff);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
}

void print_text(const std::vector<Alert>& alerts, std::size_t sig_count,
                std::size_t rec_count, bool use_color) {
    const char* reset = use_color ? "\033[0m" : "";
    const char* bold = use_color ? "\033[1m" : "";

    std::cout << bold << "sentinel - " << sig_count << " signatures, "
              << rec_count << " records scanned" << reset << "\n";

    if (alerts.empty()) {
        std::cout << (use_color ? "\033[94m" : "")
                  << "No alerts.\n" << reset;
        return;
    }

    // Sort alerts worst-severity first for the report.
    std::vector<Alert> sorted = alerts;
    std::sort(sorted.begin(), sorted.end(), [](const Alert& a, const Alert& b) {
        return a.signature.severity > b.signature.severity;
    });

    std::cout << alerts.size() << " alert(s)\n\n";
    for (const auto& a : sorted) {
        const char* col = color_for(a.signature.severity, use_color);
        std::cout << col << "[" << severity_name(a.signature.severity) << "]"
                  << reset << " " << a.signature.name
                  << "  (" << a.signature.sid << ")\n";
        std::cout << "   source: " << a.source << "\n";
        std::cout << "   category: " << a.signature.category
                  << "   offset: " << a.offset << "\n\n";
    }
}

void print_json(const std::vector<Alert>& alerts, std::size_t sig_count,
                std::size_t rec_count) {
    std::cout << "{\n";
    std::cout << "  \"signatures_loaded\": " << sig_count << ",\n";
    std::cout << "  \"records_scanned\": " << rec_count << ",\n";
    std::cout << "  \"alert_count\": " << alerts.size() << ",\n";
    std::cout << "  \"alerts\": [\n";
    for (std::size_t i = 0; i < alerts.size(); ++i) {
        const auto& a = alerts[i];
        std::string name_e, sid_e, cat_e, src_e;
        escape_json(a.signature.name, name_e);
        escape_json(a.signature.sid, sid_e);
        escape_json(a.signature.category, cat_e);
        escape_json(a.source, src_e);
        std::cout << "    {\n"
                  << "      \"sid\": \"" << sid_e << "\",\n"
                  << "      \"name\": \"" << name_e << "\",\n"
                  << "      \"severity\": \"" << severity_name(a.signature.severity) << "\",\n"
                  << "      \"category\": \"" << cat_e << "\",\n"
                  << "      \"source\": \"" << src_e << "\",\n"
                  << "      \"offset\": " << a.offset << "\n"
                  << "    }" << (i + 1 < alerts.size() ? "," : "") << "\n";
    }
    std::cout << "  ]\n}\n";
}

} // namespace

int main(int argc, char** argv) {
    Args args = parse_args(argc, argv);
    if (!args.ok) {
        if (args.error == "help") {
            print_usage();
            return 0;
        }
        std::cerr << "sentinel: " << args.error << "\n\n";
        print_usage();
        return 2;
    }

    try {
        SignatureSet sigs = SignatureSet::load_from_file(args.rules_path);
        std::size_t sig_count = sigs.size();
        Engine engine(std::move(sigs));
        auto records = read_records_from_lines(args.input_path);
        auto alerts = engine.scan_all(records);

        if (args.json) {
            print_json(alerts, sig_count, records.size());
        } else {
            bool use_color = isatty(fileno(stdout));
            print_text(alerts, sig_count, records.size(), use_color);
        }
        return alerts.empty() ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "sentinel: " << e.what() << "\n";
        return 2;
    }
}
