#include "engine.hpp"
#include "signature.hpp"

#include <iostream>

using namespace sentinel;

// TODO: proper arg parsing, for now just hardcode while testing
int main() {
    auto sigs = SignatureSet::load_from_file("signatures/default.rules");
    Engine engine(std::move(sigs));
    auto records = read_records_from_lines("samples/traffic.log");
    auto alerts = engine.scan_all(records);

    std::cout << alerts.size() << " alerts\n";
    for (const auto& a : alerts) {
        std::cout << "[" << severity_name(a.signature.severity) << "] "
                  << a.signature.name << " (" << a.signature.sid << ") "
                  << "line " << a.record_index << "\n";
    }
    return 0;
}
