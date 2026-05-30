#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include <filesystem>
#include "engine.hpp"
#include "graph.hpp"
#include "detectors.hpp"
#include "types.hpp"
#include "cairo_parser.hpp"
#include "solidity_parser.hpp"
#include "formatters.hpp"

using namespace crossguard;
namespace fs = std::filesystem;

// Locate fixtures directory from binary location or cwd
static fs::path find_fixtures() {
    if (fs::exists("fixtures/StarkBridge_vuln.sol")) return "fixtures";
    if (fs::exists("../fixtures/StarkBridge_vuln.sol")) return "../fixtures";
    auto bin = fs::read_symlink("/proc/self/exe");
    auto p = bin.parent_path() / "../share/crossguard/fixtures";
    if (fs::exists(p / "StarkBridge_vuln.sol")) return fs::canonical(p);
    return {};
}

class TestRunner {
public:
    int run_all() {
        fixtures = find_fixtures();

        std::cout << "=== CrossGuard Tests ===\n";
        if (fixtures.empty())
            std::cout << "[warn] fixture files not found — integration tests skipped\n\n";

        run("type_system",            [&]{ test_type_system(); });
        run("graph_operations",       [&]{ test_graph_operations(); });
        run("finding_creation",       [&]{ test_finding_creation(); });
        run("severity_ordering",      [&]{ test_severity_ordering(); });
        run("d1_unit",                [&]{ test_d1_unit(); });
        run("d3_unit",                [&]{ test_d3_unit(); });
        run("d6_unit",                [&]{ test_d6_unit(); });
        run("type_matching",          [&]{ test_type_matching(); });
        run("json_output_valid",      [&]{ test_json_output_valid(); });
        run("sarif_output_valid",     [&]{ test_sarif_output_valid(); });
        run("terminal_no_color",      [&]{ test_terminal_no_color(); });

        if (!fixtures.empty()) {
            run("cairo_parser_real",  [&]{ test_cairo_parser_real(); });
            run("d1_on_vuln_cairo",   [&]{ test_d1_on_vuln_cairo(); });
            run("d1_on_safe_cairo",   [&]{ test_d1_on_safe_cairo(); });
            run("d3_d4_on_vuln_sol",  [&]{ test_d3_d4_on_vuln_sol(); });
            run("safe_pair_clean",    [&]{ test_safe_pair_clean(); });
            run("vuln_pair_findings", [&]{ test_vuln_pair_findings(); });
        }

        std::cout << "\n=== Results ===\n";
        std::cout << "Passed: " << passed << "\n";
        std::cout << "Failed: " << failed << "\n";
        std::cout << "Total:  " << (passed + failed) << "\n";
        return failed == 0 ? 0 : 1;
    }

private:
    int passed = 0, failed = 0;
    fs::path fixtures;

    void run(const char* name, std::function<void()> fn) {
        try {
            fn();
            std::cout << "  \u2713 " << name << "\n";
            ++passed;
        } catch (const std::exception& e) {
            std::cout << "  \u2717 " << name << ": " << e.what() << "\n";
            ++failed;
        }
    }

    // ── unit tests ────────────────────────────────────────────────────────────

    void test_type_system() {
        TypeInfo a; a.name = "uint256"; a.bits = 256;
        assert(a.is_uint256());
        TypeInfo b; b.name = "u256";    b.bits = 256;
        assert(b.is_u256());
        TypeInfo c; c.name = "felt252"; c.bits = 252;
        assert(c.is_felt252());
    }

    void test_graph_operations() {
        Graph g;
        Send s; s.selector = "0x1"; s.location.file = "A.sol"; s.location.line = 1;
        g.add_send(s);
        assert(g.send_count() == 1);

        Handler h; h.selector = "0x1"; h.location.file = "a.cairo"; h.location.line = 10;
        g.add_handler(h);
        assert(g.handler_count() == 1);
        assert(g.find_handler_by_selector("0x1") != nullptr);
    }

    void test_finding_creation() {
        Location loc; loc.file = "t.sol"; loc.line = 1;
        Finding f("D1", Severity::CRITICAL, loc, "Title", "Desc");
        assert(f.id == "D1");
        assert(f.severity == Severity::CRITICAL);
    }

    void test_severity_ordering() {
        assert((int)Severity::CRITICAL < (int)Severity::HIGH);
        assert((int)Severity::HIGH     < (int)Severity::MEDIUM);
        assert((int)Severity::MEDIUM   < (int)Severity::LOW);
    }

    void test_d1_unit() {
        Graph g;
        Handler h; h.selector = "0x1";
        h.validates_from_address = false;
        h.location = {"handler.cairo", 50, 0, "process_deposit"};
        g.add_handler(h);

        SenderCheckDetector det;
        auto findings = det.run(g);
        assert(findings.size() == 1);
        assert(findings[0].severity == Severity::CRITICAL);
        assert(findings[0].id == "D1");

        // Validated handler should produce no finding
        Graph g2;
        Handler h2 = h; h2.validates_from_address = true;
        g2.add_handler(h2);
        assert(SenderCheckDetector().run(g2).empty());
    }

    void test_d3_unit() {
        Graph g;
        Send s; s.selector = "0x2"; s.has_fee_check = false;
        s.location = {"Bridge.sol", 30, 0, "deposit"};
        g.add_send(s);

        FeeDetector det;
        auto findings = det.run(g);
        assert(findings.size() == 1);
        assert(findings[0].severity == Severity::HIGH);
        assert(findings[0].id == "D3");

        // Send with fee check — no finding
        Graph g2;
        Send s2 = s; s2.has_fee_check = true;
        g2.add_send(s2);
        assert(FeeDetector().run(g2).empty());
    }

    void test_type_matching() {
        TypeMismatchDetector det;
        // Empty graph — no findings
        assert(det.run(Graph()).empty());
    }

    void test_d6_unit() {
        // Handler with multiple typed params — Cairo type system enforces arity,
        // so PayloadLengthDetector should NOT flag it.
        {
            Graph g;
            Handler h;
            h.location = {"bridge.cairo", 10, 0, "process_deposit"};
            h.validates_from_address = true;
            TypeInfo p1; p1.name = "u128"; h.params.push_back(p1);
            TypeInfo p2; p2.name = "u128"; h.params.push_back(p2);
            // Supply a non-empty source line that doesn't mention Span<felt252>
            h.source_lines.push_back("let amount: u256 = u256 { low: amount_low, high: amount_high };");
            g.add_handler(h);

            PayloadLengthDetector det;
            // Typed params → safe by construction; detector must not flag
            auto findings = det.run(g);
            assert(findings.empty());
        }

        // Handler with raw Span<felt252> payload and no length check — must be flagged
        {
            Graph g;
            Handler h;
            h.location = {"bridge.cairo", 30, 0, "handle_raw_payload"};
            h.validates_from_address = true;
            TypeInfo p1; p1.name = "felt252"; h.params.push_back(p1);
            TypeInfo p2; p2.name = "felt252"; h.params.push_back(p2);
            // Body references Span<felt252> but has no length assertion
            h.source_lines.push_back("let val = *payload.get(0).unwrap(); // Span<felt252>");
            g.add_handler(h);

            PayloadLengthDetector det;
            auto findings = det.run(g);
            assert(!findings.empty());
            assert(findings[0].id == "D6");
            assert(findings[0].severity == Severity::MEDIUM);
        }
    }

    void test_json_output_valid() {
        // Build a small finding set and verify JSON is parseable
        Location loc; loc.file = "Bridge.sol"; loc.line = 42;
        loc.selector_or_function = "deposit";
        Finding f("D3", Severity::HIGH, loc, "Missing fee check", "msg.value not forwarded");
        f.metadata["function"] = "deposit";

        JsonFormatter fmt;
        std::string out = fmt.format({f}, {});

        // Must contain required JSON keys
        assert(out.find("\"findings\"") != std::string::npos);
        assert(out.find("\"D3\"") != std::string::npos);
        assert(out.find("\"HIGH\"") != std::string::npos);
        assert(out.find("\"count\"") != std::string::npos);

        // Braces must be balanced
        int depth = 0;
        for (char c : out) {
            if (c == '{') ++depth;
            if (c == '}') --depth;
        }
        assert(depth == 0);
    }

    void test_sarif_output_valid() {
        Location loc; loc.file = "bridge.cairo"; loc.line = 28;
        loc.selector_or_function = "process_deposit";
        Finding f("D1", Severity::CRITICAL, loc,
                  "Missing from_address validation", "Any address can call this handler");

        SarifFormatter fmt;
        std::string out = fmt.format({f}, {});

        // SARIF 2.1.0 required fields
        assert(out.find("\"version\": \"2.1.0\"") != std::string::npos);
        assert(out.find("\"runs\"")  != std::string::npos);
        assert(out.find("\"rules\"") != std::string::npos);
        assert(out.find("\"D1\"")    != std::string::npos);
        assert(out.find("\"error\"") != std::string::npos);
        assert(out.find("\"security-severity\"") != std::string::npos);
        // "9.5" expected for CRITICAL
        assert(out.find("\"9.5\"") != std::string::npos);

        // Braces balanced
        int depth = 0;
        for (char c : out) {
            if (c == '{') ++depth;
            if (c == '}') --depth;
        }
        assert(depth == 0);
    }

    void test_terminal_no_color() {
        Location loc; loc.file = "Bridge.sol"; loc.line = 10;
        Finding f("D4", Severity::HIGH, loc, "Unrestricted cancel", "No access control");

        TerminalFormatter fmt(/*color=*/false);
        std::string out = fmt.format({f}, {});

        // Must mention severity, id, title
        assert(out.find("HIGH") != std::string::npos);
        assert(out.find("D4")   != std::string::npos);
        assert(out.find("Unrestricted cancel") != std::string::npos);
        // No ANSI escape codes
        assert(out.find("\033[") == std::string::npos);
    }

    // ── integration tests ─────────────────────────────────────────────────────

    void test_cairo_parser_real() {
        auto p = CairoSourceParser::load((fixtures / "bridge_vuln.cairo").string());
        auto handlers = p->parse_handlers();
        assert(!handlers.empty());
        // Must find process_deposit, process_withdrawal_request, update_l1_bridge
        assert(handlers.size() == 3);
        bool found_deposit = false;
        for (auto& h : handlers)
            if (h.location.selector_or_function == "process_deposit") found_deposit = true;
        assert(found_deposit);
    }

    void test_d1_on_vuln_cairo() {
        auto p = CairoSourceParser::load((fixtures / "bridge_vuln.cairo").string());
        auto handlers = p->parse_handlers();

        Graph g;
        for (auto& h : handlers) g.add_handler(h);

        SenderCheckDetector det;
        auto findings = det.run(g);
        // process_deposit has no from_address check — must be flagged
        bool found = false;
        for (auto& f : findings)
            if (f.metadata.count("handler") &&
                f.metadata.at("handler") == "process_deposit") found = true;
        assert(found);
    }

    void test_d1_on_safe_cairo() {
        auto p = CairoSourceParser::load((fixtures / "bridge_safe.cairo").string());
        auto handlers = p->parse_handlers();

        Graph g;
        for (auto& h : handlers) g.add_handler(h);

        SenderCheckDetector det;
        auto findings = det.run(g);
        // Safe bridge validates from_address in every handler — no D1 findings
        assert(findings.empty());
    }

    void test_d3_d4_on_vuln_sol() {
        auto p = SoliditySourceParser::load((fixtures / "StarkBridge_vuln.sol").string());

        Graph g;
        for (auto& s : p->parse_sends())         g.add_send(s);
        for (auto& c : p->parse_cancellations())  g.add_cancellation(c);

        // D3: depositToL2NoFee must be flagged
        FeeDetector fee_det;
        auto fee_findings = fee_det.run(g);
        assert(!fee_findings.empty());

        // D4: cancelDeposit (no access control) must be flagged
        CancellationDetector canc_det;
        auto canc_findings = canc_det.run(g);
        assert(!canc_findings.empty());
    }

    void test_safe_pair_clean() {
        Engine engine;
        auto ctx = engine.analyze(
            (fixtures / "StarkBridge_safe.sol").string(),
            (fixtures / "bridge_safe.cairo").string()
        );

        // Safe pair must produce zero CRITICAL or HIGH findings
        int high_plus = 0;
        for (auto& f : ctx.findings)
            if (f.severity == Severity::CRITICAL || f.severity == Severity::HIGH)
                ++high_plus;

        if (high_plus > 0) {
            std::string msg = "safe pair has " + std::to_string(high_plus) +
                              " HIGH/CRITICAL finding(s):\n";
            for (auto& f : ctx.findings)
                if (f.severity == Severity::CRITICAL || f.severity == Severity::HIGH)
                    msg += "  [" + f.id + "] " + f.title + "\n";
            throw std::runtime_error(msg);
        }
    }

    void test_vuln_pair_findings() {
        Engine engine;
        auto ctx = engine.analyze(
            (fixtures / "StarkBridge_vuln.sol").string(),
            (fixtures / "bridge_vuln.cairo").string()
        );

        // Must find at least one HIGH+ finding
        bool has_high = false;
        for (auto& f : ctx.findings)
            if (f.severity <= Severity::HIGH) has_high = true;
        assert(has_high);

        // D1 (missing sender check) must be present
        bool has_d1 = false;
        for (auto& f : ctx.findings)
            if (f.id == "D1") has_d1 = true;
        assert(has_d1);

        // D3 (missing fee) must be present
        bool has_d3 = false;
        for (auto& f : ctx.findings)
            if (f.id == "D3") has_d3 = true;
        assert(has_d3);

        // D4 (unrestricted cancel) must be present
        bool has_d4 = false;
        for (auto& f : ctx.findings)
            if (f.id == "D4") has_d4 = true;
        assert(has_d4);
    }
};

int main() {
    TestRunner runner;
    return runner.run_all();
}
