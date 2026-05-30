#include <iostream>
#include <fstream>
#include <filesystem>
#include "engine.hpp"
#include "formatters.hpp"

namespace fs = std::filesystem;
using namespace crossguard;

struct Args {
    std::string cmd;
    std::string l1, l2;
    std::string format  = "terminal";
    std::string output;
    std::string fail_on = "NONE";
    bool no_color = false;
};

static void show_help() {
    std::cout <<
"CrossGuard v0.1.0 - Bridge security analyzer\n\n"
"USAGE:\n"
"    crossguard-cli <COMMAND> [OPTIONS]\n\n"
"COMMANDS:\n"
"    analyze     Analyze an L1/L2 contract pair\n"
"    demo        Run on built-in fixture contracts\n"
"    version     Print version\n\n"
"OPTIONS:\n"
"    --l1 <PATH>       L1 contract (.sol or solc AST .json)\n"
"    --l2 <PATH>       L2 contract (.cairo or Sierra .json)\n"
"    --format <FMT>    terminal | json | sarif | html  (default: terminal)\n"
"    --output, -o <F>  Write to file instead of stdout\n"
"    --fail-on <LVL>   Exit 1 if findings at CRITICAL|HIGH|MEDIUM|LOW\n"
"    --no-color        Disable ANSI colors\n\n"
"EXAMPLES:\n"
"    crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo\n"
"    crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --format sarif -o out.sarif\n"
"    crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --fail-on HIGH\n"
"    crossguard-cli demo\n";
}

static Args parse_args(int argc, char* argv[]) {
    Args a;
    if (argc < 2) { show_help(); exit(0); }
    a.cmd = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string s = argv[i];
        if      (s == "--l1"      && i+1 < argc) a.l1      = argv[++i];
        else if (s == "--l2"      && i+1 < argc) a.l2      = argv[++i];
        else if (s == "--format"  && i+1 < argc) a.format  = argv[++i];
        else if ((s == "--output" || s == "-o") && i+1 < argc) a.output = argv[++i];
        else if (s == "--fail-on" && i+1 < argc) a.fail_on = argv[++i];
        else if (s == "--no-color") a.no_color = true;
        else if (s == "--help" || s == "-h") { show_help(); exit(0); }
    }
    return a;
}

static std::unique_ptr<BaseFormatter> make_formatter(const Args& a) {
    if (a.format == "json")  return std::make_unique<JsonFormatter>();
    if (a.format == "sarif") return std::make_unique<SarifFormatter>();
    if (a.format == "html")  return std::make_unique<HtmlFormatter>(a.l1, a.l2);
    return std::make_unique<TerminalFormatter>(!a.no_color);
}

static void write_output(const std::string& text, const Args& a) {
    if (!a.output.empty()) {
        std::ofstream f(a.output);
        if (!f) { std::cerr << "error: cannot write: " << a.output << "\n"; exit(1); }
        f << text;
        std::cerr << "report written to " << a.output << "\n";
    } else {
        std::cout << text << "\n";
    }
}

static bool should_fail(const AnalysisContext& ctx, const Args& a) {
    if (a.fail_on == "NONE") return false;
    Severity thr = severity_from_string(a.fail_on);
    for (const auto& f : ctx.findings)
        if (static_cast<int>(f.severity) <= static_cast<int>(thr)) return true;
    return false;
}

static fs::path find_fixtures() {
    if (fs::exists("fixtures/StarkBridge_vuln.sol")) return "fixtures";
    fs::path bin = fs::read_symlink("/proc/self/exe");
    fs::path p = bin.parent_path() / "../share/crossguard/fixtures";
    if (fs::exists(p / "StarkBridge_vuln.sol")) return fs::canonical(p);
    return {};
}

static int cmd_demo(const Args& a) {
    fs::path fix = find_fixtures();
    if (fix.empty()) {
        std::cerr << "error: fixtures not found. Run from the source root.\n";
        return 1;
    }

    bool color = !a.no_color;
    auto sep = [&](const std::string& title) {
        if (color) std::cout << "\033[1;34m";
        std::cout << "\n" << std::string(56, '=') << "\n  " << title
                  << "\n" << std::string(56, '=') << "\n";
        if (color) std::cout << "\033[0m";
    };

    auto run_pair = [&](const std::string& l1, const std::string& l2) {
        std::cout << "  L1: " << l1 << "\n  L2: " << l2 << "\n\n";
        Engine eng;
        AnalysisContext ctx = eng.analyze(l1, l2);
        TerminalFormatter fmt(color);
        std::cout << fmt.format(ctx.findings, ctx.errors) << "\n";
        return (int)ctx.findings.size();
    };

    sep("DEMO 1/2  vulnerable bridge pair");
    int n = run_pair((fix / "StarkBridge_vuln.sol").string(),
                     (fix / "bridge_vuln.cairo").string());
    if (n == 0) std::cerr << "warning: no findings on vulnerable fixtures\n";

    sep("DEMO 2/2  safe bridge pair");
    run_pair((fix / "StarkBridge_safe.sol").string(),
             (fix / "bridge_safe.cairo").string());

    sep("done — run 'crossguard-cli analyze --help' for your contracts");
    return n > 0 ? 0 : 1;
}

static int cmd_analyze(const Args& a) {
    if (a.l1.empty() || a.l2.empty()) {
        std::cerr << "error: --l1 and --l2 required\n"; return 4;
    }
    if (!fs::exists(a.l1)) { std::cerr << "error: L1 not found: " << a.l1 << "\n"; return 1; }
    if (!fs::exists(a.l2)) { std::cerr << "error: L2 not found: " << a.l2 << "\n"; return 1; }

    try {
        Engine eng;
        AnalysisContext ctx = eng.analyze(a.l1, a.l2);
        write_output(make_formatter(a)->format(ctx.findings, ctx.errors), a);
        return should_fail(ctx, a) ? 1 : 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n"; return 2;
    }
}

int main(int argc, char* argv[]) {
    Args a = parse_args(argc, argv);
    if (a.cmd == "analyze")                     return cmd_analyze(a);
    if (a.cmd == "demo")                        return cmd_demo(a);
    if (a.cmd == "version" || a.cmd == "--version") { std::cout << "CrossGuard v0.1.0\n"; return 0; }
    if (a.cmd == "--help"  || a.cmd == "-h")    { show_help(); return 0; }
    std::cerr << "error: unknown command: " << a.cmd << "\n";
    show_help();
    return 4;
}
