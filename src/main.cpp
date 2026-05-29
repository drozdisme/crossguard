#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <filesystem>
#include "engine.hpp"
#include "formatters.hpp"

namespace fs = std::filesystem;
using namespace crossguard;

struct Args {
    std::string cmd;
    std::string l1;
    std::string l2;
    std::string format  = "terminal";
    std::string output;
    std::string fail_on = "NONE";
    bool no_color = false;
};

static void show_help() {
    std::cout <<
"CrossGuard v0.1.0 - Cross-layer bridge security analyzer\n"
"\n"
"USAGE:\n"
"    crossguard-cli <COMMAND> [OPTIONS]\n"
"\n"
"COMMANDS:\n"
"    analyze     Analyze L1/L2 contract pair\n"
"    demo        Run analysis on built-in fixture contracts\n"
"    version     Print version\n"
"\n"
"OPTIONS (analyze):\n"
"    --l1 <PATH>       L1 contract (.sol or .json AST)\n"
"    --l2 <PATH>       L2 contract (.cairo or .json Sierra)\n"
"    --format <FMT>    terminal | json | sarif | html  (default: terminal)\n"
"    --output <FILE>   Write report to file instead of stdout\n"
"    -o <FILE>         Alias for --output\n"
"    --fail-on <LVL>   Exit 1 if any finding >= level: CRITICAL HIGH MEDIUM LOW\n"
"    --no-color        Disable ANSI colors\n"
"\n"
"EXAMPLES:\n"
"    crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo\n"
"    crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --format json -o report.json\n"
"    crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --fail-on HIGH\n"
"    crossguard-cli demo\n"
<< std::endl;
}

static void show_version() {
    std::cout << "CrossGuard v0.1.0" << std::endl;
}

static Args parse_args(int argc, char* argv[]) {
    Args args;

    if (argc < 2) {
        show_help();
        exit(0);
    }

    args.cmd = argv[1];

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--l1"      && i+1 < argc) args.l1      = argv[++i];
        else if (a == "--l2"      && i+1 < argc) args.l2      = argv[++i];
        else if (a == "--format"  && i+1 < argc) args.format  = argv[++i];
        else if ((a == "--output" || a == "-o") && i+1 < argc) args.output = argv[++i];
        else if (a == "--fail-on" && i+1 < argc) args.fail_on = argv[++i];
        else if (a == "--no-color") args.no_color = true;
        else if (a == "--help" || a == "-h") { show_help(); exit(0); }
    }

    return args;
}

static void validate_analyze(const Args& args) {
    if (args.l1.empty() || args.l2.empty()) {
        std::cerr << "error: --l1 and --l2 are required\n\n";
        show_help();
        exit(4);
    }

    auto check = [](const std::string& path, const char* role) {
        if (!fs::exists(path)) {
            std::cerr << "error: " << role << " file not found: " << path << "\n"
                      << "  cwd: " << fs::current_path().string() << "\n";
            exit(1);
        }
    };
    check(args.l1, "L1");
    check(args.l2, "L2");

    static const std::vector<std::string> fmts = {"terminal","json","sarif","html"};
    if (std::find(fmts.begin(), fmts.end(), args.format) == fmts.end()) {
        std::cerr << "error: unknown format: " << args.format << "\n";
        exit(4);
    }
}

static std::unique_ptr<BaseFormatter> make_formatter(const Args& args) {
    if (args.format == "json")  return std::make_unique<JsonFormatter>();
    if (args.format == "sarif") return std::make_unique<SarifFormatter>();
    if (args.format == "html")  return std::make_unique<HtmlFormatter>(args.l1, args.l2);
    return std::make_unique<TerminalFormatter>(!args.no_color);
}

static void write_output(const std::string& text, const Args& args) {
    if (!args.output.empty()) {
        std::ofstream f(args.output);
        if (!f) {
            std::cerr << "error: cannot write to: " << args.output << "\n";
            exit(1);
        }
        f << text;
        std::cerr << "Report written to " << args.output << "\n";
    } else {
        std::cout << text << "\n";
    }
}

static bool should_fail(const AnalysisContext& ctx, const Args& args) {
    if (args.fail_on == "NONE") return false;
    Severity thr = severity_from_string(args.fail_on);
    for (const auto& f : ctx.findings)
        if (static_cast<int>(f.severity) <= static_cast<int>(thr)) return true;
    return false;
}

// Locate fixtures relative to the installed binary or the source tree.
static fs::path find_fixtures_dir() {
    // 1. Relative to cwd (running from source root)
    if (fs::exists("fixtures/StarkBridge_vuln.sol"))
        return "fixtures";
    // 2. Alongside the binary (installed via cmake)
    fs::path bin = fs::read_symlink("/proc/self/exe");
    fs::path sibling = bin.parent_path() / "../share/crossguard/fixtures";
    if (fs::exists(sibling / "StarkBridge_vuln.sol"))
        return fs::canonical(sibling);
    return {};
}

static int cmd_demo(const Args& args) {
    fs::path fix = find_fixtures_dir();
    if (fix.empty()) {
        std::cerr <<
            "error: fixture contracts not found.\n"
            "  Run from the crossguard source root, or install with:\n"
            "    sudo make install   (requires CMakeLists.txt to install fixtures)\n";
        return 1;
    }

    std::string l1 = (fix / "StarkBridge_vuln.sol").string();
    std::string l2 = (fix / "bridge_vuln.cairo").string();
    std::cerr << "demo: " << l1 << "\n"
              << "   +  " << l2 << "\n\n";

    try {
        Engine engine;
        AnalysisContext ctx = engine.analyze(l1, l2);
        auto formatter = std::make_unique<TerminalFormatter>(!args.no_color);
        std::cout << formatter->format(ctx.findings, ctx.errors) << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 2;
    }
}

static int cmd_analyze(const Args& args) {
    validate_analyze(args);
    try {
        Engine engine;
        AnalysisContext ctx = engine.analyze(args.l1, args.l2);
        auto formatter = make_formatter(args);
        write_output(formatter->format(ctx.findings, ctx.errors), args);
        return should_fail(ctx, args) ? 1 : 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 2;
    }
}

int main(int argc, char* argv[]) {
    Args args = parse_args(argc, argv);

    if (args.cmd == "analyze")               return cmd_analyze(args);
    if (args.cmd == "demo")                  return cmd_demo(args);
    if (args.cmd == "version")             { show_version(); return 0; }
    if (args.cmd == "--help" || args.cmd == "-h") { show_help(); return 0; }
    if (args.cmd == "--version")           { show_version(); return 0; }

    std::cerr << "error: unknown command: " << args.cmd << "\n\n";
    show_help();
    return 4;
}
