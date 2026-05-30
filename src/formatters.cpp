#include "formatters.hpp"
#include "json.hpp"
#include <sstream>
#include <map>
#include <set>
#include <algorithm>

namespace crossguard {

const std::string TerminalFormatter::RED    = "\033[31m";
const std::string TerminalFormatter::YELLOW = "\033[33m";
const std::string TerminalFormatter::BLUE   = "\033[34m";
const std::string TerminalFormatter::GREEN  = "\033[32m";
const std::string TerminalFormatter::RESET  = "\033[0m";

std::string TerminalFormatter::colorize(const Finding& f) {
    switch (f.severity) {
        case Severity::CRITICAL: return RED;
        case Severity::HIGH:     return YELLOW;
        case Severity::MEDIUM:   return BLUE;
        default:                 return GREEN;
    }
}

std::string TerminalFormatter::format(const std::vector<Finding>& findings,
                                      const std::vector<std::string>& errors) {
    std::stringstream ss;

    const std::string BOLD  = color_enabled ? "\033[1m"  : "";
    const std::string DIM   = color_enabled ? "\033[2m"  : "";
    const std::string rst   = color_enabled ? RESET : "";

    if (findings.empty() && errors.empty()) {
        ss << (color_enabled ? GREEN : "") << BOLD
           << "✓ No findings — bridge contracts look clean."
           << rst << "\n";
        return ss.str();
    }

    for (const auto& f : findings) {
        std::string col  = color_enabled ? colorize(f) : "";
        std::string blu  = color_enabled ? BLUE  : "";
        std::string sev  = severity_to_string(f.severity);

        // ── severity badge + detector id + title ─────────────────────────────
        ss << col << BOLD << "[" << sev << "]" << rst << "  "
           << blu << f.id << rst
           << "  " << BOLD << f.title << rst << "\n";

        // ── location line ─────────────────────────────────────────────────────
        ss << "  " << DIM << "at " << f.location.file;
        if (f.location.line > 0)
            ss << ":" << f.location.line;
        if (!f.location.selector_or_function.empty())
            ss << "  (" << f.location.selector_or_function << ")";
        ss << rst << "\n";

        // ── description ───────────────────────────────────────────────────────
        ss << "  " << f.description << "\n";

        // ── code snippet (first non-empty affected_line, trimmed) ─────────────
        for (const auto& line : f.affected_lines) {
            // trim and show only first 120 chars to keep output readable
            std::string trimmed = line;
            auto start = trimmed.find_first_not_of(" \t\n\r");
            if (start != std::string::npos) trimmed = trimmed.substr(start);
            if (trimmed.size() > 120) trimmed = trimmed.substr(0, 117) + "...";
            if (!trimmed.empty()) {
                ss << "\n" << DIM << "  ┌─ snippet ───\n";
                // print at most first 4 lines of the body
                std::istringstream lines(trimmed);
                std::string l;
                int cnt = 0;
                while (std::getline(lines, l) && cnt < 4) {
                    ss << "  │ " << l << "\n";
                    ++cnt;
                }
                if (cnt == 4) ss << "  │ ...\n";
                ss << "  └─────────────" << rst << "\n";
                break;  // one snippet per finding
            }
        }

        ss << "\n";
    }

    // ── summary bar ──────────────────────────────────────────────────────────
    std::map<std::string, int> cnt;
    for (const auto& f : findings) cnt[severity_to_string(f.severity)]++;

    ss << (color_enabled ? "\033[2m" : "") << std::string(54, '-') << rst << "\n";
    ss << BOLD << "Summary" << rst << "  ";

    auto print_count = [&](const std::string& sev, const std::string& col) {
        if (cnt.count(sev) && cnt[sev] > 0)
            ss << (color_enabled ? col : "") << cnt[sev] << " " << sev << rst << "  ";
    };
    print_count("CRITICAL", RED);
    print_count("HIGH",     YELLOW);
    print_count("MEDIUM",   BLUE);
    print_count("LOW",      GREEN);
    ss << DIM << findings.size() << " total" << rst << "\n";

    if (!errors.empty()) {
        ss << "\n" << (color_enabled ? RED : "") << "Errors:" << rst << "\n";
        for (const auto& e : errors) ss << "  ✗ " << e << "\n";
    }
    return ss.str();
}

// JSON formatter — builds JSON manually to avoid nlohmann initializer-list issues
std::string JsonFormatter::escape_json(const std::string& s) const {
    std::string r;
    for (char c : s) {
        switch (c) {
            case '"':  r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\b': r += "\\b";  break;
            case '\f': r += "\\f";  break;
            case '\n': r += "\\n";  break;
            case '\r': r += "\\r";  break;
            case '\t': r += "\\t";  break;
            default:   r += c;
        }
    }
    return r;
}

std::string JsonFormatter::format(const std::vector<Finding>& findings,
                                  const std::vector<std::string>& errors) {
    std::stringstream ss;
    ss << "{\n  \"findings\": [\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        ss << "    {\n";
        ss << "      \"id\": \""          << escape_json(f.id)                        << "\",\n";
        ss << "      \"severity\": \""    << severity_to_string(f.severity)           << "\",\n";
        ss << "      \"title\": \""       << escape_json(f.title)                     << "\",\n";
        ss << "      \"description\": \"" << escape_json(f.description)               << "\",\n";
        ss << "      \"file\": \""        << escape_json(f.location.file)             << "\",\n";
        ss << "      \"line\": "          << f.location.line                          << ",\n";
        ss << "      \"function\": \""    << escape_json(f.location.selector_or_function) << "\"\n";
        ss << "    }" << (i + 1 < findings.size() ? "," : "") << "\n";
    }
    ss << "  ],\n";
    ss << "  \"errors\": [\n";
    for (size_t i = 0; i < errors.size(); ++i) {
        ss << "    \"" << escape_json(errors[i]) << "\""
           << (i + 1 < errors.size() ? "," : "") << "\n";
    }
    ss << "  ],\n";
    ss << "  \"count\": " << findings.size() << "\n";
    ss << "}\n";
    return ss.str();
}

// SARIF formatter
std::string SarifFormatter::escape_json(const std::string& s) const {
    std::string r;
    for (char c : s) {
        switch (c) {
            case '"':  r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n";  break;
            case '\r': r += "\\r";  break;
            case '\t': r += "\\t";  break;
            default:   r += c;
        }
    }
    return r;
}

// Map CrossGuard severity → SARIF level (error/warning/note)
static std::string sarif_level(Severity sev) {
    switch (sev) {
        case Severity::CRITICAL: return "error";
        case Severity::HIGH:     return "error";
        case Severity::MEDIUM:   return "warning";
        case Severity::LOW:      return "note";
    }
    return "warning";
}

// Map CrossGuard severity → SARIF security-severity score (for GitHub Advanced Security)
static std::string sarif_security_severity(Severity sev) {
    switch (sev) {
        case Severity::CRITICAL: return "9.5";
        case Severity::HIGH:     return "7.5";
        case Severity::MEDIUM:   return "5.0";
        case Severity::LOW:      return "2.5";
    }
    return "5.0";
}

struct RuleMeta {
    std::string id;
    std::string name;
    std::string short_desc;
    std::string full_desc;
    std::string help_uri;
};

static std::vector<RuleMeta> sarif_rules() {
    return {
        {"D1", "MissingFromAddressValidation",
         "l1_handler missing from_address check",
         "An #[l1_handler] function does not assert that from_address equals the registered L1 "
         "bridge contract. Any Ethereum address can invoke this handler and trigger state changes on L2.",
         "https://github.com/crossguard/crossguard/blob/main/README.md#d1--missing-from_address-validation-critical"},
        {"D2", "TypeEncodingMismatch",
         "uint256/u256 encoding mismatch between L1 and L2",
         "L1 sends a uint256 as a single 256-bit ABI word, but the L2 handler expects u256 "
         "as two separate felt252 values (low: u128, high: u128). This causes silent data corruption.",
         "https://github.com/crossguard/crossguard/blob/main/README.md#d2--uint256u256-encoding-mismatch-critical"},
        {"D3", "MissingFeeForwarding",
         "sendMessageToL2 called without msg.value",
         "A sendMessageToL2 call does not forward ETH as a fee. The Starknet sequencer "
         "silently drops messages without sufficient fee, causing permanent loss of user funds.",
         "https://github.com/crossguard/crossguard/blob/main/README.md#d3--missing-fee-forwarding-high"},
        {"D4", "UnrestrictedMessageCancellation",
         "startL1ToL2MessageCancellation without access control",
         "Anyone can call startL1ToL2MessageCancellation and cancel pending messages after L2 "
         "has already processed them, enabling double-spend or griefing attacks.",
         "https://github.com/crossguard/crossguard/blob/main/README.md#d4--unrestricted-cancellation-high"},
        {"D5", "L2ToL1ReplayRisk",
         "L2-to-L1 message without nonce tracking",
         "An L2 handler sends a message to L1 without recording a uniqueness nonce. "
         "The L1 consumer can call consumeMessageFromL2 multiple times, allowing replay attacks.",
         "https://github.com/crossguard/crossguard/blob/main/README.md#d5--l2-to-l1-replay-risk-medium"},
        {"D6", "UncheckedPayloadLength",
         "L1 message payload length not validated before decode",
         "An #[l1_handler] decodes message payload fields without first asserting the payload "
         "length. A short payload causes out-of-bounds reads with undefined behaviour.",
         "https://github.com/crossguard/crossguard/blob/main/README.md#d6-unchecked-payload-length"},
    };
}

std::string SarifFormatter::format(const std::vector<Finding>& findings,
                                   const std::vector<std::string>&) {
    auto ej = [&](const std::string& s) { return escape_json(s); };

    // Collect the rule IDs that actually appear in findings
    std::set<std::string> used_ids;
    for (const auto& f : findings) used_ids.insert(f.id);
    auto rules = sarif_rules();

    std::stringstream ss;
    ss << "{\n";
    ss << "  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n";
    ss << "  \"version\": \"2.1.0\",\n";
    ss << "  \"runs\": [\n    {\n";

    // ── tool.driver with rules ────────────────────────────────────────────────
    ss << "      \"tool\": {\n";
    ss << "        \"driver\": {\n";
    ss << "          \"name\": \"CrossGuard\",\n";
    ss << "          \"version\": \"0.1.0\",\n";
    ss << "          \"informationUri\": \"https://github.com/crossguard/crossguard\",\n";
    ss << "          \"rules\": [\n";

    bool first_rule = true;
    for (const auto& r : rules) {
        if (!first_rule) ss << ",\n";
        first_rule = false;
        ss << "            {\n";
        ss << "              \"id\": \""         << ej(r.id)         << "\",\n";
        ss << "              \"name\": \""        << ej(r.name)       << "\",\n";
        ss << "              \"shortDescription\": {\"text\": \"" << ej(r.short_desc) << "\"},\n";
        ss << "              \"fullDescription\":  {\"text\": \"" << ej(r.full_desc)  << "\"},\n";
        ss << "              \"helpUri\": \""      << ej(r.help_uri)  << "\",\n";
        ss << "              \"properties\": {\"tags\": [\"security\", \"starknet\", \"bridge\"]}\n";
        ss << "            }";
    }
    ss << "\n          ]\n";
    ss << "        }\n";
    ss << "      },\n";

    // ── results ───────────────────────────────────────────────────────────────
    ss << "      \"results\": [\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        std::string lvl      = sarif_level(f.severity);
        std::string sec_sev  = sarif_security_severity(f.severity);

        if (i > 0) ss << ",\n";
        ss << "        {\n";
        ss << "          \"ruleId\": \""     << ej(f.id)          << "\",\n";
        ss << "          \"level\": \""      << lvl               << "\",\n";
        ss << "          \"message\": {\"text\": \"" << ej(f.title + ". " + f.description) << "\"},\n";
        ss << "          \"locations\": [{\n";
        ss << "            \"physicalLocation\": {\n";
        ss << "              \"artifactLocation\": {\"uri\": \"" << ej(f.location.file) << "\"},\n";
        ss << "              \"region\": {\"startLine\": " << (f.location.line > 0 ? f.location.line : 1);
        if (f.location.column > 0)
            ss << ", \"startColumn\": " << f.location.column;
        ss << "}\n";
        ss << "            }\n";
        ss << "          }],\n";
        ss << "          \"properties\": {\n";
        ss << "            \"severity\": \""          << ej(severity_to_string(f.severity)) << "\",\n";
        ss << "            \"security-severity\": \"" << sec_sev                            << "\",\n";
        ss << "            \"function\": \""          << ej(f.location.selector_or_function) << "\"\n";
        ss << "          }\n";
        ss << "        }";
    }
    ss << "\n      ]\n";
    ss << "    }\n  ]\n}\n";
    return ss.str();
}

// HTML formatter
std::string HtmlFormatter::escape_html(const std::string& s) const {
    std::string r;
    for (char c : s) {
        switch (c) {
            case '&':  r += "&amp;";  break;
            case '<':  r += "&lt;";   break;
            case '>':  r += "&gt;";   break;
            case '"':  r += "&quot;"; break;
            case '\'': r += "&#39;";  break;
            default:   r += c;
        }
    }
    return r;
}

std::string HtmlFormatter::get_severity_color(Severity sev) const {
    switch (sev) {
        case Severity::CRITICAL: return "#b91c1c";
        case Severity::HIGH:     return "#c2410c";
        case Severity::MEDIUM:   return "#b45309";
        default:                 return "#15803d";
    }
}

std::string HtmlFormatter::format(const std::vector<Finding>& findings,
                                  const std::vector<std::string>& errors) {
    std::map<std::string, int> cnt;
    for (const auto& f : findings) cnt[severity_to_string(f.severity)]++;

    std::stringstream ss;
    ss << R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CrossGuard Security Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#0f172a;color:#e2e8f0;min-height:100vh;padding:2rem 1rem}
.container{max-width:900px;margin:0 auto}
header{border-bottom:1px solid #1e293b;padding-bottom:1.5rem;margin-bottom:2rem}
.logo{font-size:1.5rem;font-weight:700;color:#f8fafc;letter-spacing:-0.02em}
.logo span{color:#f97316}
.subtitle{color:#64748b;font-size:.875rem;margin-top:.25rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:1rem;margin-bottom:2rem}
.stat{background:#1e293b;border:1px solid #334155;border-radius:.75rem;
      padding:1rem;text-align:center}
.stat .num{font-size:2rem;font-weight:700;line-height:1}
.stat .lbl{font-size:.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-top:.25rem}
.stat.critical .num{color:#ef4444}
.stat.high .num{color:#f97316}
.stat.medium .num{color:#f59e0b}
.stat.low .num{color:#22c55e}
.stat.total .num{color:#94a3b8}
.section-title{font-size:.875rem;font-weight:600;text-transform:uppercase;
               letter-spacing:.1em;color:#64748b;margin-bottom:1rem}
.finding{background:#1e293b;border:1px solid #334155;border-radius:.75rem;
         padding:1.25rem;margin-bottom:1rem;border-left:4px solid}
.finding-header{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:.75rem}
.finding-title{font-weight:600;font-size:1rem;color:#f8fafc;flex:1}
.badge{padding:.25rem .625rem;border-radius:9999px;font-size:.75rem;
       font-weight:600;text-transform:uppercase;letter-spacing:.05em;
       white-space:nowrap;color:#fff}
.finding-meta{display:flex;gap:1.5rem;font-size:.8125rem;color:#64748b;margin-bottom:.75rem}
.finding-meta span{display:flex;align-items:center;gap:.25rem}
.det-id{background:#0f172a;border:1px solid #334155;border-radius:.375rem;
        padding:.125rem .5rem;font-family:monospace;font-size:.75rem;color:#94a3b8}
.desc{font-size:.875rem;color:#cbd5e1;line-height:1.6}
.snippet{background:#0f172a;border:1px solid #1e293b;border-radius:.5rem;
         padding:.75rem 1rem;margin-top:.75rem;font-family:monospace;
         font-size:.8125rem;color:#94a3b8;white-space:pre-wrap;word-break:break-all;
         max-height:120px;overflow:hidden}
.errors{background:#1e293b;border:1px solid #dc2626;border-radius:.75rem;
        padding:1.25rem;margin-top:1rem}
.errors h3{color:#ef4444;font-size:.875rem;margin-bottom:.5rem}
.errors ul{list-style:none;font-size:.8125rem;color:#fca5a5}
.errors li::before{content:"✗ ";color:#ef4444}
.clean{text-align:center;padding:3rem;color:#22c55e;font-size:1.125rem}
footer{text-align:center;color:#475569;font-size:.75rem;margin-top:3rem;padding-top:1.5rem;
       border-top:1px solid #1e293b}
</style>
</head>
<body>
<div class="container">
<header>
  <div class="logo">Cross<span>Guard</span></div>
  <div class="subtitle">Starknet Bridge Security Analyzer — Static Analysis Report</div>
</header>
)";

    // Stats
    ss << "<div class=\"stats\">\n";
    auto stat = [&](const std::string& cls, const std::string& label, int n) {
        ss << "  <div class=\"stat " << cls << "\">"
           << "<div class=\"num\">" << n << "</div>"
           << "<div class=\"lbl\">" << label << "</div>"
           << "</div>\n";
    };
    stat("critical", "Critical", cnt["CRITICAL"]);
    stat("high",     "High",     cnt["HIGH"]);
    stat("medium",   "Medium",   cnt["MEDIUM"]);
    stat("low",      "Low",      cnt["LOW"]);
    stat("total",    "Total",    (int)findings.size());
    ss << "</div>\n";

    if (findings.empty()) {
        ss << "<div class=\"clean\">✓ No security findings — bridge contracts look clean.</div>\n";
    } else {
        ss << "<div class=\"section-title\">Findings</div>\n";
        for (const auto& f : findings) {
            std::string col = get_severity_color(f.severity);
            std::string sev = severity_to_string(f.severity);
            std::string cls = sev;
            std::transform(cls.begin(), cls.end(), cls.begin(), ::tolower);

            ss << "<div class=\"finding\" style=\"border-left-color:" << col << "\">\n";
            ss << "  <div class=\"finding-header\">\n";
            ss << "    <div class=\"finding-title\">" << escape_html(f.title) << "</div>\n";
            ss << "    <span class=\"badge\" style=\"background:" << col << "\">" << sev << "</span>\n";
            ss << "  </div>\n";

            ss << "  <div class=\"finding-meta\">\n";
            ss << "    <span><span class=\"det-id\">" << escape_html(f.id) << "</span></span>\n";
            ss << "    <span>📄 " << escape_html(f.location.file);
            if (f.location.line > 0) ss << ":" << f.location.line;
            ss << "</span>\n";
            if (!f.location.selector_or_function.empty())
                ss << "    <span>ƒ " << escape_html(f.location.selector_or_function) << "</span>\n";
            ss << "  </div>\n";

            ss << "  <div class=\"desc\">" << escape_html(f.description) << "</div>\n";

            // Code snippet
            for (const auto& line : f.affected_lines) {
                std::string trimmed = line;
                auto s = trimmed.find_first_not_of(" \t\n\r");
                if (s != std::string::npos) trimmed = trimmed.substr(s);
                if (!trimmed.empty()) {
                    if (trimmed.size() > 400) trimmed = trimmed.substr(0, 397) + "...";
                    ss << "  <div class=\"snippet\">" << escape_html(trimmed) << "</div>\n";
                    break;
                }
            }
            ss << "</div>\n";
        }
    }

    if (!errors.empty()) {
        ss << "<div class=\"errors\">\n<h3>Analysis Errors</h3><ul>\n";
        for (const auto& e : errors) ss << "<li>" << escape_html(e) << "</li>\n";
        ss << "</ul></div>\n";
    }

    ss << "<footer>Generated by CrossGuard v0.1.0 &mdash; "
          "<a href=\"https://github.com/crossguard/crossguard\" style=\"color:#475569\">"
          "github.com/crossguard/crossguard</a></footer>\n";
    ss << "</div></body></html>\n";
    return ss.str();
}

} 
