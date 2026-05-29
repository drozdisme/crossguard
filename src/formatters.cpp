#include "formatters.hpp"
#include "json.hpp"
#include <sstream>
#include <map>
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
    ss << (color_enabled ? GREEN : "") << "=== CrossGuard Analysis Report ==="
       << (color_enabled ? RESET : "") << "\n\n";

    for (const auto& f : findings) {
        std::string col = color_enabled ? colorize(f) : "";
        std::string rst = color_enabled ? RESET : "";
        std::string blu = color_enabled ? BLUE  : "";
        ss << col << "[" << severity_to_string(f.severity) << "]" << rst << " "
           << blu << f.id << rst << ": " << f.title << "\n";
        ss << "  Location: " << f.location.to_string() << "\n";
        ss << "  " << f.description << "\n\n";
    }

    std::map<std::string, int> cnt;
    for (const auto& f : findings) cnt[severity_to_string(f.severity)]++;

    ss << "=== Summary ===\n";
    ss << "CRITICAL: " << cnt["CRITICAL"] << "\n";
    ss << "HIGH:     " << cnt["HIGH"]     << "\n";
    ss << "MEDIUM:   " << cnt["MEDIUM"]   << "\n";
    ss << "LOW:      " << cnt["LOW"]      << "\n";
    ss << "Total:    " << findings.size() << " findings\n";

    if (!errors.empty()) {
        ss << "\n=== Errors ===\n";
        for (const auto& e : errors) ss << "  * " << e << "\n";
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

std::string SarifFormatter::format(const std::vector<Finding>& findings,
                                   const std::vector<std::string>&) {
    std::stringstream ss;
    ss << "{\n  \"version\": \"2.1.0\",\n  \"runs\": [{\n";
    ss << "    \"tool\": {\"driver\": {\"name\": \"CrossGuard\", \"version\": \"0.1.0\"}},\n";
    ss << "    \"results\": [\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        std::string lvl = (f.severity == Severity::CRITICAL || f.severity == Severity::HIGH)
                          ? "error" : "warning";
        ss << "      {\n";
        ss << "        \"ruleId\": \""   << escape_json(f.id)          << "\",\n";
        ss << "        \"level\": \""    << lvl                        << "\",\n";
        ss << "        \"message\": {\"text\": \"" << escape_json(f.description) << "\"},\n";
        ss << "        \"locations\": [{\"physicalLocation\": {";
        ss << "\"artifactLocation\": {\"uri\": \"" << escape_json(f.location.file) << "\"},";
        ss << "\"region\": {\"startLine\": " << f.location.line << "}}}]\n";
        ss << "      }" << (i + 1 < findings.size() ? "," : "") << "\n";
    }
    ss << "    ]\n  }]\n}\n";
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
        case Severity::CRITICAL: return "#dc3545";
        case Severity::HIGH:     return "#ff6b6b";
        case Severity::MEDIUM:   return "#ffc107";
        default:                 return "#28a745";
    }
}

std::string HtmlFormatter::format(const std::vector<Finding>& findings,
                                  const std::vector<std::string>& errors) {
    std::stringstream ss;
    ss << R"(<!DOCTYPE html><html><head><title>CrossGuard Report</title>
<style>
body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}
.wrap{max-width:1200px;margin:0 auto;background:#fff;padding:20px;border-radius:8px}
.sum{display:flex;gap:20px;margin:20px 0}
.s{padding:15px;border-radius:4px;color:#fff;text-align:center;min-width:80px}
.finding{border-left:4px solid #ccc;padding:15px;margin:15px 0;background:#fafafa}
.hdr{display:flex;justify-content:space-between}
.ttl{font-weight:bold;font-size:16px}
.sev{padding:4px 8px;border-radius:4px;color:#fff;font-size:12px}
.loc{margin-top:8px;font-size:12px;color:#777}
.desc{margin-top:8px;color:#555}
</style></head><body><div class="wrap">
<h1>CrossGuard Analysis Report</h1>)";

    std::map<std::string, int> cnt;
    for (const auto& f : findings) cnt[severity_to_string(f.severity)]++;

    ss << "<div class=\"sum\">";
    for (auto& [sev, c] : cnt) {
        ss << "<div class=\"s\" style=\"background:"
           << get_severity_color(severity_from_string(sev)) << "\">"
           << c << " " << sev << "</div>";
    }
    ss << "</div><h2>Findings</h2>";

    for (const auto& f : findings) {
        std::string col = get_severity_color(f.severity);
        std::string sev = severity_to_string(f.severity);
        ss << "<div class=\"finding\" style=\"border-left-color:" << col << "\">";
        ss << "<div class=\"hdr\"><div class=\"ttl\">" << escape_html(f.title) << "</div>";
        ss << "<div class=\"sev\" style=\"background:" << col << "\">" << sev << "</div></div>";
        ss << "<div class=\"desc\">" << escape_html(f.description) << "</div>";
        ss << "<div class=\"loc\">" << escape_html(f.location.to_string());
        if (!f.location.selector_or_function.empty())
            ss << " &mdash; " << escape_html(f.location.selector_or_function);
        ss << "</div></div>";
    }

    if (!errors.empty()) {
        ss << "<h2>Errors</h2><ul>";
        for (const auto& e : errors) ss << "<li>" << escape_html(e) << "</li>";
        ss << "</ul>";
    }

    ss << "</div></body></html>";
    return ss.str();
}

} 
