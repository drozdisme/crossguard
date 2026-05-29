#include "cairo_parser.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace crossguard {

std::unique_ptr<CairoSourceParser> CairoSourceParser::load(const std::string& path) {
    auto p = std::make_unique<CairoSourceParser>();
    std::ifstream f(path);
    if (!f.is_open())
        throw std::runtime_error("Cannot open file: " + path);
    std::stringstream buf;
    buf << f.rdbuf();
    p->source = buf.str();
    return p;
}

std::vector<TypeInfo> CairoSourceParser::extract_handler_params(const std::string& raw) {
    std::vector<TypeInfo> result;
    std::istringstream ss(raw);
    std::string token;
    while (std::getline(ss, token, ',')) {
        auto trim = [](std::string& t) {
            t.erase(0, t.find_first_not_of(" \t\n\r"));
            auto e = t.find_last_not_of(" \t\n\r");
            if (e != std::string::npos) t.erase(e + 1);
        };
        trim(token);
        if (token.empty()) continue;
        if (token.find("self") != std::string::npos) continue;

        TypeInfo ti;
        auto colon = token.rfind(':');
        if (colon != std::string::npos) {
            ti.name = token.substr(colon + 1);
            ti.name.erase(0, ti.name.find_first_not_of(" \t"));
            auto e = ti.name.find_last_not_of(" \t");
            if (e != std::string::npos) ti.name.erase(e + 1);
        } else {
            ti.name = token;
        }
        if      (ti.name == "u256")    ti.bits = 256;
        else if (ti.name == "u128")    ti.bits = 128;
        else if (ti.name == "felt252") ti.bits = 252;
        result.push_back(ti);
    }
    return result;
}

std::vector<Handler> CairoSourceParser::parse_handlers() {
    std::vector<Handler> handlers;

    std::regex norm(R"(#\[l1_handler\]\s*\n\s*)");
    std::string flat = std::regex_replace(source, norm, "#[l1_handler] ");

    std::regex pat(R"(#\[l1_handler\]\s+fn\s+(\w+)\s*\(([^)]*)\))");
    std::smatch m;

    auto it = flat.cbegin();
    while (std::regex_search(it, flat.cend(), m, pat)) {
        std::string func_name  = m[1].str();
        std::string params_raw = m[2].str();

        auto brace_it = m[0].second;
        while (brace_it != flat.cend() && *brace_it != '{') ++brace_it;
        if (brace_it == flat.cend()) { it = m[0].second; continue; }
        ++brace_it;

        int depth = 1;
        auto body_end = brace_it;
        while (body_end != flat.cend() && depth > 0) {
            if      (*body_end == '{') ++depth;
            else if (*body_end == '}') --depth;
            ++body_end;
        }
        std::string body(brace_it, body_end);

        auto match_pos = (size_t)std::distance(flat.cbegin(), m[0].first);
        int line = 1 + (int)std::count(source.begin(),
                                        source.begin() + match_pos, '\n');

        Handler h;
        h.selector = std::to_string(std::hash<std::string>{}(func_name));
        h.location.file = "L2";
        h.location.line = line;
        h.location.selector_or_function = func_name;
        h.validates_from_address = has_from_address_validation(body);
        h.assertions = extract_assertions(body);
        h.source_lines.push_back(body);
        h.params = extract_handler_params(params_raw);

        handlers.push_back(h);
        it = body_end;
    }

    return handlers;
}

bool CairoSourceParser::has_from_address_validation(const std::string& body) {
    std::regex re(R"(assert\s*[!(]\s*from_address\s*==)");
    return std::regex_search(body, re);
}

std::vector<std::string> CairoSourceParser::extract_assertions(const std::string& body) {
    std::vector<std::string> result;
    std::regex re(R"(assert[!(]\s*([^,)]+))");
    std::smatch m;
    auto it = body.cbegin();
    while (std::regex_search(it, body.cend(), m, re)) {
        result.push_back(m[1].str());
        it = m[0].second;
    }
    return result;
}

std::unique_ptr<CairoParser> CairoParser::load_json(const std::string& path) {
    auto p = std::make_unique<CairoParser>();
    std::ifstream f(path);
    if (!f.is_open())
        throw std::runtime_error("Cannot open file: " + path);
    std::stringstream buf;
    buf << f.rdbuf();
    p->source = buf.str();
    p->is_json_format = true;
    try {
        p->ast_data = nlohmann::json::parse(p->source);
    } catch (...) {
        throw std::runtime_error("Invalid JSON in Cairo AST: " + path);
    }
    return p;
}

std::unique_ptr<CairoParser> CairoParser::load_source(const std::string& path) {
    auto sp = CairoSourceParser::load(path);
    auto p  = std::make_unique<CairoParser>();
    p->source = sp->source;
    p->is_json_format = false;
    return p;
}

std::vector<Handler> CairoParser::parse_handlers() {
    auto sp = std::make_unique<CairoSourceParser>();
    sp->source = source;
    return sp->parse_handlers();
}

} 
