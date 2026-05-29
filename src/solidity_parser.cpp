#include "solidity_parser.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace crossguard {

std::unique_ptr<SoliditySourceParser> SoliditySourceParser::load(const std::string& filepath) {
    auto parser = std::make_unique<SoliditySourceParser>();
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    parser->source = buffer.str();
    return parser;
}

std::vector<Send> SoliditySourceParser::parse_sends() {
    std::vector<Send> sends;
    
    // Look for functions containing "sendMessageToL2"
    std::regex send_func_pattern(
        R"((?:function|external|public)\s+(\w+)\s*\((.*?)\)[^{]*\{([^}]+)\})",
        std::regex::ECMAScript
    );

    std::smatch match;
    std::string::const_iterator searchStart(source.cbegin());
    
    int line_num = 1;
    while (std::regex_search(searchStart, source.cend(), match, send_func_pattern)) {
        std::string func_name = match[1].str();
        std::string params_str = match[2].str();
        std::string body = match[3].str();
        
        // Count lines for location
        line_num += std::count(source.begin(), 
                               source.begin() + std::distance(source.cbegin(), match[0].first),
                               '\n');
        
        if (body.find("sendMessageToL2") != std::string::npos) {
            Send send;
            send.selector = std::to_string(std::hash<std::string>{}(func_name));
            send.location.file = "L1";
            send.location.line = line_num;
            send.location.selector_or_function = func_name;
            send.has_fee_check = has_fee_check(body);
            send.source_lines.push_back(body);
            
            // Parse params
            send.params = extract_params(params_str);
            
            sends.push_back(send);
        }
        
        line_num += std::count(match[0].first, match[0].second, '\n');
        searchStart = match[0].second;
    }
    
    return sends;
}

std::vector<Cancellation> SoliditySourceParser::parse_cancellations() {
    std::vector<Cancellation> cancellations;

    // Match function containing startL1ToL2MessageCancellation, capturing modifier list
    // Pattern: function name(params) [visibility] [modifiers] { ... startL1ToL2... }
    std::regex func_pat(
        R"(function\s+(\w+)\s*\([^)]*\)([^{]*?)\{([^}]*startL1ToL2MessageCancellation[^}]*)\})"
    );

    std::smatch m;
    auto it = source.cbegin();
    while (std::regex_search(it, source.cend(), m, func_pat)) {
        std::string modifiers = m[2].str();
        std::string body      = m[3].str();

        Cancellation canc;
        canc.location.file = "L1";
        canc.location.line = 1 + (int)std::count(
            source.begin(),
            source.begin() + std::distance(source.cbegin(), m[0].first), '\n');

        // Access control: explicit modifier, onlyOwner, require(msg.sender == ...)
        bool mod_ctrl  = modifiers.find("onlyOwner")  != std::string::npos ||
                         modifiers.find("onlyAdmin")  != std::string::npos ||
                         modifiers.find("onlyRole")   != std::string::npos;
        bool body_ctrl = body.find("require(msg.sender") != std::string::npos ||
                         body.find("require (msg.sender") != std::string::npos ||
                         body.find("msg.sender == owner") != std::string::npos ||
                         body.find("_checkOwner")    != std::string::npos;

        canc.has_access_control = mod_ctrl || body_ctrl;
        cancellations.push_back(canc);

        it = m[0].second;
    }

    return cancellations;
}

std::vector<TypeInfo> SoliditySourceParser::extract_params(const std::string& params_str) {
    std::vector<TypeInfo> params;
    
    const std::string delim = ",";
    
    std::string params_copy = params_str;
    size_t prev = 0;
    size_t found = params_copy.find(delim);
    
    while (found != std::string::npos) {
        std::string param = params_copy.substr(prev, found - prev);
        
        // Trim whitespace
        param.erase(0, param.find_first_not_of(" \t"));
        param.erase(param.find_last_not_of(" \t") + 1);
        
        // Extract type (usually last word before identifier)
        std::istringstream iss(param);
        std::string type;
        iss >> type;
        
        TypeInfo ti;
        ti.name = type;
        if (type.find("uint256") != std::string::npos) {
            ti.bits = 256;
        } else if (type.find("uint") != std::string::npos) {
            ti.bits = 256;
        }
        params.push_back(ti);
        
        prev = found + 1;
        found = params_copy.find(delim, prev);
    }
    
    // Last param
    if (prev < params_copy.length()) {
        std::string param = params_copy.substr(prev);
        param.erase(0, param.find_first_not_of(" \t"));
        param.erase(param.find_last_not_of(" \t") + 1);
        
        std::istringstream iss(param);
        std::string type;
        iss >> type;
        
        TypeInfo ti;
        ti.name = type;
        if (type.find("uint256") != std::string::npos) {
            ti.bits = 256;
        } else if (type.find("uint") != std::string::npos) {
            ti.bits = 256;
        }
        params.push_back(ti);
    }
    
    return params;
}

bool SoliditySourceParser::has_fee_check(const std::string& body) {
    return body.find("msg.value") != std::string::npos ||
           body.find(".value(") != std::string::npos ||
           body.find("require") != std::string::npos;
}

std::unique_ptr<SolidityParser> SolidityParser::load_json(const std::string& filepath) {
    auto parser = std::make_unique<SolidityParser>();
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    parser->source = buffer.str();
    parser->is_json_format = true;
    try {
        parser->ast_data = nlohmann::json::parse(parser->source);
    } catch (...) {
        throw std::runtime_error("Invalid JSON in Solidity AST file");
    }
    return parser;
}

std::unique_ptr<SolidityParser> SolidityParser::load_source(const std::string& filepath) {
    auto sp = SoliditySourceParser::load(filepath);
    auto p  = std::make_unique<SolidityParser>();
    p->source = sp->source;
    p->is_json_format = false;
    return p;
}

std::vector<Send> SolidityParser::parse_sends() {
    if (is_json_format) {
        // Parse from JSON AST
        std::vector<Send> sends;
        // This would require parsing solc's AST JSON format
        // For now, return empty
        return sends;
    } else {
        // Parse from source
        auto source_parser = std::make_unique<SoliditySourceParser>();
        source_parser->source = source;
        return source_parser->parse_sends();
    }
}

std::vector<Cancellation> SolidityParser::parse_cancellations() {
    if (is_json_format) {
        return std::vector<Cancellation>();
    } else {
        auto source_parser = std::make_unique<SoliditySourceParser>();
        source_parser->source = source;
        return source_parser->parse_cancellations();
    }
}

} 
