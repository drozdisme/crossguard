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
    if (!is_json_format) {
        auto source_parser = std::make_unique<SoliditySourceParser>();
        source_parser->source = source;
        return source_parser->parse_sends();
    }

    // Parse from solc --ast-json output using our custom nlohmann::json.
    // Helper: safely get a string field from an object node.
    auto str_field = [](const nlohmann::json& node, const std::string& key) -> std::string {
        if (!node.is_object() || !node.contains(key)) return "";
        const auto& v = node[key];
        if (v.is_string()) return v.get_string();
        return "";
    };

    std::vector<Send> sends;
    try {
        // Walk the AST tree recursively collecting sendMessageToL2 calls.
        std::function<void(const nlohmann::json&, const std::string&, int)> walk;
        walk = [&](const nlohmann::json& node, const std::string& fn_name, int base_line) {
            if (!node.is_object()) return;

            std::string nt = str_field(node, "nodeType");

            if (nt == "FunctionCall") {
                if (node.contains("expression") && node["expression"].is_object()) {
                    std::string member = str_field(node["expression"], "memberName");
                    if (member == "sendMessageToL2") {
                        Send send;
                        send.selector = std::to_string(std::hash<std::string>{}(fn_name));
                        send.location.file = "L1";
                        send.location.line = base_line;
                        send.location.selector_or_function = fn_name;
                        // {value: msg.value} shows up as "value" options in solc AST
                        bool has_value = node.contains("options") ||
                                         source.find("{value:") != std::string::npos ||
                                         source.find("{value :") != std::string::npos;
                        send.has_fee_check = has_value;
                        sends.push_back(send);
                    }
                }
            }

            // Recurse into object children
            if (node.is_object()) {
                for (auto& [key, child] : node.get_object()) {
                    if (child.is_object()) walk(child, fn_name, base_line);
                    if (child.is_array()) {
                        for (size_t i = 0; i < child.size(); ++i)
                            walk(child[i], fn_name, base_line);
                    }
                }
            }
        };

        // Find all FunctionDefinition nodes at any depth
        std::function<void(const nlohmann::json&)> find_fns;
        find_fns = [&](const nlohmann::json& node) {
            if (!node.is_object()) return;

            if (str_field(node, "nodeType") == "FunctionDefinition") {
                std::string fn_name = str_field(node, "name");
                if (fn_name.empty()) fn_name = "<unknown>";
                int line = 0;
                if (node.contains("src") && node["src"].is_string()) {
                    std::string src_str = node["src"].get_string();
                    try {
                        size_t offset = std::stoul(src_str.substr(0, src_str.find(':')));
                        line = 1 + (int)std::count(source.begin(),
                                                    source.begin() + std::min(offset, source.size()),
                                                    '\n');
                    } catch (...) {}
                }
                if (node.contains("body") && node["body"].is_object())
                    walk(node["body"], fn_name, line);
                return;
            }

            for (auto& [key, child] : node.get_object()) {
                if (child.is_object()) find_fns(child);
                if (child.is_array()) {
                    for (size_t i = 0; i < child.size(); ++i) find_fns(child[i]);
                }
            }
        };

        find_fns(ast_data);
    } catch (const std::exception&) {
        // Fall back to source-based parsing
        auto source_parser = std::make_unique<SoliditySourceParser>();
        source_parser->source = source;
        return source_parser->parse_sends();
    }
    return sends;
}

std::vector<Cancellation> SolidityParser::parse_cancellations() {
    if (!is_json_format) {
        auto source_parser = std::make_unique<SoliditySourceParser>();
        source_parser->source = source;
        return source_parser->parse_cancellations();
    }

    auto str_field = [](const nlohmann::json& node, const std::string& key) -> std::string {
        if (!node.is_object() || !node.contains(key)) return "";
        const auto& v = node[key];
        if (v.is_string()) return v.get_string();
        return "";
    };

    std::vector<Cancellation> cancellations;
    try {
        std::function<void(const nlohmann::json&, bool, int)> walk;
        walk = [&](const nlohmann::json& node, bool has_access_ctrl, int line) {
            if (!node.is_object()) return;

            std::string nt = str_field(node, "nodeType");

            if (nt == "FunctionDefinition") {
                // Check modifier list
                bool mod_ctrl = false;
                if (node.contains("modifiers") && node["modifiers"].is_array()) {
                    for (size_t i = 0; i < node["modifiers"].size(); ++i) {
                        const auto& mod = node["modifiers"][i];
                        std::string mod_name;
                        if (mod.contains("modifierName"))
                            mod_name = str_field(mod["modifierName"], "name");
                        if (mod_name.find("only") != std::string::npos ||
                            mod_name.find("Owner") != std::string::npos ||
                            mod_name.find("Admin") != std::string::npos)
                            mod_ctrl = true;
                    }
                }
                has_access_ctrl = mod_ctrl;
            }

            // Detect require(msg.sender == ...) by dumping the node as JSON
            if (nt == "ExpressionStatement" || nt == "FunctionCall") {
                std::string raw = node.dump();
                if (raw.find("msg.sender") != std::string::npos &&
                    (raw.find("require") != std::string::npos ||
                     raw.find("revert")  != std::string::npos))
                    has_access_ctrl = true;
            }

            // Detect the target call
            if (nt == "FunctionCall" && node.contains("expression") &&
                node["expression"].is_object()) {
                std::string member = str_field(node["expression"], "memberName");
                if (member == "startL1ToL2MessageCancellation") {
                    Cancellation c;
                    c.location.file = "L1";
                    c.location.line = line;
                    c.has_access_control = has_access_ctrl;
                    cancellations.push_back(c);
                }
            }

            for (auto& [key, child] : node.get_object()) {
                if (child.is_object()) walk(child, has_access_ctrl, line);
                if (child.is_array()) {
                    for (size_t i = 0; i < child.size(); ++i)
                        walk(child[i], has_access_ctrl, line);
                }
            }
        };

        walk(ast_data, false, 0);
    } catch (const std::exception&) {
        auto source_parser = std::make_unique<SoliditySourceParser>();
        source_parser->source = source;
        return source_parser->parse_cancellations();
    }
    return cancellations;
}

} 
