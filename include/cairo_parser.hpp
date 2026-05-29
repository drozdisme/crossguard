#pragma once

#include <string>
#include <vector>
#include <regex>
#include <memory>
#include "types.hpp"
#include "json.hpp"

namespace crossguard {

class CairoParser {
public:
    CairoParser() = default;

    static std::unique_ptr<CairoParser> load_json(const std::string& path);
    static std::unique_ptr<CairoParser> load_source(const std::string& path);

    std::vector<Handler> parse_handlers();

    const std::string& get_source() const { return source; }
    bool is_json() const { return is_json_format; }

protected:
    std::string source;
    bool is_json_format = false;
    nlohmann::json ast_data;

private:
    Handler parse_handler_func(const std::string& func, int line);
    std::string extract_handler_selector(const std::string& func);
    std::vector<TypeInfo> extract_handler_params(const std::string& params);
    bool validates_from_address(const std::string& body);
};

class CairoSourceParser {
public:
    static std::unique_ptr<CairoSourceParser> load(const std::string& path);

    std::vector<Handler> parse_handlers();
    const std::string& get_source() const { return source; }

    std::string source;

private:
    const std::regex l1_handler_pattern =
        std::regex(R"(#\[l1_handler\]\s*(?:fn|func)\s+(\w+)\s*\((.*?)\))");

    const std::regex assert_re =
        std::regex(R"(assert|AssertionError|require)");

    const std::regex addr_re =
        std::regex(R"(from_address|caller_address|message_sender)");

    std::vector<TypeInfo> extract_handler_params(const std::string& params);
    bool has_from_address_validation(const std::string& body);
    std::vector<std::string> extract_assertions(const std::string& body);
};

} 
