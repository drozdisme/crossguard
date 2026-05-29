#pragma once

#include <string>
#include <vector>
#include <regex>
#include <memory>
#include "types.hpp"
#include "json.hpp"

namespace crossguard {

class SolidityParser {
public:
    SolidityParser() = default;

    static std::unique_ptr<SolidityParser> load_json(const std::string& path);
    static std::unique_ptr<SolidityParser> load_source(const std::string& path);

    std::vector<Send>         parse_sends();
    std::vector<Cancellation> parse_cancellations();

    const std::string& get_source() const { return source; }
    bool is_json() const { return is_json_format; }

protected:
    std::string source;
    bool is_json_format = false;
    nlohmann::json ast_data;

private:
    Send         parse_send_func(const std::string& func, int line);
    Cancellation parse_cancel_func(const std::string& func, int line);
    std::vector<TypeInfo> extract_params(const std::string& params);
    std::string extract_selector(const std::string& name);
    bool has_fee_check(const std::string& body);
    bool has_cancel_check(const std::string& body);
};

class SoliditySourceParser {
public:
    static std::unique_ptr<SoliditySourceParser> load(const std::string& path);

    std::vector<Send>         parse_sends();
    std::vector<Cancellation> parse_cancellations();

    const std::string& get_source() const { return source; }

    std::string source;

private:
    const std::regex func_pattern =
        std::regex(R"(function\s+(\w+)\s*\((.*?)\)\s*(?:public|external|internal)?\s*(?:payable)?\s*\{)");

    const std::regex send_msg_pattern =
        std::regex(R"(sendMessageToL2\s*\()");

    const std::regex fee_pattern =
        std::regex(R"(msg\.value|\.value\s*\(|require\s*\(\s*msg\.value)");

    std::vector<std::string>  extract_functions();
    std::vector<TypeInfo>     extract_params(const std::string& params);
    bool is_send_func(const std::string& body);
    bool is_cancel_func(const std::string& body);
    bool has_fee_check(const std::string& body);
    bool has_access_control(const std::string& body);
};

} 
