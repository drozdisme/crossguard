#include "json.hpp"
#include <algorithm>
#include <stdexcept>
#include <cctype>
#include <cmath>
#include <iomanip>

namespace nlohmann {

// Parser helper class
class JsonParser {
private:
    std::string input;
    size_t pos = 0;

public:
    JsonParser(const std::string& str) : input(str) {}

    json parse() {
        skip_whitespace();
        auto result = parse_value();
        skip_whitespace();
        if (pos != input.length()) {
            throw std::runtime_error("Unexpected characters after JSON");
        }
        return result;
    }

private:
    void skip_whitespace() {
        while (pos < input.length() && std::isspace(input[pos])) {
            pos++;
        }
    }

    char peek() const {
        if (pos >= input.length()) return '\0';
        return input[pos];
    }

    char consume() {
        return input[pos++];
    }

    json parse_value() {
        skip_whitespace();
        char c = peek();

        if (c == '{') return parse_object();
        if (c == '[') return parse_array();
        if (c == '"') return parse_string();
        if (c == 't' || c == 'f') return parse_bool();
        if (c == 'n') return parse_null();
        if (c == '-' || std::isdigit(c)) return parse_number();

        throw std::runtime_error("Invalid JSON value");
    }

    json parse_object() {
        consume(); // '{'
        skip_whitespace();

        std::map<std::string, json> obj;

        if (peek() != '}') {
            while (true) {
                skip_whitespace();
                std::string key = parse_string().get_string();
                skip_whitespace();
                
                if (consume() != ':') {
                    throw std::runtime_error("Expected ':' in object");
                }
                
                skip_whitespace();
                obj[key] = parse_value();
                skip_whitespace();

                char c = peek();
                if (c == '}') break;
                if (c != ',') throw std::runtime_error("Expected ',' or '}' in object");
                consume();
            }
        }

        consume(); // '}'
        return json(obj);
    }

    json parse_array() {
        consume(); // '['
        skip_whitespace();

        std::vector<json> arr;

        if (peek() != ']') {
            while (true) {
                arr.push_back(parse_value());
                skip_whitespace();

                char c = peek();
                if (c == ']') break;
                if (c != ',') throw std::runtime_error("Expected ',' or ']' in array");
                consume();
                skip_whitespace();
            }
        }

        consume(); // ']'
        return json(arr);
    }

    json parse_string() {
        consume(); // '"'
        std::string result;

        while (peek() != '"') {
            if (peek() == '\\') {
                consume();
                switch (consume()) {
                    case '"': result += '"'; break;
                    case '\\': result += '\\'; break;
                    case '/': result += '/'; break;
                    case 'b': result += '\b'; break;
                    case 'f': result += '\f'; break;
                    case 'n': result += '\n'; break;
                    case 'r': result += '\r'; break;
                    case 't': result += '\t'; break;
                    default: throw std::runtime_error("Invalid escape sequence");
                }
            } else {
                result += consume();
            }
        }

        consume(); // '"'
        return json(result);
    }

    json parse_number() {
        std::string num_str;
        
        if (peek() == '-') num_str += consume();
        
        while (std::isdigit(peek())) {
            num_str += consume();
        }
        
        if (peek() == '.') {
            num_str += consume();
            while (std::isdigit(peek())) {
                num_str += consume();
            }
        }
        
        if (peek() == 'e' || peek() == 'E') {
            num_str += consume();
            if (peek() == '+' || peek() == '-') {
                num_str += consume();
            }
            while (std::isdigit(peek())) {
                num_str += consume();
            }
        }
        
        if (num_str.find('.') != std::string::npos || 
            num_str.find('e') != std::string::npos ||
            num_str.find('E') != std::string::npos) {
            return json(std::stod(num_str));
        } else {
            return json(std::stoi(num_str));
        }
    }

    json parse_bool() {
        if (input.substr(pos, 4) == "true") {
            pos += 4;
            return json(true);
        } else if (input.substr(pos, 5) == "false") {
            pos += 5;
            return json(false);
        }
        throw std::runtime_error("Invalid boolean value");
    }

    json parse_null() {
        if (input.substr(pos, 4) == "null") {
            pos += 4;
            return json(nullptr);
        }
        throw std::runtime_error("Invalid null value");
    }
};

// Implementation of json class
json json::parse(const std::string& str) {
    JsonParser parser(str);
    return parser.parse();
}

json json::parse(std::istream& is) {
    std::stringstream ss;
    ss << is.rdbuf();
    return parse(ss.str());
}

std::string json::dump(int indent) const {
    return dump_impl(indent, 0);
}

std::string json::dump_impl(int indent, int current_indent) const {
    if (is_null()) return "null";
    if (is_bool()) return get_bool() ? "true" : "false";
    if (is_number()) {
        std::stringstream ss;
        if (std::holds_alternative<int>(data)) {
            ss << get_int();
        } else {
            ss << std::fixed << std::setprecision(6) << get_double();
        }
        return ss.str();
    }
    if (is_string()) {
        std::string s = get_string();
        std::string result = "\"";
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:
                    if (std::isprint(c)) {
                        result += c;
                    } else {
                        result += "\\u00";
                        result += "0123456789abcdef"[c / 16];
                        result += "0123456789abcdef"[c % 16];
                    }
            }
        }
        result += "\"";
        return result;
    }

    if (is_array()) {
        std::string result = "[";
        const auto& arr = get_array();
        for (size_t i = 0; i < arr.size(); ++i) {
            if (indent >= 0) {
                result += "\n";
                result += std::string(current_indent + indent, ' ');
            }
            result += arr[i].dump_impl(indent, current_indent + indent);
            if (i < arr.size() - 1) result += ",";
        }
        if (indent >= 0 && !arr.empty()) {
            result += "\n";
            result += std::string(current_indent, ' ');
        }
        result += "]";
        return result;
    }

    if (is_object()) {
        std::string result = "{";
        const auto& obj = get_object();
        size_t idx = 0;
        for (const auto& [key, value] : obj) {
            if (indent >= 0) {
                result += "\n";
                result += std::string(current_indent + indent, ' ');
            }
            result += "\"" + key + "\":";
            if (indent >= 0) result += " ";
            result += value.dump_impl(indent, current_indent + indent);
            if (++idx < obj.size()) result += ",";
        }
        if (indent >= 0 && !obj.empty()) {
            result += "\n";
            result += std::string(current_indent, ' ');
        }
        result += "}";
        return result;
    }

    return "null";
}

json& json::operator[](const std::string& key) {
    if (!is_object()) {
        data = std::map<std::string, json>();
    }
    return std::get<std::map<std::string, json>>(data)[key];
}

const json& json::operator[](const std::string& key) const {
    if (!is_object()) {
        static json null_json(nullptr);
        return null_json;
    }
    const auto& obj = std::get<std::map<std::string, json>>(data);
    if (obj.find(key) == obj.end()) {
        static json null_json(nullptr);
        return null_json;
    }
    return obj.at(key);
}

json& json::operator[](size_t idx) {
    if (!is_array()) {
        data = std::vector<json>();
    }
    auto& arr = std::get<std::vector<json>>(data);
    if (idx >= arr.size()) {
        arr.resize(idx + 1);
    }
    return arr[idx];
}

const json& json::operator[](size_t idx) const {
    if (!is_array()) {
        static json null_json(nullptr);
        return null_json;
    }
    const auto& arr = std::get<std::vector<json>>(data);
    if (idx >= arr.size()) {
        static json null_json(nullptr);
        return null_json;
    }
    return arr[idx];
}

bool json::is_null() const { return std::holds_alternative<std::nullptr_t>(data); }
bool json::is_bool() const { return std::holds_alternative<bool>(data); }
bool json::is_number() const { 
    return std::holds_alternative<int>(data) || std::holds_alternative<double>(data);
}
bool json::is_string() const { return std::holds_alternative<std::string>(data); }
bool json::is_array() const { return std::holds_alternative<std::vector<json>>(data); }
bool json::is_object() const { return std::holds_alternative<std::map<std::string, json>>(data); }

bool json::get_bool() const { return std::get<bool>(data); }
int json::get_int() const { return std::get<int>(data); }
double json::get_double() const { 
    if (std::holds_alternative<double>(data)) return std::get<double>(data);
    return static_cast<double>(std::get<int>(data));
}
std::string json::get_string() const { return std::get<std::string>(data); }
const std::vector<json>& json::get_array() const { 
    return std::get<std::vector<json>>(data);
}
const std::map<std::string, json>& json::get_object() const {
    return std::get<std::map<std::string, json>>(data);
}

void json::set_bool(bool b) { data = b; }
void json::set_int(int i) { data = i; }
void json::set_double(double d) { data = d; }
void json::set_string(const std::string& s) { data = s; }

size_t json::size() const {
    if (is_array()) return get_array().size();
    if (is_object()) return get_object().size();
    return 0;
}

bool json::empty() const { return size() == 0; }

bool json::contains(const std::string& key) const {
    if (!is_object()) return false;
    return get_object().find(key) != get_object().end();
}

void json::push_back(const json& j) {
    if (!is_array()) {
        data = std::vector<json>();
    }
    std::get<std::vector<json>>(data).push_back(j);
}

std::vector<json>::iterator json::begin() {
    return std::get<std::vector<json>>(data).begin();
}

std::vector<json>::iterator json::end() {
    return std::get<std::vector<json>>(data).end();
}

std::vector<json>::const_iterator json::begin() const {
    return std::get<std::vector<json>>(data).begin();
}

std::vector<json>::const_iterator json::end() const {
    return std::get<std::vector<json>>(data).end();
}

} 
