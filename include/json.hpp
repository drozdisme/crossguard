#pragma once

#include <string>
#include <vector>
#include <map>
#include <variant>
#include <memory>
#include <sstream>

namespace nlohmann {

class json {
public:
    using value_t = std::variant<
        std::nullptr_t,
        bool,
        int,
        double,
        std::string,
        std::vector<json>,
        std::map<std::string, json>
    >;

    json() : data(nullptr) {}
    json(std::nullptr_t)               : data(nullptr) {}
    json(bool b)                       : data(b) {}
    json(int i)                        : data(i) {}
    json(double d)                     : data(d) {}
    json(const std::string& s)         : data(s) {}
    json(const char* s)                : data(std::string(s)) {}
    json(const std::vector<json>& v)   : data(v) {}
    json(std::vector<json>&& v)        : data(std::move(v)) {}
    json(const std::map<std::string, json>& m) : data(m) {}

    static json parse(const std::string& str);
    static json parse(std::istream& is);

    std::string dump(int indent = -1) const;

    json& operator[](const std::string& key);
    const json& operator[](const std::string& key) const;
    json& operator[](size_t idx);
    const json& operator[](size_t idx) const;

    bool is_null()   const;
    bool is_bool()   const;
    bool is_number() const;
    bool is_string() const;
    bool is_array()  const;
    bool is_object() const;

    bool        get_bool()   const;
    int         get_int()    const;
    double      get_double() const;
    std::string get_string() const;
    const std::vector<json>&          get_array()  const;
    const std::map<std::string, json>& get_object() const;

    void set_bool(bool b);
    void set_int(int i);
    void set_double(double d);
    void set_string(const std::string& s);

    size_t size()  const;
    bool   empty() const;
    bool   contains(const std::string& key) const;

    void push_back(const json& j);
    void push(const json& j) { push_back(j); }

    std::vector<json>::iterator       begin();
    std::vector<json>::iterator       end();
    std::vector<json>::const_iterator begin() const;
    std::vector<json>::const_iterator end()   const;

private:
    value_t data;
    std::string dump_impl(int indent, int current) const;
};

} // namespace nlohmann
