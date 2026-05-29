#pragma once

#include <string>
#include <vector>
#include <memory>
#include "types.hpp"

namespace crossguard {

class BaseFormatter {
public:
    virtual ~BaseFormatter() = default;
    virtual std::string format(const std::vector<Finding>& findings,
                               const std::vector<std::string>& errors) = 0;
};

class TerminalFormatter : public BaseFormatter {
public:
    explicit TerminalFormatter(bool use_color = true) : color_enabled(use_color) {}

    std::string format(const std::vector<Finding>& findings,
                       const std::vector<std::string>& errors) override;

private:
    bool color_enabled;

    static const std::string RED;
    static const std::string YELLOW;
    static const std::string BLUE;
    static const std::string GREEN;
    static const std::string RESET;

    std::string colorize(const Finding& f);
};

class JsonFormatter : public BaseFormatter {
public:
    std::string format(const std::vector<Finding>& findings,
                       const std::vector<std::string>& errors) override;

private:
    std::string escape_json(const std::string& s) const;
};

class SarifFormatter : public BaseFormatter {
public:
    std::string format(const std::vector<Finding>& findings,
                       const std::vector<std::string>& errors) override;

private:
    std::string escape_json(const std::string& s) const;
};

class HtmlFormatter : public BaseFormatter {
public:
    HtmlFormatter(const std::string& l1 = "", const std::string& l2 = "")
        : l1_contract(l1), l2_contract(l2) {}

    std::string format(const std::vector<Finding>& findings,
                       const std::vector<std::string>& errors) override;

private:
    std::string l1_contract;
    std::string l2_contract;

    std::string escape_html(const std::string& s) const;
    std::string get_severity_color(Severity sev) const;
};

} 
