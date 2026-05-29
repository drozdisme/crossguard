#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <variant>
#include <iostream>
#include <algorithm>

namespace crossguard {

enum class Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW
};

inline std::string severity_to_string(Severity sev) {
    switch (sev) {
        case Severity::CRITICAL: return "CRITICAL";
        case Severity::HIGH:     return "HIGH";
        case Severity::MEDIUM:   return "MEDIUM";
        case Severity::LOW:      return "LOW";
    }
    return "UNKNOWN";
}

inline Severity severity_from_string(const std::string& s) {
    if (s == "CRITICAL") return Severity::CRITICAL;
    if (s == "HIGH")     return Severity::HIGH;
    if (s == "MEDIUM")   return Severity::MEDIUM;
    if (s == "LOW")      return Severity::LOW;
    return Severity::MEDIUM;
}

struct Location {
    std::string file;
    int line = 0;
    int column = 0;
    std::string selector_or_function;

    std::string to_string() const {
        return file + ":" + std::to_string(line) + ":" + std::to_string(column);
    }
};

struct Finding {
    std::string id;
    Severity severity;
    Location location;
    std::string title;
    std::string description;
    std::vector<std::string> affected_lines;
    std::map<std::string, std::string> metadata;

    Finding(const std::string& det_id, Severity sev, const Location& loc,
            const std::string& t, const std::string& desc)
        : id(det_id), severity(sev), location(loc), title(t), description(desc) {}
};

struct TypeInfo {
    std::string name;
    int bits = 0;
    bool is_array = false;
    bool is_struct = false;
    std::vector<std::string> members;

    bool is_uint256() const { return (name == "uint256") && bits == 256; }
    bool is_u256()    const { return (name == "u256")    && bits == 256; }
    bool is_felt252() const { return  name == "felt252"  && bits == 252; }
};

struct Send {
    std::string selector;
    Location location;
    std::vector<TypeInfo> params;
    bool has_fee_check = false;
    bool has_cancellation_check = false;
    std::vector<std::string> source_lines;
};

struct Handler {
    std::string selector;
    Location location;
    std::vector<TypeInfo> params;
    bool validates_from_address = false;
    std::vector<std::string> assertions;
    std::vector<std::string> source_lines;
};

struct TypeMismatch {
    Send*    send;
    Handler* handler;
    int      param_index;
    TypeInfo l1_type;
    TypeInfo l2_type;
};

struct TaintViolation {
    std::string variable;
    Location source;
    Location sink;
    std::vector<Location> path;
};

struct Cancellation {
    Location location;
    bool has_access_control = false;
    std::vector<std::string> access_checks;
};

} 
