#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include "types.hpp"

namespace crossguard {

class Graph {
public:
    Graph()                        = default;
    ~Graph()                       = default;
    Graph(Graph&&)                 = default;
    Graph& operator=(Graph&&)      = default;
    Graph(const Graph&)            = delete;
    Graph& operator=(const Graph&) = delete;

    void add_send(const Send& s)             { sends.push_back(std::make_unique<Send>(s)); }
    void add_handler(const Handler& h)       { handlers.push_back(std::make_unique<Handler>(h)); }
    void add_cancellation(const Cancellation& c) { cancellations.push_back(std::make_unique<Cancellation>(c)); }

    // Keep camelCase aliases used by engine.cpp
    void addSend(const Send& s)             { add_send(s); }
    void addHandler(const Handler& h)       { add_handler(h); }
    void addCancellation(const Cancellation& c) { add_cancellation(c); }

    const std::vector<std::unique_ptr<Send>>&          get_sends()         const { return sends; }
    const std::vector<std::unique_ptr<Handler>>&        get_handlers()      const { return handlers; }
    const std::vector<std::unique_ptr<Cancellation>>&  get_cancellations() const { return cancellations; }

    Handler* find_handler_by_selector(const std::string& sel) {
        for (auto& h : handlers)
            if (h->selector == sel) return h.get();
        return nullptr;
    }

    Send* find_send_by_selector(const std::string& sel) {
        for (auto& s : sends)
            if (s->selector == sel) return s.get();
        return nullptr;
    }

    const std::vector<TypeMismatch>&   get_mismatches()  const { return mismatches; }
    const std::vector<TaintViolation>& get_violations()  const { return violations; }

    void add_mismatch(const TypeMismatch& tm)   { mismatches.push_back(tm); }
    void add_violation(const TaintViolation& tv) { violations.push_back(tv); }

    size_t send_count()         const { return sends.size(); }
    size_t handler_count()      const { return handlers.size(); }
    size_t cancellation_count() const { return cancellations.size(); }

private:
    std::vector<std::unique_ptr<Send>>         sends;
    std::vector<std::unique_ptr<Handler>>       handlers;
    std::vector<std::unique_ptr<Cancellation>>  cancellations;
    std::vector<TypeMismatch>   mismatches;
    std::vector<TaintViolation> violations;
};

} 
