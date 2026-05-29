#pragma once

#include <string>
#include <vector>
#include <set>
#include "types.hpp"
#include "graph.hpp"

namespace crossguard {

class TaintEngine {
public:
    TaintEngine() = default;
    std::vector<TaintViolation> run(const Graph& graph);

private:
    bool is_user_controllable(const std::string& var, const Handler* h) const;
    bool flows_to_unsafe_operation(const std::string& var,
                                   const std::string& sink_op,
                                   const Handler* h) const;
    std::vector<std::string> find_taint_path(const std::string& src,
                                             const std::string& dst) const;
};

} 
