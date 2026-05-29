#pragma once

#include <string>
#include <vector>
#include "types.hpp"
#include "graph.hpp"

namespace crossguard {

class Correlator {
public:
    Correlator() = default;
    void run(Graph& graph);

private:
    std::string compute_selector(const std::string& name) const;
    std::string hash_selector(const std::string& selector) const;
    bool params_compatible(const Send* send, const Handler* handler) const;
};

} 
