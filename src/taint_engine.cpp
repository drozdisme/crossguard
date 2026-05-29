#include "taint_engine.hpp"
#include <algorithm>

namespace crossguard {

std::vector<TaintViolation> TaintEngine::run(const Graph& graph) {
    std::vector<TaintViolation> violations;
    
    const auto& handlers = graph.get_handlers();
    
    for (const auto& handler : handlers) {
        // Check for user-controllable parameters flowing to unsafe operations
        for (size_t i = 0; i < handler->params.size(); ++i) {
            const auto& param = handler->params[i];
            
            // from_address is user-controllable
            if (param.name == "from_address" || param.name == "caller_address") {
                // Check if it flows to state modification without validation
                if (!handler->validates_from_address) {
                    for (const auto& line : handler->source_lines) {
                        if (line.find("self.") != std::string::npos ||
                            line.find(".write(") != std::string::npos) {
                            TaintViolation violation;
                            violation.variable = param.name;
                            violation.source = handler->location;
                            violation.source.selector_or_function = "parameter: " + param.name;
                            violation.sink = handler->location;
                            violation.sink.selector_or_function = "state modification";
                            violations.push_back(violation);
                            break;
                        }
                    }
                }
            }
        }
    }
    
    return violations;
}

bool TaintEngine::is_user_controllable(const std::string& variable, const Handler* handler) const {
    if (!handler) return false;
    
    // Parameters are user-controllable
    for (const auto& param : handler->params) {
        if (param.name == variable) {
            return true;
        }
    }
    
    return false;
}

bool TaintEngine::flows_to_unsafe_operation(const std::string& var,
                                           const std::string& sink_op,
                                           const Handler* handler) const {
    if (!handler) return false;
    
    for (const auto& line : handler->source_lines) {
        if (line.find(var) != std::string::npos &&
            (line.find(sink_op) != std::string::npos ||
             line.find("self.") != std::string::npos ||
             line.find(".write(") != std::string::npos)) {
            return true;
        }
    }
    
    return false;
}

std::vector<std::string> TaintEngine::find_taint_path(const std::string& source,
                                                      const std::string& sink) const {
    std::vector<std::string> path;
    path.push_back(source);
    path.push_back(sink);
    return path;
}

} 
