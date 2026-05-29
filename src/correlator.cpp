#include "correlator.hpp"
#include <algorithm>
#include <cstring>
#include <cctype>

namespace crossguard {

static std::string normalize(const std::string& name) {
    std::string r = name;
    // remove common prefixes
    for (const auto& pfx : {"process_", "handle_", "on_"}) {
        if (r.substr(0, strlen(pfx)) == pfx)
            r = r.substr(strlen(pfx));
    }
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

void Correlator::run(Graph& graph) {
    const auto& sends    = graph.get_sends();
    const auto& handlers = graph.get_handlers();

    for (const auto& send : sends) {
        std::string sn = normalize(send->location.selector_or_function);

        for (const auto& handler : handlers) {
            std::string hn = normalize(handler->location.selector_or_function);

            bool name_match = (sn == hn) ||
                              (sn.find(hn) != std::string::npos) ||
                              (hn.find(sn) != std::string::npos);

            bool param_match = params_compatible(send.get(), handler.get());

            if (name_match || param_match) {
                // Record mismatch if types don't align
                if (name_match && !param_match && !send->params.empty()) {
                    for (size_t i = 0; i < std::min(send->params.size(),
                                                     handler->params.size()); ++i) {
                        const auto& sp = send->params[i];
                        const auto& hp = handler->params[i];
                        bool problematic =
                            (sp.name.find("uint256") != std::string::npos && hp.name == "u256") ||
                            (sp.name == "u256" && hp.name.find("uint256") != std::string::npos);
                        if (problematic) {
                            TypeMismatch tm;
                            tm.send        = send.get();
                            tm.handler     = handler.get();
                            tm.param_index = (int)i;
                            tm.l1_type     = sp;
                            tm.l2_type     = hp;
                            graph.add_mismatch(tm);
                        }
                    }
                }
            }
        }
    }
}

std::string Correlator::compute_selector(const std::string& name) const {
    return std::to_string(std::hash<std::string>{}(name));
}

std::string Correlator::hash_selector(const std::string& s) const {
    return compute_selector(s);
}

bool Correlator::params_compatible(const Send* s, const Handler* h) const {
    if (!s || !h) return false;
    if (s->params.size() != h->params.size()) return false;
    for (size_t i = 0; i < s->params.size(); ++i) {
        const auto& sp = s->params[i];
        const auto& hp = h->params[i];
        bool uint_u256 =
            (sp.name.find("uint") != std::string::npos && hp.name == "u256") ||
            (sp.name == "u256" && hp.name.find("uint") != std::string::npos);
        if (!uint_u256 && sp.name != hp.name) return false;
    }
    return true;
}

} 
