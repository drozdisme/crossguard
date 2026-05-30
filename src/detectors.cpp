#include "detectors.hpp"
#include <algorithm>

namespace crossguard {

std::vector<Finding> SenderCheckDetector::run(const Graph& graph) {
    std::vector<Finding> findings;
    for (const auto& h : graph.get_handlers()) {
        if (!h->validates_from_address) {
            Finding f = make_finding(
                Severity::CRITICAL, h->location,
                "Missing from_address validation",
                "Handler does not validate that from_address == registered L1 bridge. "
                "Any Ethereum address can call this handler."
            );
            f.affected_lines = h->source_lines;
            f.metadata["handler"] = h->location.selector_or_function;
            findings.push_back(f);
        }
    }
    return findings;
}

bool SenderCheckDetector::validates_sender(const Handler* h) const {
    return h && h->validates_from_address;
}

std::vector<Finding> TypeMismatchDetector::run(const Graph& graph) {
    std::vector<Finding> findings;
    for (const auto& tm : graph.get_mismatches()) {
        Severity sev = is_problematic_mismatch(tm.l1_type, tm.l2_type)
                     ? Severity::CRITICAL : Severity::HIGH;
        Finding f = make_finding(
            sev, tm.handler->location,
            "Type mismatch: " + tm.l1_type.name + " (L1) vs " + tm.l2_type.name + " (L2)",
            "L1 sends " + tm.l1_type.name + " as a single 256-bit word, but L2 expects "
            + tm.l2_type.name + " as two 128-bit limbs. Silent data corruption."
        );
        f.metadata["l1_type"]     = tm.l1_type.name;
        f.metadata["l2_type"]     = tm.l2_type.name;
        f.metadata["param_index"] = std::to_string(tm.param_index);
        f.metadata["l1_fn"]       = tm.send->location.selector_or_function;
        f.metadata["l2_fn"]       = tm.handler->location.selector_or_function;
        findings.push_back(f);
    }
    return findings;
}

bool TypeMismatchDetector::types_match(const TypeInfo& a, const TypeInfo& b) const {
    if ((a.is_uint256() && b.is_u256()) || (a.is_u256() && b.is_uint256())) return true;
    return a.name == b.name;
}

bool TypeMismatchDetector::is_problematic_mismatch(const TypeInfo& l1, const TypeInfo& l2) const {
    return (l1.is_uint256() && l2.is_u256()) || (l1.is_u256() && l2.is_uint256());
}

std::vector<Finding> FeeDetector::run(const Graph& graph) {
    std::vector<Finding> findings;
    for (const auto& s : graph.get_sends()) {
        if (!s->has_fee_check) {
            Finding f = make_finding(
                Severity::HIGH, s->location,
                "Missing fee check in sendMessageToL2",
                "sendMessageToL2 called without msg.value. "
                "Message may be silently dropped by the sequencer."
            );
            f.affected_lines = s->source_lines;
            f.metadata["function"] = s->location.selector_or_function;
            findings.push_back(f);
        }
    }
    return findings;
}

bool FeeDetector::has_fee_check(const Send* s) const {
    return s && s->has_fee_check;
}

std::vector<Finding> CancellationDetector::run(const Graph& graph) {
    std::vector<Finding> findings;
    for (const auto& c : graph.get_cancellations()) {
        if (!c->has_access_control) {
            Finding f = make_finding(
                Severity::HIGH, c->location,
                "Unrestricted message cancellation",
                "startL1ToL2MessageCancellation without access control. "
                "Anyone can cancel pending messages after L2 processing."
            );
            f.metadata["location"] = c->location.to_string();
            findings.push_back(f);
        }
    }
    return findings;
}

bool CancellationDetector::has_access_control(const Cancellation* c) const {
    return c && c->has_access_control;
}

std::vector<Finding> ReplayRiskDetector::run(const Graph& graph) {
    std::vector<Finding> findings;
    for (const auto& h : graph.get_handlers()) {
        bool sends = false;
        for (const auto& line : h->source_lines) {
            if (line.find("send_message_to_l1") != std::string::npos) {
                sends = true; break;
            }
        }
        if (sends && !has_nonce_tracking(h.get())) {
            Finding f = make_finding(
                Severity::MEDIUM, h->location,
                "L2-to-L1 message replay risk",
                "L2 sends message to L1 without nonce/uniqueness tracking. "
                "L1 consumer can call consumeMessageFromL2 multiple times."
            );
            f.affected_lines = h->source_lines;
            f.metadata["handler"] = h->location.selector_or_function;
            findings.push_back(f);
        }
    }
    return findings;
}

bool ReplayRiskDetector::has_nonce_tracking(const Handler* h) const {
    if (!h) return false;
    for (const auto& line : h->source_lines)
        if (line.find("nonce") != std::string::npos) return true;
    return false;
}

std::vector<Finding> PayloadLengthDetector::run(const Graph& graph) {
    std::vector<Finding> findings;
    for (const auto& h : graph.get_handlers()) {
        size_t fields = 0;
        for (const auto& p : h->params)
            if (p.name != "self" && p.name != "from_address" && p.name != "EthAddress")
                ++fields;
        if (fields < 2) continue;

        if (!has_payload_length_check(h.get())) {
            Finding f = make_finding(
                Severity::MEDIUM, h->location,
                "Unchecked payload length in l1_handler",
                "Handler '" + h->location.selector_or_function + "' decodes "
                + std::to_string(fields) + " fields without asserting payload length."
            );
            f.metadata["handler"]       = h->location.selector_or_function;
            f.metadata["decoded_fields"] = std::to_string(fields);
            findings.push_back(f);
        }
    }
    return findings;
}

bool PayloadLengthDetector::has_payload_length_check(const Handler* h) const {
    if (!h) return false;
    for (const auto& line : h->source_lines) {
        if (line.find("payload.len()")   != std::string::npos ||
            line.find("assert_eq!(")     != std::string::npos ||
            line.find("assert!(payload") != std::string::npos ||
            line.find("pop_front()")     != std::string::npos ||
            line.find("array_len")       != std::string::npos)
            return true;
        if (line.find("Span<felt252>") == std::string::npos)
            return true;
    }
    return false;
}

}
