#include "detectors.hpp"
#include <algorithm>

namespace crossguard {

// D1: Missing from_address validation
std::vector<Finding> SenderCheckDetector::run(const Graph& graph) {
    std::vector<Finding> findings;
    
    const auto& handlers = graph.get_handlers();
    for (const auto& handler : handlers) {
        if (!handler->validates_from_address) {
            Location loc = handler->location;
            loc.line = handler->location.line;
            
            Finding f = make_finding(
                Severity::CRITICAL,
                loc,
                "Missing from_address validation",
                "Handler does not validate that from_address == registered L1 bridge. "
                "Any Ethereum address can call this handler."
            );
            
            f.affected_lines = handler->source_lines;
            f.metadata["handler"] = handler->location.selector_or_function;
            
            findings.push_back(f);
        }
    }
    
    return findings;
}

bool SenderCheckDetector::validates_sender(const Handler* handler) const {
    if (!handler) return false;
    return handler->validates_from_address;
}

// D2: Type mismatch — uses correlator-populated mismatches
std::vector<Finding> TypeMismatchDetector::run(const Graph& graph) {
    std::vector<Finding> findings;

    for (const auto& tm : graph.get_mismatches()) {
        bool critical = is_problematic_mismatch(tm.l1_type, tm.l2_type);
        Severity sev  = critical ? Severity::CRITICAL : Severity::HIGH;

        Location loc = tm.handler->location;
        std::string l1n = tm.l1_type.name;
        std::string l2n = tm.l2_type.name;

        Finding f = make_finding(
            sev, loc,
            "Type mismatch: " + l1n + " (L1) vs " + l2n + " (L2)",
            "L1 sends " + l1n + " as a single 256-bit word, but L2 expects " + l2n +
            " as two 128-bit limbs (low, high). "
            "This causes silent data corruption in cross-layer messages."
        );
        f.metadata["l1_type"]    = l1n;
        f.metadata["l2_type"]    = l2n;
        f.metadata["param_index"] = std::to_string(tm.param_index);
        f.metadata["l1_fn"]      = tm.send->location.selector_or_function;
        f.metadata["l2_fn"]      = tm.handler->location.selector_or_function;

        findings.push_back(f);
    }

    return findings;
}

bool TypeMismatchDetector::types_match(const TypeInfo& l1_type, const TypeInfo& l2_type) const {
    if ((l1_type.is_uint256() && l2_type.is_u256()) ||
        (l1_type.is_u256() && l2_type.is_uint256())) {
        return true;
    }
    
    // Same types
    return l1_type.name == l2_type.name;
}

bool TypeMismatchDetector::is_problematic_mismatch(const TypeInfo& l1, const TypeInfo& l2) const {
    return (l1.is_uint256() && l2.is_u256()) || (l1.is_u256() && l2.is_uint256());
}

std::vector<Finding> FeeDetector::run(const Graph& graph) {
    std::vector<Finding> findings;
    
    const auto& sends = graph.get_sends();
    for (const auto& send : sends) {
        if (!has_fee_check(send.get())) {
            Location loc = send->location;
            
            Finding f = make_finding(
                Severity::HIGH,
                loc,
                "Missing fee check in sendMessageToL2",
                "sendMessageToL2 call without msg.value verification. "
                "Message may be silently dropped by the sequencer."
            );
            
            f.affected_lines = send->source_lines;
            f.metadata["function"] = send->location.selector_or_function;
            
            findings.push_back(f);
        }
    }
    
    return findings;
}

bool FeeDetector::has_fee_check(const Send* send) const {
    if (!send) return false;
    return send->has_fee_check;
}

// D4: Unrestricted cancellation
std::vector<Finding> CancellationDetector::run(const Graph& graph) {
    std::vector<Finding> findings;
    
    const auto& cancellations = graph.get_cancellations();
    for (const auto& canc : cancellations) {
        if (!has_access_control(canc.get())) {
            Location loc = canc->location;
            
            Finding f = make_finding(
                Severity::HIGH,
                loc,
                "Unrestricted message cancellation",
                "startL1ToL2MessageCancellation without access control. "
                "Anyone can cancel pending messages after L2 processing."
            );
            
            f.metadata["location"] = loc.to_string();
            
            findings.push_back(f);
        }
    }
    
    return findings;
}

bool CancellationDetector::has_access_control(const Cancellation* canc) const {
    if (!canc) return false;
    return canc->has_access_control;
}

// D5: L2-to-L1 replay risk
std::vector<Finding> ReplayRiskDetector::run(const Graph& graph) {
    std::vector<Finding> findings;
    
    const auto& handlers = graph.get_handlers();
    for (const auto& handler : handlers) {
        bool has_send_message = false;
        for (const auto& line : handler->source_lines) {
            if (line.find("send_message_to_l1") != std::string::npos ||
                line.find("send_message") != std::string::npos) {
                has_send_message = true;
                break;
            }
        }
        
        if (has_send_message && !has_nonce_tracking(handler.get())) {
            Location loc = handler->location;
            
            Finding f = make_finding(
                Severity::MEDIUM,
                loc,
                "L2-to-L1 message replay risk",
                "L2 sends message to L1 without nonce/uniqueness tracking. "
                "L1 consumer can call consumeMessageFromL2 multiple times."
            );
            
            f.affected_lines = handler->source_lines;
            f.metadata["handler"] = handler->location.selector_or_function;
            
            findings.push_back(f);
        }
    }
    
    return findings;
}

bool ReplayRiskDetector::has_nonce_tracking(const Handler* handler) const {
    if (!handler) return false;
    
    // Check if source lines contain nonce-related code
    for (const auto& line : handler->source_lines) {
        if (line.find("nonce") != std::string::npos ||
            line.find("uniqueness") != std::string::npos) {
            return true;
        }
    }
    return false;
}

}
