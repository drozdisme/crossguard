#pragma once

#include <string>
#include <vector>
#include <memory>
#include "types.hpp"
#include "graph.hpp"

namespace crossguard {

class BaseDetector {
public:
    virtual ~BaseDetector() = default;

    virtual std::string id()          const = 0;
    virtual std::string name()        const = 0;
    virtual std::string description() const = 0;
    virtual std::vector<Finding> run(const Graph& graph) = 0;

protected:
    Finding make_finding(Severity sev, const Location& loc,
                         const std::string& title, const std::string& desc) {
        return Finding(id(), sev, loc, title, desc);
    }
};

class SenderCheckDetector : public BaseDetector {
public:
    std::string id()          const override { return "D1"; }
    std::string name()        const override { return "Missing from_address validation"; }
    std::string description() const override {
        return "l1_handler does not assert from_address == l1_bridge";
    }
    std::vector<Finding> run(const Graph& graph) override;

private:
    bool validates_sender(const Handler* h) const;
};

class TypeMismatchDetector : public BaseDetector {
public:
    std::string id()          const override { return "D2"; }
    std::string name()        const override { return "Type mismatch between L1 and L2"; }
    std::string description() const override {
        return "uint256 and u256 encoding mismatch (256-bit vs two u128s)";
    }
    std::vector<Finding> run(const Graph& graph) override;

private:
    bool types_match(const TypeInfo& l1, const TypeInfo& l2) const;
    bool is_problematic_mismatch(const TypeInfo& l1, const TypeInfo& l2) const;
};

class FeeDetector : public BaseDetector {
public:
    std::string id()          const override { return "D3"; }
    std::string name()        const override { return "Missing fee forwarding"; }
    std::string description() const override {
        return "sendMessageToL2 without fee check - message may be silently dropped";
    }
    std::vector<Finding> run(const Graph& graph) override;

private:
    bool has_fee_check(const Send* s) const;
};

class CancellationDetector : public BaseDetector {
public:
    std::string id()          const override { return "D4"; }
    std::string name()        const override { return "Unrestricted message cancellation"; }
    std::string description() const override {
        return "startL1ToL2MessageCancellation without proper access control";
    }
    std::vector<Finding> run(const Graph& graph) override;

private:
    bool has_access_control(const Cancellation* c) const;
};

class ReplayRiskDetector : public BaseDetector {
public:
    std::string id()          const override { return "D5"; }
    std::string name()        const override { return "L2-to-L1 message replay risk"; }
    std::string description() const override {
        return "send_message_to_l1_syscall without nonce tracking allows replay";
    }
    std::vector<Finding> run(const Graph& graph) override;

private:
    bool has_nonce_tracking(const Handler* h) const;
};

class PayloadLengthDetector : public BaseDetector {
public:
    std::string id()          const override { return "D6"; }
    std::string name()        const override { return "Unchecked payload length"; }
    std::string description() const override {
        return "l1_handler decodes payload fields without asserting payload length";
    }
    std::vector<Finding> run(const Graph& graph) override;

private:
    // Returns true if the handler body verifies payload size before field access
    bool has_payload_length_check(const Handler* h) const;
};

} 
