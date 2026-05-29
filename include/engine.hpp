#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <map>
#include <algorithm>
#include "types.hpp"
#include "graph.hpp"
#include "detectors.hpp"
#include "solidity_parser.hpp"
#include "cairo_parser.hpp"
#include "taint_engine.hpp"
#include "correlator.hpp"

namespace crossguard {

struct AnalysisContext {
    Graph graph;
    std::vector<Finding> findings;
    std::vector<std::string> errors;
    std::vector<TaintViolation> violations;

    bool hasCritical() const {
        return std::any_of(findings.begin(), findings.end(),
            [](const Finding& f) { return f.severity == Severity::CRITICAL; });
    }

    std::map<std::string, int> summary() const {
        std::map<std::string, int> counts;
        counts["CRITICAL"] = 0;
        counts["HIGH"] = 0;
        counts["MEDIUM"] = 0;
        counts["LOW"] = 0;
        
        for (const auto& finding : findings) {
            counts[severity_to_string(finding.severity)]++;
        }
        return counts;
    }
};

class Engine {
public:
    Engine();
    ~Engine() = default;

    void onFinding(std::function<void(const Finding&)> callback) {
        hooks.push_back(callback);
    }

    AnalysisContext analyze(const std::string& l1, const std::string& l2);
    AnalysisContext analyzeData(const std::string& l1Data, const std::string& l2Data);

    void addDetector(std::unique_ptr<BaseDetector> detector) {
        detectors.push_back(std::move(detector));
    }

private:
    std::vector<std::unique_ptr<BaseDetector>> detectors;
    std::vector<std::function<void(const Finding&)>> hooks;

    void loadL1(AnalysisContext& ctx, const std::string& path);
    void loadL1Data(AnalysisContext& ctx, const std::string& data);
    void loadL2(AnalysisContext& ctx, const std::string& path);
    void loadL2Data(AnalysisContext& ctx, const std::string& data);

    void runDetectors(AnalysisContext& ctx);
    void sortFindings(std::vector<Finding>& findings);
    std::string readFile(const std::string& path);
    std::string getExtension(const std::string& path);
};

} 
