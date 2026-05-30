#include "engine.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

namespace crossguard {

Engine::Engine() {
    detectors.push_back(std::make_unique<SenderCheckDetector>());
    detectors.push_back(std::make_unique<TypeMismatchDetector>());
    detectors.push_back(std::make_unique<FeeDetector>());
    detectors.push_back(std::make_unique<CancellationDetector>());
    detectors.push_back(std::make_unique<ReplayRiskDetector>());
    detectors.push_back(std::make_unique<PayloadLengthDetector>());
}

AnalysisContext Engine::analyze(const std::string& l1, const std::string& l2) {
    AnalysisContext ctx;
    
    loadL1(ctx, l1);
    loadL2(ctx, l2);
    
    Correlator().run(ctx.graph);
    ctx.violations = TaintEngine().run(ctx.graph);
    
    runDetectors(ctx);
    sortFindings(ctx.findings);
    
    return ctx;
}

AnalysisContext Engine::analyzeData(const std::string& l1Data, const std::string& l2Data) {
    AnalysisContext ctx;
    
    loadL1Data(ctx, l1Data);
    loadL2Data(ctx, l2Data);
    
    Correlator().run(ctx.graph);
    ctx.violations = TaintEngine().run(ctx.graph);
    
    runDetectors(ctx);
    sortFindings(ctx.findings);
    
    return ctx;
}

void Engine::runDetectors(AnalysisContext& ctx) {
    for (auto& detector : detectors) {
        try {
            auto findings = detector->run(ctx.graph);
            for (auto& finding : findings) {
                ctx.findings.push_back(finding);
                for (auto& hook : hooks) {
                    hook(finding);
                }
            }
        } catch (const std::exception& e) {
            ctx.errors.push_back("[" + detector->id() + "] " + std::string(e.what()));
        }
    }
}

void Engine::sortFindings(std::vector<Finding>& findings) {
    std::sort(findings.begin(), findings.end(),
        [](const Finding& a, const Finding& b) {
            int aSev = static_cast<int>(a.severity);
            int bSev = static_cast<int>(b.severity);
            if (aSev != bSev) return aSev < bSev;
            return a.location.to_string() < b.location.to_string();
        });
}

void Engine::loadL1(AnalysisContext& ctx, const std::string& path) {
    try {
        std::string ext = getExtension(path);
        
        if (ext == ".sol") {
            auto parser = SoliditySourceParser::load(path);
            for (auto send : parser->parse_sends()) {
                ctx.graph.addSend(send);
            }
            for (auto canc : parser->parse_cancellations()) {
                ctx.graph.addCancellation(canc);
            }
        } else if (ext == ".json" || ext == ".ast") {
            auto parser = SolidityParser::load_json(path);
            for (auto send : parser->parse_sends()) {
                ctx.graph.addSend(send);
            }
            for (auto canc : parser->parse_cancellations()) {
                ctx.graph.addCancellation(canc);
            }
        }
    } catch (const std::exception& e) {
        ctx.errors.push_back("[L1] " + std::string(e.what()));
    }
}

void Engine::loadL1Data(AnalysisContext& ctx, const std::string& data) {
    try {
        try {
            auto parser = SolidityParser::load_json(data);
            for (auto send : parser->parse_sends()) {
                ctx.graph.addSend(send);
            }
        } catch (...) {
            auto parser = std::make_unique<SoliditySourceParser>();
            parser->source = data;
            for (auto send : parser->parse_sends()) {
                ctx.graph.addSend(send);
            }
        }
    } catch (const std::exception& e) {
        ctx.errors.push_back("[L1] " + std::string(e.what()));
    }
}

void Engine::loadL2(AnalysisContext& ctx, const std::string& path) {
    try {
        std::string ext = getExtension(path);
        
        if (ext == ".cairo") {
            auto parser = CairoSourceParser::load(path);
            for (auto handler : parser->parse_handlers()) {
                ctx.graph.addHandler(handler);
            }
        } else if (ext == ".json" || ext == ".sierra") {
            auto parser = CairoParser::load_json(path);
            for (auto handler : parser->parse_handlers()) {
                ctx.graph.addHandler(handler);
            }
        }
    } catch (const std::exception& e) {
        ctx.errors.push_back("[L2] " + std::string(e.what()));
    }
}

void Engine::loadL2Data(AnalysisContext& ctx, const std::string& data) {
    try {
        try {
            auto parser = CairoParser::load_json(data);
            for (auto handler : parser->parse_handlers()) {
                ctx.graph.addHandler(handler);
            }
        } catch (...) {
            auto parser = std::make_unique<CairoSourceParser>();
            parser->source = data;
            for (auto handler : parser->parse_handlers()) {
                ctx.graph.addHandler(handler);
            }
        }
    } catch (const std::exception& e) {
        ctx.errors.push_back("[L2] " + std::string(e.what()));
    }
}

std::string Engine::readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string Engine::getExtension(const std::string& path) {
    size_t pos = path.find_last_of(".");
    if (pos == std::string::npos) {
        return "";
    }
    return path.substr(pos);
}

} 
