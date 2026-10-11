#include "sentinel/behavior/ml_model.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <string>

namespace sentinel {
namespace {

// Numerically stable logistic (sigmoid). Splitting on the sign of z avoids
// overflow of std::exp for large-magnitude inputs.
double Logistic(double z) {
    if (z >= 0.0) {
        return 1.0 / (1.0 + std::exp(-z));
    }
    const double ez = std::exp(z);
    return ez / (1.0 + ez);
}

// Two-decimal score formatting for human-readable Signal detail strings.
std::string FormatScore(double v) {
    std::ostringstream oss;
    oss.setf(std::ios::fixed);
    oss.precision(2);
    oss << v;
    return oss.str();
}

}  // namespace

MlModel::MlModel() {
    // Transparent, hand-tuned logistic weights standing in for the shipped
    // learned model. Each weight is roughly the log-odds contribution of one
    // feature; every feature is non-negative evidence of malice, so all weights
    // are positive and the bias is strongly negative. An all-zero (clean)
    // feature vector therefore scores logistic(bias) ~= 0.02 — benign stays low,
    // and the cap in Evaluate keeps even a high score corroborating, not sole.
    weights_ = {
        {"entropy", 0.35},              // per bit/byte of file/section entropy
        {"rwx_section", 1.60},          // a read-write-execute PE section
        {"section_wx", 1.40},           // write+execute section permissions
        {"pe_packed", 1.20},            // packer indicators present
        {"imports_only_dynamic", 1.10}, // imports resolved only via LoadLibrary
        {"remote_thread", 1.80},        // CreateRemoteThread into another proc
        {"remote_alloc_write", 1.70},   // VirtualAllocEx + WriteProcessMemory
        {"high_entropy_writes", 0.50},  // per encrypted-looking file write
        {"persistence", 1.00},          // Run key / service / boot persistence
        {"canary_touch", 3.00},         // touched a ransomware decoy (near-cert)
        {"obfuscation_layers", 0.80},   // per decode/deobfuscation layer
    };
    bias_ = -4.5;
}

Status MlModel::LoadWeights(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        return Status::Error(ErrorCode::IoError,
                             "ml_model: cannot open weights file: " + path);
    }

    // Parse into a scratch map first; only commit once the whole file is clean,
    // so a malformed line never leaves the model half-replaced.
    std::map<std::string, double> weights;
    double bias = bias_;  // keep the current bias unless the file sets __bias__.
    std::string line;
    std::size_t lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        std::istringstream iss(line);
        std::string name;
        if (!(iss >> name)) continue;        // blank / whitespace-only line
        if (!name.empty() && name[0] == '#') continue;  // comment line

        double value = 0.0;
        if (!(iss >> value)) {
            return Status::Error(
                ErrorCode::ParseError,
                "ml_model: malformed line " + std::to_string(lineno) +
                    " in " + path);
        }
        if (name == "__bias__") {
            bias = value;
        } else {
            weights[name] = value;
        }
    }

    weights_ = std::move(weights);  // replaces the built-in weights
    bias_ = bias;
    return Status::Ok();
}

void MlModel::SetWeight(const std::string& feature, double weight) {
    weights_[feature] = weight;
}

double MlModel::Score(const FeatureVector& fv) const {
    // Dot product of weights and present features, plus bias, through logistic.
    // Iterating the weight table (not the feature map) means unweighted features
    // are ignored and absent features contribute 0 via FeatureVector::Get.
    double z = bias_;
    for (const auto& kv : weights_) {
        z += kv.second * fv.Get(kv.first);
    }
    return Logistic(z);
}

Signal MlModel::Evaluate(const FeatureVector& fv) const {
    const double score = Score(fv);

    // Map the probability to a risk band. The model is corroborating, so the
    // bands are deliberately coarse and never reach a stand-alone conviction.
    RiskLevel level;
    if (score >= 0.80) {
        level = RiskLevel::Malicious;
    } else if (score >= 0.50) {
        level = RiskLevel::Suspicious;
    } else if (score >= 0.25) {
        level = RiskLevel::LowRisk;
    } else {
        level = RiskLevel::Unknown;
    }

    // Identify the single largest positive contributor for an explainable
    // detail string.
    std::string top_feature;
    double top_contrib = 0.0;
    for (const auto& kv : weights_) {
        const double contrib = kv.second * fv.Get(kv.first);
        if (contrib > top_contrib) {
            top_contrib = contrib;
            top_feature = kv.first;
        }
    }

    std::string detail = "model score=" + FormatScore(score);
    if (!top_feature.empty()) {
        detail += " (top feature: " + top_feature + ")";
    } else {
        detail += " (no active features)";
    }

    // Confidence is capped at max_confidence_ so the model can never alone cross
    // the block threshold — it only reinforces the deterministic layers.
    const double confidence = std::min(score, max_confidence_);
    return Signal(SignalSource::MlModel, level, confidence, detail, "ml.logistic");
}

}  // namespace sentinel
