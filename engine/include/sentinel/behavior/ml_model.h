// The "small model" scorer. In the shipping product this is a gradient-boosted
// / lightweight neural model trained on large clean+malicious corpora. Here we
// implement a transparent, deterministic logistic model over the same feature
// vector (PE structure, entropy, imports, strings, action-graph shape) so the
// pipeline is real, explainable, and testable. Model weights load from a file
// and ship/update like signatures; the interface does not change when a learned
// model replaces the built-in weights.
//
// Design rule from the blueprint: the model is a CORROBORATING signal inside
// verdict fusion, never a sole judge, and it is paired with the deterministic
// layers so a fooled model cannot alone clear or convict a threat.
#ifndef SENTINEL_BEHAVIOR_ML_MODEL_H
#define SENTINEL_BEHAVIOR_ML_MODEL_H

#include <map>
#include <string>
#include <vector>

#include "sentinel/core/result.h"
#include "sentinel/core/types.h"

namespace sentinel {

// Named feature vector. Missing features default to 0.
struct FeatureVector {
    std::map<std::string, double> features;
    void Set(const std::string& name, double value) { features[name] = value; }
    double Get(const std::string& name) const {
        auto it = features.find(name);
        return it == features.end() ? 0.0 : it->second;
    }
};

class MlModel {
public:
    MlModel();  // loads sane built-in weights

    // Load weights from a text file: "feature_name weight" per line, plus a
    // special line "__bias__ value". Replaces the built-in weights.
    Status LoadWeights(const std::string& path);

    // Set a single weight (tests / tuning).
    void SetWeight(const std::string& feature, double weight);
    void SetBias(double bias) { bias_ = bias; }

    // Probability of malice in [0,1] via logistic(w·x + b).
    double Score(const FeatureVector& fv) const;

    // Wrap the score as a corroborating Signal (confidence deliberately capped
    // so the model cannot convict alone).
    Signal Evaluate(const FeatureVector& fv) const;

private:
    std::map<std::string, double> weights_;
    double bias_ = 0.0;
    double max_confidence_ = 0.6;  // cap: corroborating, never sole judge
};

}  // namespace sentinel

#endif  // SENTINEL_BEHAVIOR_ML_MODEL_H
