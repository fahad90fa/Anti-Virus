#include "sentinel/core/config.h"

#include <cstdlib>
#include <fstream>
#include <sstream>

#include "sentinel/core/logging.h"

namespace sentinel {
namespace {

std::string Trim(const std::string& s) {
    const char* ws = " \t\r\n";
    const auto begin = s.find_first_not_of(ws);
    if (begin == std::string::npos) return "";
    const auto end = s.find_last_not_of(ws);
    return s.substr(begin, end - begin + 1);
}

bool ParseBool(const std::string& v, bool fallback) {
    std::string lower;
    for (char c : v) lower += static_cast<char>(std::tolower(c));
    if (lower == "1" || lower == "true" || lower == "yes" || lower == "on") return true;
    if (lower == "0" || lower == "false" || lower == "no" || lower == "off") return false;
    return fallback;
}

LogLevel ParseLevel(const std::string& v, LogLevel fallback) {
    std::string lower;
    for (char c : v) lower += static_cast<char>(std::tolower(c));
    if (lower == "trace") return LogLevel::Trace;
    if (lower == "debug") return LogLevel::Debug;
    if (lower == "info") return LogLevel::Info;
    if (lower == "warn" || lower == "warning") return LogLevel::Warn;
    if (lower == "error") return LogLevel::Error;
    if (lower == "off") return LogLevel::Off;
    return fallback;
}

}  // namespace

bool Config::Set(const std::string& key, const std::string& value) {
    if (key == "signatures_dir") signatures_dir = value;
    else if (key == "blocklist_hashes") blocklist_hashes = value;
    else if (key == "allowlist_hashes") allowlist_hashes = value;
    else if (key == "rules_dir") rules_dir = value;
    else if (key == "driverblock") driverblock = value;
    else if (key == "quarantine_dir") quarantine_dir = value;
    else if (key == "shadow_dir") shadow_dir = value;
    else if (key == "timeline_path") timeline_path = value;
    else if (key == "state_dir") state_dir = value;
    else if (key == "block_threshold") block_threshold = std::strtod(value.c_str(), nullptr);
    else if (key == "shadow_threshold") shadow_threshold = std::strtod(value.c_str(), nullptr);
    else if (key == "monitor_threshold") monitor_threshold = std::strtod(value.c_str(), nullptr);
    else if (key == "high_entropy_threshold") high_entropy_threshold = std::strtod(value.c_str(), nullptr);
    else if (key == "ransomware_file_window") ransomware_file_window = std::atoi(value.c_str());
    else if (key == "ransomware_window_ms") ransomware_window_ms = std::atoi(value.c_str());
    else if (key == "ransomware_entropy_min") ransomware_entropy_min = std::strtod(value.c_str(), nullptr);
    else if (key == "enable_behavioral") enable_behavioral = ParseBool(value, enable_behavioral);
    else if (key == "enable_script_analysis") enable_script_analysis = ParseBool(value, enable_script_analysis);
    else if (key == "enable_memory_scan") enable_memory_scan = ParseBool(value, enable_memory_scan);
    else if (key == "enable_deception") enable_deception = ParseBool(value, enable_deception);
    else if (key == "quarantine_on_malicious") quarantine_on_malicious = ParseBool(value, quarantine_on_malicious);
    else if (key == "log_level") log_level = ParseLevel(value, log_level);
    else {
        SENTINEL_LOG(Debug) << "config: ignoring unknown key '" << key << "'";
        return false;
    }
    return true;
}

bool Config::LoadFromFile(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        const std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') continue;
        const auto eq = trimmed.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = Trim(trimmed.substr(0, eq));
        const std::string value = Trim(trimmed.substr(eq + 1));
        Set(key, value);
    }
    return true;
}

std::map<std::string, std::string> Config::AsMap() const {
    std::map<std::string, std::string> m;
    m["signatures_dir"] = signatures_dir;
    m["blocklist_hashes"] = blocklist_hashes;
    m["allowlist_hashes"] = allowlist_hashes;
    m["rules_dir"] = rules_dir;
    m["driverblock"] = driverblock;
    m["quarantine_dir"] = quarantine_dir;
    m["shadow_dir"] = shadow_dir;
    m["timeline_path"] = timeline_path;
    m["state_dir"] = state_dir;
    m["block_threshold"] = std::to_string(block_threshold);
    m["shadow_threshold"] = std::to_string(shadow_threshold);
    m["monitor_threshold"] = std::to_string(monitor_threshold);
    m["high_entropy_threshold"] = std::to_string(high_entropy_threshold);
    m["ransomware_file_window"] = std::to_string(ransomware_file_window);
    m["ransomware_window_ms"] = std::to_string(ransomware_window_ms);
    m["ransomware_entropy_min"] = std::to_string(ransomware_entropy_min);
    m["enable_behavioral"] = enable_behavioral ? "true" : "false";
    m["enable_script_analysis"] = enable_script_analysis ? "true" : "false";
    m["enable_memory_scan"] = enable_memory_scan ? "true" : "false";
    m["enable_deception"] = enable_deception ? "true" : "false";
    m["quarantine_on_malicious"] = quarantine_on_malicious ? "true" : "false";
    m["log_level"] = Log::LevelName(log_level);
    return m;
}

}  // namespace sentinel
