// Tamper-evident, append-only hash-chained log. Each record's seal is
// SHA-256(prev_seal || CanonicalBytes(record)); removing or altering any record
// breaks the chain and is caught on Verify(). See secure_log.h for the contract.
#include "sentinel/edr/secure_log.h"

#include <charconv>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#include "sentinel/core/fs.h"
#include "sentinel/core/sha256.h"

namespace sentinel {
namespace {

// A single process-wide mutex serializes all append/read access. The SecureLog
// contract is thread-safe but the frozen header exposes no member to hold a
// lock, so a file-scope mutex stands in: it is coarse (appends to distinct logs
// serialize with each other) but always correct.
std::mutex g_log_mutex;

// On-disk line format (self-describing, one record per line):
//   v1 \t sequence \t timestamp_ms \t esc(category) \t esc(message) \t prev_seal \t seal \n
// category/message are escaped so they never contain a literal tab or newline,
// making the tab split and the line boundary unambiguous.
constexpr char kRecordVersion[] = "v1";
constexpr std::size_t kFieldCount = 7;

// Escape the control characters that would otherwise break the tab-delimited,
// one-record-per-line layout. Reversible via UnescapeField.
std::string EscapeField(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out += c;      break;
        }
    }
    return out;
}

// Inverse of EscapeField. Returns false on a dangling or unknown escape so that
// a tampered line is rejected rather than silently misread.
bool UnescapeField(const std::string& in, std::string& out) {
    out.clear();
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        const char c = in[i];
        if (c != '\\') {
            out += c;
            continue;
        }
        if (i + 1 >= in.size()) return false;  // dangling backslash
        const char n = in[++i];
        switch (n) {
            case '\\': out += '\\'; break;
            case 'n':  out += '\n'; break;
            case 'r':  out += '\r'; break;
            case 't':  out += '\t'; break;
            default:   return false;  // unknown escape => corrupt
        }
    }
    return true;
}

// Non-throwing decimal parse of an unsigned 64-bit field. Rejects anything that
// is not exactly a run of digits (no sign, no trailing garbage).
bool ParseU64(const std::string& s, std::uint64_t& out) {
    if (s.empty()) return false;
    const char* begin = s.data();
    const char* end = s.data() + s.size();
    const auto res = std::from_chars(begin, end, out);
    return res.ec == std::errc() && res.ptr == end;
}

// Compute a record's seal from the preceding seal. Single source of truth so
// append and verification stay in lockstep.
std::string SealOf(const std::string& prev_seal, const LogRecord& r) {
    return Sha256::HexDigest(prev_seal + SecureLog::CanonicalBytes(r));
}

// Parse the whole log file into records. A missing file is reported as NotFound
// (the caller treats that as an empty chain); a malformed line is ParseError.
Status ParseFile(const std::string& path, std::vector<LogRecord>& out) {
    out.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return Status::Error(ErrorCode::NotFound, "cannot open secure log: " + path);
    }

    std::string line;
    std::uint64_t lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        // Tolerate CRLF files: getline strips '\n', so drop a trailing '\r'.
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        // Split on every tab. Because every variable field is escaped, there are
        // exactly kFieldCount-1 tabs and none hide inside a field.
        std::vector<std::string> fields;
        std::size_t start = 0;
        while (true) {
            const std::size_t tab = line.find('\t', start);
            if (tab == std::string::npos) {
                fields.push_back(line.substr(start));
                break;
            }
            fields.push_back(line.substr(start, tab - start));
            start = tab + 1;
        }

        if (fields.size() != kFieldCount || fields[0] != kRecordVersion) {
            return Status::Error(ErrorCode::ParseError,
                                 "malformed secure-log record at line " +
                                     std::to_string(lineno));
        }

        LogRecord r;
        if (!ParseU64(fields[1], r.sequence) || !ParseU64(fields[2], r.timestamp_ms)) {
            return Status::Error(ErrorCode::ParseError,
                                 "bad numeric field at line " + std::to_string(lineno));
        }
        if (!UnescapeField(fields[3], r.category) || !UnescapeField(fields[4], r.message)) {
            return Status::Error(ErrorCode::ParseError,
                                 "bad escaped field at line " + std::to_string(lineno));
        }
        r.prev_seal = fields[5];
        r.seal = fields[6];
        out.push_back(std::move(r));
    }
    return Status::Ok();
}

// Recompute the chain from genesis and report the first break. Sequences must be
// contiguous from 0, each record's prev_seal must match the running head, and
// each seal must recompute exactly.
Status ValidateChain(const std::vector<LogRecord>& records) {
    std::string prev;  // "" == genesis
    for (std::size_t i = 0; i < records.size(); ++i) {
        const LogRecord& r = records[i];
        if (r.sequence != i) {
            return Status::Error(ErrorCode::Corrupt,
                                 "secure log: sequence break at record " +
                                     std::to_string(r.sequence) + " (expected " +
                                     std::to_string(i) + ")");
        }
        if (r.prev_seal != prev) {
            return Status::Error(ErrorCode::Corrupt,
                                 "secure log: prev-seal mismatch at sequence " +
                                     std::to_string(r.sequence));
        }
        if (r.seal != SealOf(prev, r)) {
            return Status::Error(ErrorCode::Corrupt,
                                 "secure log: seal mismatch at sequence " +
                                     std::to_string(r.sequence));
        }
        prev = r.seal;
    }
    return Status::Ok();
}

}  // namespace

std::string SecureLog::CanonicalBytes(const LogRecord& r) {
    // Length-prefix the free-text fields so the serialization is unambiguous and
    // reproducible no matter what they contain (tabs, newlines, '|', ':'). The
    // numeric fields are fixed-charset and need no prefix. prev_seal is NOT part
    // of the canonical bytes: it is prepended separately when sealing.
    std::string out;
    out += std::to_string(r.sequence);
    out += '|';
    out += std::to_string(r.timestamp_ms);
    out += '|';
    out += std::to_string(r.category.size());
    out += ':';
    out += r.category;
    out += '|';
    out += std::to_string(r.message.size());
    out += ':';
    out += r.message;
    return out;
}

Status SecureLog::Open(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    path_ = path;
    next_sequence_ = 0;
    head_seal_.clear();

    // Make sure the directory exists so the first Append can create the file.
    const std::string parent = ParentDir(path_);
    if (!parent.empty()) {
        MakeDirs(parent);
    }

    if (!PathExists(path_) || !IsRegularFile(path_)) {
        // Genesis: a brand-new chain. head_seal_ stays "" and next_sequence_ 0.
        return Status::Ok();
    }

    std::vector<LogRecord> records;
    Status parsed = ParseFile(path_, records);
    if (!parsed.ok()) {
        // A file that vanished between the stat and the open is just empty.
        if (parsed.code() == ErrorCode::NotFound) return Status::Ok();
        return parsed;  // malformed on disk
    }

    Status valid = ValidateChain(records);
    if (!valid.ok()) {
        // Refuse to adopt a broken chain as the head: appending would extend
        // corruption. Leave the log in the genesis state and surface the break.
        return valid;
    }

    if (!records.empty()) {
        next_sequence_ = records.back().sequence + 1;
        head_seal_ = records.back().seal;
    }
    return Status::Ok();
}

void SecureLog::Close() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    path_.clear();
    next_sequence_ = 0;
    head_seal_.clear();
}

Status SecureLog::Append(const std::string& category, const std::string& message,
                         std::uint64_t timestamp_ms) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (path_.empty()) {
        return Status::Error(ErrorCode::InvalidArgument, "secure log is not open");
    }

    LogRecord r;
    r.sequence = next_sequence_;
    r.timestamp_ms = timestamp_ms;
    r.category = category;
    r.message = message;
    r.prev_seal = head_seal_;
    r.seal = SealOf(r.prev_seal, r);

    // Append (never rewrite) and flush so the record is durable before we commit
    // the new head in memory.
    std::ofstream out(path_, std::ios::binary | std::ios::app);
    if (!out) {
        return Status::Error(ErrorCode::IoError,
                             "cannot open secure log for append: " + path_);
    }
    out << kRecordVersion << '\t' << r.sequence << '\t' << r.timestamp_ms << '\t'
        << EscapeField(r.category) << '\t' << EscapeField(r.message) << '\t'
        << r.prev_seal << '\t' << r.seal << '\n';
    out.flush();
    if (!out) {
        return Status::Error(ErrorCode::IoError, "failed to write secure-log record");
    }

    // Only advance the chain head once the write succeeded.
    head_seal_ = r.seal;
    ++next_sequence_;
    return Status::Ok();
}

Status SecureLog::Verify() const {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::vector<LogRecord> records;
    Status parsed = ParseFile(path_, records);
    if (!parsed.ok()) {
        // An absent/empty chain has nothing to break => intact.
        if (parsed.code() == ErrorCode::NotFound) return Status::Ok();
        return parsed;
    }
    return ValidateChain(records);
}

Result<std::vector<LogRecord>> SecureLog::ReadAll() const {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::vector<LogRecord> records;
    Status parsed = ParseFile(path_, records);
    if (!parsed.ok()) {
        if (parsed.code() == ErrorCode::NotFound) {
            return std::vector<LogRecord>{};  // empty log, not an error
        }
        return parsed;
    }
    return records;
}

std::uint64_t SecureLog::count() const {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    // Sequences are contiguous from 0, so the next sequence equals the record
    // count.
    return next_sequence_;
}

std::string SecureLog::head_seal() const {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    return head_seal_;
}

}  // namespace sentinel
