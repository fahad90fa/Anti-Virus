#include "sentinel/scan/rule_engine.h"

#include <cctype>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "sentinel/core/bytes.h"
#include "sentinel/core/fs.h"
#include "sentinel/core/logging.h"
#include "sentinel/core/result.h"

namespace sentinel {

// ---------------------------------------------------------------------------
// Compiled representation + parser + matcher, all kept private behind the PIMPL
// declared in rule_engine.h. Everything lives inside RuleSet::Impl so the
// internal-linkage helper types never leak into another translation unit.
// ---------------------------------------------------------------------------
struct RuleSet::Impl {
    // One compiled string pattern ($id).
    struct StrPattern {
        std::string id;        // e.g. "$s"
        bool is_hex = false;
        // Text patterns:
        std::string text;      // decoded literal bytes
        bool nocase = false;
        bool wide = false;     // match UTF-16LE (ASCII interleaved with 0x00)
        // Hex patterns: value + significance mask per byte. A fully-wildcard
        // byte ("??") has mask 0x00; a nibble wildcard ("?A"/"A?") masks half.
        std::vector<std::uint8_t> hex_val;
        std::vector<std::uint8_t> hex_mask;
    };

    // Condition AST.
    enum class Op { And, Or, Not, Ref, AnyOf, AllOf, NOf };
    struct Node {
        Op op = Op::Ref;
        std::string ref;   // for Ref: the "$id" referenced
        int n = 0;         // for NOf: the N in "N of them"
        std::vector<std::unique_ptr<Node>> kids;
    };

    struct Rule {
        std::string name;
        std::vector<std::string> tags;
        std::string description;
        std::string severity = "medium";
        double weight = 0.5;
        std::vector<StrPattern> strings;
        std::unique_ptr<Node> condition;
    };

    std::vector<Rule> rules;

    // -----------------------------------------------------------------------
    // Recursive-descent parser for the compact YARA-style dialect.
    // -----------------------------------------------------------------------
    struct Parser {
        const std::string& s;
        std::size_t pos = 0;
        std::string error;      // non-empty => parsing failed
        std::string cur_rule;   // for error context

        explicit Parser(const std::string& text) : s(text) {}

        bool failed() const { return !error.empty(); }
        char Peek() const { return pos < s.size() ? s[pos] : '\0'; }

        void Fail(const std::string& msg) {
            if (!error.empty()) return;  // keep the first, most relevant error
            error = msg;
            if (!cur_rule.empty()) error += " (rule '" + cur_rule + "')";
        }

        static bool IdentChar(char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
        }
        static int HexNibble(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }
        static bool ParseDouble(const std::string& tok, double& out) {
            if (tok.empty()) return false;
            char* end = nullptr;
            const double v = std::strtod(tok.c_str(), &end);
            if (end == tok.c_str()) return false;  // no digits consumed
            out = v;
            return true;
        }

        // Skip whitespace plus // line comments and /* */ block comments.
        void SkipWs() {
            while (pos < s.size()) {
                const char c = s[pos];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                    ++pos;
                    continue;
                }
                if (c == '/' && pos + 1 < s.size() && s[pos + 1] == '/') {
                    pos += 2;
                    while (pos < s.size() && s[pos] != '\n') ++pos;
                    continue;
                }
                if (c == '/' && pos + 1 < s.size() && s[pos + 1] == '*') {
                    pos += 2;
                    while (pos + 1 < s.size() &&
                           !(s[pos] == '*' && s[pos + 1] == '/')) {
                        ++pos;
                    }
                    pos = (pos + 1 < s.size()) ? pos + 2 : s.size();
                    continue;
                }
                break;
            }
        }

        std::string ParseIdent() {
            std::string out;
            while (pos < s.size() && IdentChar(s[pos])) out.push_back(s[pos++]);
            return out;
        }

        // A run of non-whitespace, non-'}' characters (numbers, bools, ...).
        std::string ParseBareToken() {
            std::string out;
            while (pos < s.size()) {
                const char c = s[pos];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
                    c == '}') {
                    break;
                }
                out.push_back(c);
                ++pos;
            }
            return out;
        }

        std::string ParseStringLit() {
            std::string out;
            if (Peek() != '"') {
                Fail("expected string literal");
                return out;
            }
            ++pos;  // opening quote
            while (pos < s.size()) {
                const char c = s[pos++];
                if (c == '"') return out;
                if (c == '\\') {
                    if (pos >= s.size()) break;
                    const char e = s[pos++];
                    switch (e) {
                        case 'n': out.push_back('\n'); break;
                        case 't': out.push_back('\t'); break;
                        case 'r': out.push_back('\r'); break;
                        case '"': out.push_back('"'); break;
                        case '\\': out.push_back('\\'); break;
                        case 'x': {
                            if (pos + 1 < s.size()) {
                                const int h = HexNibble(s[pos]);
                                const int l = HexNibble(s[pos + 1]);
                                if (h >= 0 && l >= 0) {
                                    out.push_back(
                                        static_cast<char>((h << 4) | l));
                                    pos += 2;
                                } else {
                                    out.push_back('x');
                                }
                            } else {
                                out.push_back('x');
                            }
                            break;
                        }
                        default: out.push_back(e); break;  // unknown => literal
                    }
                } else {
                    out.push_back(c);
                }
            }
            Fail("unterminated string literal");
            return out;
        }

        // ---- sections ----
        void ParseMeta(Rule& r) {
            while (!failed()) {
                SkipWs();
                if (Peek() == '}') return;
                const std::size_t save = pos;
                const std::string key = ParseIdent();
                if (key.empty()) {
                    Fail("expected meta key");
                    return;
                }
                SkipWs();
                if (Peek() == ':') {  // this is the next section header
                    pos = save;
                    return;
                }
                if (Peek() != '=') {
                    Fail("expected '=' in meta '" + key + "'");
                    return;
                }
                ++pos;  // '='
                SkipWs();
                if (Peek() == '"') {
                    const std::string val = ParseStringLit();
                    if (failed()) return;
                    if (key == "description")
                        r.description = val;
                    else if (key == "severity")
                        r.severity = val;
                    // other string metas are accepted but not retained
                } else {
                    const std::string tok = ParseBareToken();
                    if (tok.empty()) {
                        Fail("expected value in meta '" + key + "'");
                        return;
                    }
                    if (key == "weight") {
                        double d = 0.0;
                        if (ParseDouble(tok, d)) r.weight = d;
                    }
                    // other numeric metas accepted but not retained
                }
            }
        }

        void ParseHex(StrPattern& sp) {
            while (!failed()) {
                SkipWs();
                const char c = Peek();
                if (c == '}') {
                    ++pos;
                    return;
                }
                if (c == '\0') {
                    Fail("unterminated hex string in '" + sp.id + "'");
                    return;
                }
                if (pos + 1 >= s.size()) {
                    Fail("truncated hex byte in '" + sp.id + "'");
                    return;
                }
                const char n1 = s[pos];
                const char n2 = s[pos + 1];
                const int hv = (n1 == '?') ? -1 : HexNibble(n1);
                const int lv = (n2 == '?') ? -1 : HexNibble(n2);
                if ((n1 != '?' && hv < 0) || (n2 != '?' && lv < 0)) {
                    Fail("invalid hex byte in '" + sp.id + "'");
                    return;
                }
                pos += 2;
                std::uint8_t mask = 0, val = 0;
                if (hv >= 0) {
                    mask |= 0xF0;
                    val |= static_cast<std::uint8_t>(hv << 4);
                }
                if (lv >= 0) {
                    mask |= 0x0F;
                    val |= static_cast<std::uint8_t>(lv);
                }
                sp.hex_val.push_back(val);
                sp.hex_mask.push_back(mask);
            }
        }

        void ParseStrings(Rule& r) {
            while (!failed()) {
                SkipWs();
                if (Peek() == '}') return;
                if (Peek() != '$') {
                    // Could be the next section keyword (meta/condition).
                    const std::size_t save = pos;
                    const std::string id = ParseIdent();
                    SkipWs();
                    if (!id.empty() && Peek() == ':') {
                        pos = save;
                        return;
                    }
                    Fail("expected string identifier ($...)");
                    return;
                }
                ++pos;  // '$'
                const std::string name = ParseIdent();
                StrPattern sp;
                sp.id = "$" + name;
                SkipWs();
                if (Peek() != '=') {
                    Fail("expected '=' after string '" + sp.id + "'");
                    return;
                }
                ++pos;  // '='
                SkipWs();
                if (Peek() == '"') {
                    sp.text = ParseStringLit();
                    if (failed()) return;
                    sp.is_hex = false;
                    // Optional modifiers; stop at the next $id / section / }.
                    while (!failed()) {
                        SkipWs();
                        const std::size_t save = pos;
                        const std::string mod = ParseIdent();
                        if (mod == "nocase") {
                            sp.nocase = true;
                        } else if (mod == "wide") {
                            sp.wide = true;
                        } else if (mod == "ascii" || mod == "fullword") {
                            // accepted, no behavioral change here
                        } else {
                            pos = save;  // not a modifier — rewind
                            break;
                        }
                    }
                } else if (Peek() == '{') {
                    ++pos;  // '{'
                    ParseHex(sp);
                    if (failed()) return;
                    sp.is_hex = true;
                } else {
                    Fail("expected string literal or hex block for '" + sp.id +
                         "'");
                    return;
                }
                r.strings.push_back(std::move(sp));
            }
        }

        // ---- condition expression (precedence: not > and > or) ----
        bool ExpectKw(const char* word) {
            SkipWs();
            const std::size_t save = pos;
            const std::string kw = ParseIdent();
            if (kw != word) {
                pos = save;
                Fail(std::string("expected '") + word + "' in condition");
                return false;
            }
            return true;
        }

        std::unique_ptr<Node> ParsePrimary() {
            SkipWs();
            const char c = Peek();
            if (c == '(') {
                ++pos;
                auto n = ParseOr();
                if (failed()) return nullptr;
                SkipWs();
                if (Peek() != ')') {
                    Fail("expected ')' in condition");
                    return nullptr;
                }
                ++pos;
                return n;
            }
            if (c == '$') {
                ++pos;
                const std::string name = ParseIdent();
                auto n = std::make_unique<Node>();
                n->op = Op::Ref;
                n->ref = "$" + name;
                return n;
            }
            if (std::isdigit(static_cast<unsigned char>(c))) {
                std::string num;
                while (pos < s.size() &&
                       std::isdigit(static_cast<unsigned char>(s[pos]))) {
                    num.push_back(s[pos++]);
                }
                if (!ExpectKw("of") || !ExpectKw("them")) return nullptr;
                auto n = std::make_unique<Node>();
                n->op = Op::NOf;
                n->n = std::atoi(num.c_str());
                return n;
            }
            const std::size_t save = pos;
            const std::string kw = ParseIdent();
            if (kw == "any") {
                if (!ExpectKw("of") || !ExpectKw("them")) return nullptr;
                auto n = std::make_unique<Node>();
                n->op = Op::AnyOf;
                return n;
            }
            if (kw == "all") {
                if (!ExpectKw("of") || !ExpectKw("them")) return nullptr;
                auto n = std::make_unique<Node>();
                n->op = Op::AllOf;
                return n;
            }
            pos = save;
            Fail("unexpected token in condition");
            return nullptr;
        }

        std::unique_ptr<Node> ParseUnary() {
            SkipWs();
            const std::size_t save = pos;
            const std::string kw = ParseIdent();
            if (kw == "not") {
                auto child = ParseUnary();
                if (failed()) return nullptr;
                auto n = std::make_unique<Node>();
                n->op = Op::Not;
                n->kids.push_back(std::move(child));
                return n;
            }
            pos = save;  // not a 'not' — hand off to primary
            return ParsePrimary();
        }

        std::unique_ptr<Node> ParseAnd() {
            auto left = ParseUnary();
            while (!failed()) {
                SkipWs();
                const std::size_t save = pos;
                const std::string kw = ParseIdent();
                if (kw == "and") {
                    auto right = ParseUnary();
                    if (failed()) return nullptr;
                    auto n = std::make_unique<Node>();
                    n->op = Op::And;
                    n->kids.push_back(std::move(left));
                    n->kids.push_back(std::move(right));
                    left = std::move(n);
                } else {
                    pos = save;
                    break;
                }
            }
            return left;
        }

        std::unique_ptr<Node> ParseOr() {
            auto left = ParseAnd();
            while (!failed()) {
                SkipWs();
                const std::size_t save = pos;
                const std::string kw = ParseIdent();
                if (kw == "or") {
                    auto right = ParseAnd();
                    if (failed()) return nullptr;
                    auto n = std::make_unique<Node>();
                    n->op = Op::Or;
                    n->kids.push_back(std::move(left));
                    n->kids.push_back(std::move(right));
                    left = std::move(n);
                } else {
                    pos = save;
                    break;
                }
            }
            return left;
        }

        void ParseCondition(Rule& r) {
            auto node = ParseOr();
            if (failed()) return;
            if (!node) {
                Fail("empty condition");
                return;
            }
            r.condition = std::move(node);
        }

        void ParseRule(Rule& r) {
            SkipWs();
            r.name = ParseIdent();
            if (r.name.empty()) {
                Fail("expected rule name");
                return;
            }
            cur_rule = r.name;
            SkipWs();
            if (Peek() == ':') {  // tag list
                ++pos;
                while (!failed()) {
                    SkipWs();
                    if (Peek() == '{' || Peek() == '\0') break;
                    const std::string tag = ParseIdent();
                    if (tag.empty()) {
                        Fail("invalid tag in rule header");
                        return;
                    }
                    r.tags.push_back(tag);
                }
            }
            SkipWs();
            if (Peek() != '{') {
                Fail("expected '{' to open rule body");
                return;
            }
            ++pos;
            while (!failed()) {
                SkipWs();
                if (Peek() == '}') {
                    ++pos;
                    return;
                }
                if (Peek() == '\0') {
                    Fail("unterminated rule body");
                    return;
                }
                const std::string section = ParseIdent();
                if (section.empty()) {
                    Fail("expected section (meta/strings/condition)");
                    return;
                }
                SkipWs();
                if (Peek() != ':') {
                    Fail("expected ':' after section '" + section + "'");
                    return;
                }
                ++pos;
                if (section == "meta")
                    ParseMeta(r);
                else if (section == "strings")
                    ParseStrings(r);
                else if (section == "condition")
                    ParseCondition(r);
                else {
                    Fail("unknown section '" + section + "'");
                    return;
                }
            }
        }

        Status ParseAll(std::vector<Rule>& out) {
            while (true) {
                SkipWs();
                if (pos >= s.size()) break;
                const std::string kw = ParseIdent();
                if (kw != "rule") {
                    Fail("expected 'rule' keyword");
                    break;
                }
                cur_rule.clear();
                Rule r;
                ParseRule(r);
                if (failed()) break;
                out.push_back(std::move(r));
            }
            if (failed())
                return Status::Error(ErrorCode::ParseError, error);
            return Status::Ok();
        }
    };

    // -----------------------------------------------------------------------
    // Matcher helpers.
    // -----------------------------------------------------------------------
    static bool FindBytes(const std::uint8_t* data, std::size_t len,
                          const std::uint8_t* pat, std::size_t plen) {
        if (plen == 0) return true;
        if (plen > len) return false;
        const std::size_t last = len - plen;
        for (std::size_t i = 0; i <= last; ++i) {
            std::size_t j = 0;
            for (; j < plen; ++j) {
                if (data[i + j] != pat[j]) break;
            }
            if (j == plen) return true;
        }
        return false;
    }

    static bool FindMasked(const std::uint8_t* data, std::size_t len,
                           const std::vector<std::uint8_t>& val,
                           const std::vector<std::uint8_t>& mask) {
        const std::size_t plen = val.size();
        if (plen == 0) return true;
        if (plen > len) return false;
        const std::size_t last = len - plen;
        for (std::size_t i = 0; i <= last; ++i) {
            std::size_t j = 0;
            for (; j < plen; ++j) {
                if ((data[i + j] & mask[j]) != val[j]) break;
            }
            if (j == plen) return true;
        }
        return false;
    }

    static bool StringMatches(const StrPattern& sp, const std::uint8_t* data,
                              std::size_t len) {
        if (sp.is_hex) {
            return FindMasked(data, len, sp.hex_val, sp.hex_mask);
        }
        std::string needle = sp.text;
        if (sp.wide) {
            // UTF-16LE form: ASCII byte followed by 0x00. ContainsCaseInsensitive
            // folds case per byte and leaves the 0x00 separators intact, so the
            // same needle also serves the nocase+wide case.
            std::string w;
            w.reserve(needle.size() * 2);
            for (char ch : needle) {
                w.push_back(ch);
                w.push_back('\0');
            }
            needle.swap(w);
        }
        if (sp.nocase) {
            return ContainsCaseInsensitive(data, len, needle);
        }
        return FindBytes(data, len,
                         reinterpret_cast<const std::uint8_t*>(needle.data()),
                         needle.size());
    }

    static bool EvalNode(const Node* node, const Rule& rule,
                         const std::vector<bool>& hit, std::size_t hit_count) {
        if (!node) return false;
        switch (node->op) {
            case Op::And:
                if (node->kids.empty()) return false;
                for (const auto& k : node->kids) {
                    if (!EvalNode(k.get(), rule, hit, hit_count)) return false;
                }
                return true;
            case Op::Or:
                for (const auto& k : node->kids) {
                    if (EvalNode(k.get(), rule, hit, hit_count)) return true;
                }
                return false;
            case Op::Not:
                return !node->kids.empty() &&
                       !EvalNode(node->kids[0].get(), rule, hit, hit_count);
            case Op::AnyOf:
                return hit_count >= 1;
            case Op::AllOf:
                return !rule.strings.empty() &&
                       hit_count == rule.strings.size();
            case Op::NOf: {
                const std::size_t need =
                    node->n < 0 ? 0 : static_cast<std::size_t>(node->n);
                return hit_count >= need;
            }
            case Op::Ref:
                for (std::size_t i = 0; i < rule.strings.size(); ++i) {
                    if (rule.strings[i].id == node->ref) return hit[i];
                }
                return false;  // reference to an undefined string never matches
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// RuleSet public interface.
// ---------------------------------------------------------------------------
RuleSet::RuleSet() : impl_(std::make_unique<Impl>()) {}
RuleSet::~RuleSet() = default;
RuleSet::RuleSet(RuleSet&&) noexcept = default;
RuleSet& RuleSet::operator=(RuleSet&&) noexcept = default;

Status RuleSet::ParseText(const std::string& text) {
    Impl::Parser parser(text);
    std::vector<Impl::Rule> parsed;
    const Status st = parser.ParseAll(parsed);
    if (!st.ok()) return st;  // append nothing on failure (atomic per call)
    for (auto& r : parsed) impl_->rules.push_back(std::move(r));
    return Status::Ok();
}

Status RuleSet::LoadDirectory(const std::string& dir, std::size_t* count) {
    std::size_t parsed = 0;
    if (!IsDirectory(dir)) {
        if (count) *count = 0;
        return Status::Error(ErrorCode::NotFound, "rules dir not found: " + dir);
    }
    const Status walk = WalkFiles(dir, true, [&](const std::string& path) {
        const std::string ext = Extension(path);
        if (ext != ".yar" && ext != ".rules" && ext != ".txt") return;
        auto content = ReadFile(path);
        if (!content) {
            SENTINEL_LOG(Warn) << "rule file unreadable: " << path;
            return;
        }
        const std::string text(content.value().begin(), content.value().end());
        const std::size_t before = impl_->rules.size();
        const Status st = ParseText(text);
        if (!st.ok()) {
            SENTINEL_LOG(Warn) << "skipping bad rule file " << path << ": "
                               << st.message();
        } else {
            parsed += impl_->rules.size() - before;
        }
    });
    if (count) *count = parsed;
    return walk;
}

void RuleSet::Match(const std::uint8_t* data, std::size_t len,
                    std::vector<RuleMatch>& out) const {
    if (!impl_) return;
    for (const auto& rule : impl_->rules) {
        std::vector<bool> hit(rule.strings.size(), false);
        std::size_t hit_count = 0;
        std::vector<std::string> matched_ids;
        for (std::size_t i = 0; i < rule.strings.size(); ++i) {
            if (Impl::StringMatches(rule.strings[i], data, len)) {
                hit[i] = true;
                ++hit_count;
                matched_ids.push_back(rule.strings[i].id);
            }
        }
        if (Impl::EvalNode(rule.condition.get(), rule, hit, hit_count)) {
            RuleMatch m;
            m.rule_id = rule.name;
            m.description = rule.description;
            m.severity = rule.severity;
            m.weight = rule.weight;
            m.tags = rule.tags;
            m.matched_strings = std::move(matched_ids);
            out.push_back(std::move(m));
        }
    }
}

std::size_t RuleSet::rule_count() const {
    return impl_ ? impl_->rules.size() : 0;
}

}  // namespace sentinel
