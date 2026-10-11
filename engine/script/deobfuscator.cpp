#include "sentinel/script/deobfuscator.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>

namespace sentinel {
namespace {

// --- small character predicates (ASCII-only, locale-independent) ---

bool IsSpace(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' ||
           c == '\v';
}

bool IsBase64Char(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

char LowerAscii(char c) {
    if (c >= 'A' && c <= 'Z') return static_cast<char>(c - 'A' + 'a');
    return c;
}

int HexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

// Case-insensitive match of the lowercase literal `lit` at position `pos`.
bool MatchesAt(const std::string& text, std::size_t pos, const char* lit) {
    for (std::size_t i = 0; lit[i] != '\0'; ++i) {
        if (pos + i >= text.size()) return false;
        if (LowerAscii(text[pos + i]) != lit[i]) return false;
    }
    return true;
}

// ASCII text encoded as UTF-16LE is roughly half NUL bytes; use that as the
// heuristic for "this decoded blob is an -EncodedCommand payload".
bool LooksLikeUtf16Le(const std::string& s) {
    if (s.size() < 2) return false;
    std::size_t zeros = 0;
    for (unsigned char c : s) {
        if (c == 0) ++zeros;
    }
    return zeros * 3 >= s.size();
}

// A decode is only accepted if it yields mostly-printable text; this both keeps
// the normalized output useful to the classifier and prevents the peeler from
// re-"decoding" plain words that happen to be valid base64 (which would decode
// to random, non-printable bytes).
bool IsMostlyPrintable(const std::string& s) {
    if (s.empty()) return false;
    std::size_t printable = 0;
    for (unsigned char c : s) {
        if (c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f)) {
            ++printable;
        }
    }
    return printable * 10 >= s.size() * 8;  // >= 80% printable
}

// Peel one base64 / -EncodedCommand / FromBase64String construct, substituting
// the decoded text in place and keeping the surrounding wrapper so the intent
// classifier still sees the "encoded command" indicator. Sets `found_encoded`
// whenever such a construct is seen (even if it is not decodable). Returns true
// only when the text was actually changed.
bool PeelEncoded(std::string& text, bool& found_encoded) {
    // ---- FromBase64String("<b64>") / FromBase64String('<b64>') ----
    static const char* kFb = "frombase64string";
    const std::size_t kFbLen = 16;  // strlen("frombase64string")
    for (std::size_t i = 0; i + kFbLen <= text.size(); ++i) {
        if (!MatchesAt(text, i, kFb)) continue;
        found_encoded = true;
        // Skip spaces / '(' up to the opening quote.
        std::size_t j = i + kFbLen;
        while (j < text.size() &&
               (IsSpace(static_cast<unsigned char>(text[j])) || text[j] == '(')) {
            ++j;
        }
        if (j >= text.size() || (text[j] != '"' && text[j] != '\'')) continue;
        const char quote = text[j];
        const std::size_t content_start = j + 1;
        std::size_t k = content_start;
        while (k < text.size() && text[k] != quote) ++k;
        if (k >= text.size()) continue;  // unterminated literal
        const std::string token = text.substr(content_start, k - content_start);
        if (token.size() < 4) continue;
        std::string decoded = Deobfuscator::Base64Decode(token);
        if (decoded.empty()) continue;
        if (LooksLikeUtf16Le(decoded)) decoded = Deobfuscator::Utf16LeToUtf8(decoded);
        if (!IsMostlyPrintable(decoded)) continue;  // not a text payload
        if (decoded == token) continue;             // no progress
        text.replace(content_start, k - content_start, decoded);
        return true;
    }

    // ---- -EncodedCommand / -enc / -e  <b64> ----
    static const std::string kEnc = "encodedcommand";
    for (std::size_t i = 0; i + 1 < text.size(); ++i) {
        if (text[i] != '-') continue;
        // A flag must start at a token boundary.
        if (i > 0 && !IsSpace(static_cast<unsigned char>(text[i - 1]))) continue;
        // Read the alphabetic flag name.
        std::size_t a = i + 1;
        std::string flag;
        while (a < text.size() &&
               std::isalpha(static_cast<unsigned char>(text[a]))) {
            flag.push_back(LowerAscii(text[a]));
            ++a;
        }
        // The name must be a non-empty prefix of "encodedcommand" (PowerShell
        // accepts any unambiguous prefix down to -e). This excludes e.g.
        // -ExecutionPolicy, whose full name is not such a prefix.
        if (flag.empty() || flag.size() > kEnc.size()) continue;
        if (kEnc.compare(0, flag.size(), flag) != 0) continue;
        // Skip whitespace, then read the base64 token.
        std::size_t b = a;
        while (b < text.size() && IsSpace(static_cast<unsigned char>(text[b]))) ++b;
        const std::size_t tok_start = b;
        while (b < text.size() && IsBase64Char(static_cast<unsigned char>(text[b]))) {
            ++b;
        }
        const std::string token = text.substr(tok_start, b - tok_start);
        if (token.size() < 8) continue;  // too short to be a real encoded blob
        found_encoded = true;
        std::string decoded = Deobfuscator::Base64Decode(token);
        if (decoded.empty()) continue;
        // -EncodedCommand is UTF-16LE by definition; decode it as such.
        if (LooksLikeUtf16Le(decoded)) decoded = Deobfuscator::Utf16LeToUtf8(decoded);
        if (!IsMostlyPrintable(decoded)) continue;
        if (decoded == token) continue;
        text.replace(tok_start, token.size(), decoded);
        return true;
    }

    return false;
}

// Collapse char-code arrays like [char]0x41 / [char]65, including runs joined
// with '+' or ',', into a single quoted string literal. Returns true on change.
bool PeelCharCodes(std::string& text) {
    static const char* kChar = "[char]";
    const std::size_t kCharLen = 6;  // strlen("[char]")
    bool changed = false;
    std::string out;
    out.reserve(text.size());

    std::size_t i = 0;
    while (i < text.size()) {
        if (MatchesAt(text, i, kChar)) {
            std::string chars;
            bool any = false;
            std::size_t p = i;
            std::size_t run_end = i;
            while (MatchesAt(text, p, kChar)) {
                std::size_t q = p + kCharLen;
                while (q < text.size() &&
                       IsSpace(static_cast<unsigned char>(text[q]))) {
                    ++q;
                }
                bool paren = false;
                if (q < text.size() && text[q] == '(') {
                    paren = true;
                    ++q;
                    while (q < text.size() &&
                           IsSpace(static_cast<unsigned char>(text[q]))) {
                        ++q;
                    }
                }
                // Parse a decimal or 0x-hex number.
                long value = 0;
                bool got = false;
                if (q + 1 < text.size() && text[q] == '0' &&
                    (text[q + 1] == 'x' || text[q + 1] == 'X')) {
                    q += 2;
                    const std::size_t hs = q;
                    while (q < text.size() &&
                           std::isxdigit(static_cast<unsigned char>(text[q]))) {
                        value = value * 16 + HexDigit(text[q]);
                        ++q;
                    }
                    got = (q > hs);
                } else {
                    const std::size_t ds = q;
                    while (q < text.size() && text[q] >= '0' && text[q] <= '9') {
                        value = value * 10 + (text[q] - '0');
                        ++q;
                    }
                    got = (q > ds);
                }
                if (!got) break;  // "[char]" not followed by a number: stop run
                if (paren) {
                    while (q < text.size() &&
                           IsSpace(static_cast<unsigned char>(text[q]))) {
                        ++q;
                    }
                    if (q < text.size() && text[q] == ')') ++q;
                }
                // Only emit values that fit in a byte; skip out-of-range codes.
                if (value >= 0 && value < 256) {
                    chars.push_back(static_cast<char>(value));
                }
                any = true;
                run_end = q;
                // Continue the run only if a '+'/',' separator is followed by
                // another [char]; otherwise leave the separator untouched.
                std::size_t r = q;
                while (r < text.size() &&
                       IsSpace(static_cast<unsigned char>(text[r]))) {
                    ++r;
                }
                if (r < text.size() && (text[r] == '+' || text[r] == ',')) {
                    std::size_t r2 = r + 1;
                    while (r2 < text.size() &&
                           IsSpace(static_cast<unsigned char>(text[r2]))) {
                        ++r2;
                    }
                    if (MatchesAt(text, r2, kChar)) {
                        p = r2;
                        continue;
                    }
                }
                break;
            }
            if (any) {
                // Emit a single-quoted literal (PowerShell-style '' escaping),
                // so a following concatenation pass can merge it further.
                out.push_back('\'');
                for (char c : chars) {
                    if (c == '\'') out.push_back('\'');
                    out.push_back(c);
                }
                out.push_back('\'');
                changed = true;
                i = run_end;
                continue;
            }
        }
        out.push_back(text[i]);
        ++i;
    }

    if (changed) text.swap(out);
    return changed;
}

// Reverse simple '+' concatenation of adjacent quoted literals:
//   'a' + 'b' + 'c'  ->  'abc'
// Best-effort: no backtick/interpolation handling, which is fine for a scanner.
bool PeelConcat(std::string& text) {
    bool changed = false;
    std::string out;
    out.reserve(text.size());

    std::size_t i = 0;
    while (i < text.size()) {
        const char c = text[i];
        if (c == '\'' || c == '"') {
            const char quote = c;
            std::size_t j = i + 1;
            std::string content;
            bool closed = false;
            while (j < text.size()) {
                if (text[j] == quote) {
                    closed = true;
                    ++j;
                    break;
                }
                content.push_back(text[j]);
                ++j;
            }
            if (!closed) {  // dangling quote: copy verbatim and move on
                out.push_back(c);
                ++i;
                continue;
            }
            // Fold in any following  + "literal"  terms.
            std::size_t k = j;
            bool merged = false;
            while (true) {
                std::size_t m = k;
                while (m < text.size() &&
                       IsSpace(static_cast<unsigned char>(text[m]))) {
                    ++m;
                }
                if (m >= text.size() || text[m] != '+') break;
                ++m;
                while (m < text.size() &&
                       IsSpace(static_cast<unsigned char>(text[m]))) {
                    ++m;
                }
                if (m >= text.size() || (text[m] != '\'' && text[m] != '"')) break;
                const char q2 = text[m];
                std::size_t n = m + 1;
                std::string c2;
                bool closed2 = false;
                while (n < text.size()) {
                    if (text[n] == q2) {
                        closed2 = true;
                        ++n;
                        break;
                    }
                    c2.push_back(text[n]);
                    ++n;
                }
                if (!closed2) break;
                content += c2;
                merged = true;
                k = n;
            }
            out.push_back(quote);
            for (char ch : content) out.push_back(ch);
            out.push_back(quote);
            if (merged) changed = true;
            i = k;
            continue;
        }
        out.push_back(c);
        ++i;
    }

    if (changed) text.swap(out);
    return changed;
}

}  // namespace

std::string Deobfuscator::Base64Decode(const std::string& in) {
    auto dv = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    // Gather significant symbols, ignoring whitespace and tracking padding.
    std::string sym;
    sym.reserve(in.size());
    std::size_t pad = 0;
    bool seen_pad = false;
    for (unsigned char c : in) {
        if (IsSpace(c)) continue;
        if (c == '=') {
            seen_pad = true;
            ++pad;
            continue;
        }
        if (seen_pad) return "";       // real symbol after padding: malformed
        if (dv(c) < 0) return "";      // clearly-invalid (non-base64) symbol
        sym.push_back(static_cast<char>(c));
    }
    if (sym.empty()) return "";
    if (pad > 2) return "";
    if (sym.size() % 4 == 1) return "";  // impossible base64 length

    std::string out;
    out.reserve(sym.size() / 4 * 3 + 3);
    std::size_t i = 0;
    for (; i + 4 <= sym.size(); i += 4) {
        const std::uint32_t triple =
            (static_cast<std::uint32_t>(dv(static_cast<unsigned char>(sym[i]))) << 18) |
            (static_cast<std::uint32_t>(dv(static_cast<unsigned char>(sym[i + 1]))) << 12) |
            (static_cast<std::uint32_t>(dv(static_cast<unsigned char>(sym[i + 2]))) << 6) |
            (static_cast<std::uint32_t>(dv(static_cast<unsigned char>(sym[i + 3]))));
        out.push_back(static_cast<char>((triple >> 16) & 0xFF));
        out.push_back(static_cast<char>((triple >> 8) & 0xFF));
        out.push_back(static_cast<char>(triple & 0xFF));
    }
    // Tail of 2 or 3 leftover symbols (padding already stripped).
    const std::size_t rem = sym.size() - i;
    if (rem == 2) {
        const std::uint32_t triple =
            (static_cast<std::uint32_t>(dv(static_cast<unsigned char>(sym[i]))) << 18) |
            (static_cast<std::uint32_t>(dv(static_cast<unsigned char>(sym[i + 1]))) << 12);
        out.push_back(static_cast<char>((triple >> 16) & 0xFF));
    } else if (rem == 3) {
        const std::uint32_t triple =
            (static_cast<std::uint32_t>(dv(static_cast<unsigned char>(sym[i]))) << 18) |
            (static_cast<std::uint32_t>(dv(static_cast<unsigned char>(sym[i + 1]))) << 12) |
            (static_cast<std::uint32_t>(dv(static_cast<unsigned char>(sym[i + 2]))) << 6);
        out.push_back(static_cast<char>((triple >> 16) & 0xFF));
        out.push_back(static_cast<char>((triple >> 8) & 0xFF));
    }
    return out;
}

std::string Deobfuscator::Utf16LeToUtf8(const std::string& bytes) {
    std::string out;
    out.reserve(bytes.size() / 2);
    const std::size_t n = bytes.size();
    // Read little-endian 16-bit code units. We only need ASCII fidelity to
    // recover script intent, so emit ASCII directly and substitute a
    // placeholder for anything >= 128 (best effort).
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        const unsigned lo = static_cast<unsigned char>(bytes[i]);
        const unsigned hi = static_cast<unsigned char>(bytes[i + 1]);
        const unsigned unit = lo | (hi << 8);
        if (unit == 0) continue;  // skip stray NULs
        if (unit < 128) {
            out.push_back(static_cast<char>(unit));
        } else {
            out.push_back('?');
        }
    }
    return out;
}

DeobfuscationResult Deobfuscator::Deobfuscate(const std::string& script,
                                              int max_layers) const {
    DeobfuscationResult result;
    std::string text = script;
    if (max_layers < 0) max_layers = 0;

    // Peel one layer per iteration, bounded by max_layers to avoid pathological
    // loops. Transforms are tried highest-value first; the first that makes
    // progress is recorded as a layer and the next pass re-scans from scratch,
    // so a payload revealed by one transform can be peeled further by another.
    for (int layer = 0; layer < max_layers; ++layer) {
        std::string work = text;
        bool changed = false;

        if (PeelEncoded(work, result.found_encoded_command)) {
            changed = true;
        } else if (PeelCharCodes(work)) {
            changed = true;
        } else if (PeelConcat(work)) {
            changed = true;
        }

        if (!changed || work == text) break;  // fixed point reached
        text.swap(work);
        result.decoded_layers.push_back(text);
        ++result.layers_peeled;
    }

    result.normalized = text;
    return result;
}

}  // namespace sentinel
