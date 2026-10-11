// A tiny, dependency-free test framework. No GoogleTest, no network fetch.
// Register tests with TEST(suite, name) { ... } and assert with the EXPECT_*
// and ASSERT_* macros. Link against sentinel_test_main for a runner.
#ifndef SENTINEL_TEST_H
#define SENTINEL_TEST_H

#include <cmath>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace sentinel_test {

struct TestCase {
    std::string suite;
    std::string name;
    std::function<void(bool&)> fn;  // sets the bool to false on failure
};

// Global registry. Defined in sentinel_test_main.cpp.
std::vector<TestCase>& Registry();

struct Registrar {
    Registrar(const std::string& suite, const std::string& name,
              std::function<void(bool&)> fn) {
        Registry().push_back({suite, name, std::move(fn)});
    }
};

// Per-test failure sink used by the EXPECT_/ASSERT_ macros.
struct FailureContext {
    bool* ok;
    const char* file;
};

}  // namespace sentinel_test

#define SENTINEL_TEST_CONCAT2(a, b) a##b
#define SENTINEL_TEST_CONCAT(a, b) SENTINEL_TEST_CONCAT2(a, b)

#define TEST(suite, name)                                                      \
    static void SENTINEL_TEST_CONCAT(sentinel_test_fn_, __LINE__)(             \
        bool& sentinel_test_ok_);                                              \
    static ::sentinel_test::Registrar SENTINEL_TEST_CONCAT(sentinel_test_reg_, \
                                                           __LINE__)(          \
        #suite, #name, SENTINEL_TEST_CONCAT(sentinel_test_fn_, __LINE__));    \
    static void SENTINEL_TEST_CONCAT(sentinel_test_fn_, __LINE__)(             \
        bool& sentinel_test_ok_)

#define SENTINEL_FAIL(msg)                                              \
    do {                                                               \
        std::fprintf(stderr, "    FAIL %s:%d: %s\n", __FILE__, __LINE__, \
                     std::string(msg).c_str());                        \
        sentinel_test_ok_ = false;                                     \
    } while (0)

#define EXPECT_TRUE(cond)                                              \
    do {                                                              \
        if (!(cond)) SENTINEL_FAIL("expected true: " #cond);          \
    } while (0)

#define EXPECT_FALSE(cond)                                            \
    do {                                                             \
        if (cond) SENTINEL_FAIL("expected false: " #cond);           \
    } while (0)

#define EXPECT_EQ(a, b)                                                       \
    do {                                                                     \
        if (!((a) == (b))) SENTINEL_FAIL("expected equal: " #a " == " #b);   \
    } while (0)

#define EXPECT_NE(a, b)                                                       \
    do {                                                                     \
        if (!((a) != (b))) SENTINEL_FAIL("expected not equal: " #a " != " #b); \
    } while (0)

#define EXPECT_GE(a, b)                                                       \
    do {                                                                     \
        if (!((a) >= (b))) SENTINEL_FAIL("expected " #a " >= " #b);          \
    } while (0)

#define EXPECT_LE(a, b)                                                       \
    do {                                                                     \
        if (!((a) <= (b))) SENTINEL_FAIL("expected " #a " <= " #b);          \
    } while (0)

#define EXPECT_GT(a, b)                                                       \
    do {                                                                     \
        if (!((a) > (b))) SENTINEL_FAIL("expected " #a " > " #b);            \
    } while (0)

#define EXPECT_LT(a, b)                                                       \
    do {                                                                     \
        if (!((a) < (b))) SENTINEL_FAIL("expected " #a " < " #b);            \
    } while (0)

#define EXPECT_NEAR(a, b, tol)                                                \
    do {                                                                     \
        if (std::fabs((double)(a) - (double)(b)) > (double)(tol))            \
            SENTINEL_FAIL("expected near: " #a " ~ " #b);                    \
    } while (0)

#define EXPECT_STREQ(a, b)                                                    \
    do {                                                                     \
        if (std::string(a) != std::string(b))                               \
            SENTINEL_FAIL("expected string equal: " #a " == " #b);           \
    } while (0)

// ASSERT_* abort the current test (return) on failure.
#define ASSERT_TRUE(cond)                                            \
    do {                                                            \
        if (!(cond)) { SENTINEL_FAIL("assert true: " #cond); return; } \
    } while (0)

#define ASSERT_FALSE(cond)                                           \
    do {                                                            \
        if (cond) { SENTINEL_FAIL("assert false: " #cond); return; } \
    } while (0)

#define ASSERT_EQ(a, b)                                                      \
    do {                                                                    \
        if (!((a) == (b))) { SENTINEL_FAIL("assert equal: " #a " == " #b);  \
            return; }                                                        \
    } while (0)

#endif  // SENTINEL_TEST_H
