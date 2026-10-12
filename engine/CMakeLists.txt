cmake_minimum_required(VERSION 3.16)
project(sentinel_engine LANGUAGES CXX VERSION 0.1.0)

# ---------------------------------------------------------------------------
# Sentinel AV user-mode engine.
#
# Portable C++17. Builds the detection engine as a static library, the
# `sentinel` service/CLI executable, and (optionally) the unit-test runner.
# The kernel drivers, ELAM, trustlet, and C# UI live outside this build and
# target Windows (WDK / .NET).
# ---------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(SENTINEL_BUILD_TESTS "Build the unit-test runner" OFF)
option(SENTINEL_BUILD_TOOLS "Build the dev tools (rule_compiler, benchmark, log_viewer)" OFF)
option(SENTINEL_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

# Warning flags.
if(MSVC)
  add_compile_options(/W4 /permissive-)
  if(SENTINEL_WARNINGS_AS_ERRORS)
    add_compile_options(/WX)
  endif()
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
  if(SENTINEL_WARNINGS_AS_ERRORS)
    add_compile_options(-Werror)
  endif()
endif()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Engine library: everything except the service/CLI entry point.
# ---------------------------------------------------------------------------
file(GLOB_RECURSE SENTINEL_ENGINE_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/core/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/platform/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/scan/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/behavior/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/script/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/memory/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/sandbox/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/rollback/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/edr/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/deception/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/devicecontrol/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/quarantine/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/amsi/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/trustlet/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/lowlevel/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/orchestrator/*.cpp"
)

add_library(sentinel_engine STATIC ${SENTINEL_ENGINE_SOURCES})
target_include_directories(sentinel_engine PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(sentinel_engine PUBLIC Threads::Threads)

# std::filesystem needs an explicit link on older libstdc++ (gcc < 9).
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
  target_link_libraries(sentinel_engine PUBLIC stdc++fs)
endif()

if(WIN32)
  target_link_libraries(sentinel_engine PUBLIC psapi)
endif()

# ---------------------------------------------------------------------------
# Service / CLI executable.
# ---------------------------------------------------------------------------
file(GLOB SENTINEL_SERVICE_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/service/*.cpp")

if(SENTINEL_SERVICE_SOURCES)
  add_executable(sentinel ${SENTINEL_SERVICE_SOURCES})
  target_link_libraries(sentinel PRIVATE sentinel_engine)
  set_target_properties(sentinel PROPERTIES OUTPUT_NAME "sentinel")
  if(WIN32)
    # The filter-service mode uses the FltMgr user-mode API (fltlib).
    target_link_libraries(sentinel PRIVATE fltlib)
  endif()
endif()

# ---------------------------------------------------------------------------
# Unit tests.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Dev tools (tools/ at the repo root), each a small executable on the engine lib.
# ---------------------------------------------------------------------------
if(SENTINEL_BUILD_TOOLS)
  set(SENTINEL_TOOLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../tools")
  foreach(tool rule_compiler benchmark log_viewer)
    if(EXISTS "${SENTINEL_TOOLS_DIR}/${tool}.cpp")
      add_executable(${tool} "${SENTINEL_TOOLS_DIR}/${tool}.cpp")
      target_link_libraries(${tool} PRIVATE sentinel_engine)
    endif()
  endforeach()
endif()

if(SENTINEL_BUILD_TESTS)
  enable_testing()
  set(SENTINEL_TESTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../tests")
  file(GLOB_RECURSE SENTINEL_UNIT_TEST_SOURCES CONFIGURE_DEPENDS
    "${SENTINEL_TESTS_DIR}/unit/*.cpp"
    "${SENTINEL_TESTS_DIR}/integration/*.cpp")
  add_executable(sentinel_tests
    ${SENTINEL_UNIT_TEST_SOURCES}
    "${SENTINEL_TESTS_DIR}/framework/sentinel_test_main.cpp")
  target_include_directories(sentinel_tests PRIVATE "${SENTINEL_TESTS_DIR}/framework")
  target_link_libraries(sentinel_tests PRIVATE sentinel_engine)
  add_test(NAME unit COMMAND sentinel_tests)
  set_tests_properties(unit PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/..")
endif()
