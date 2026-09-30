cmake_minimum_required(VERSION 3.25)

project(llmfw_proxy
  VERSION 0.1.0
  DESCRIPTION "llm-firewall data plane: logging-only proxy"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(LLMFW_BUILD_TESTS "Build GoogleTest unit tests" ON)
option(LLMFW_SANITIZE    "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

# Dependencies come from Homebrew (see README). vcpkg.json lists the same packages for a vcpkg build.
find_package(Boost 1.83 REQUIRED CONFIG COMPONENTS headers)  # Asio is header-only

add_library(llmfw_flags INTERFACE)
target_compile_options(llmfw_flags INTERFACE
  -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wnon-virtual-dtor
  $<$<CONFIG:Release>:-O2>)
target_compile_definitions(llmfw_flags INTERFACE BOOST_ASIO_NO_DEPRECATED)

if (LLMFW_SANITIZE)
  target_compile_options(llmfw_flags INTERFACE
    -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  target_link_options(llmfw_flags INTERFACE -fsanitize=address,undefined)
endif()

# Core proxy library, linked by the tests
add_library(llmfw_core STATIC
  src/host_scope.cpp)
target_include_directories(llmfw_core PUBLIC include)
target_link_libraries(llmfw_core PUBLIC llmfw_flags Boost::headers)

if (LLMFW_BUILD_TESTS)
  enable_testing()
  find_package(GTest CONFIG REQUIRED)
  add_executable(llmfw-tests
    tests/test_host_scope.cpp)
  target_link_libraries(llmfw-tests PRIVATE llmfw_core GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(llmfw-tests)
endif()
