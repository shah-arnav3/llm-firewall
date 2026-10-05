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
find_package(yaml-cpp CONFIG REQUIRED)
find_package(Protobuf CONFIG REQUIRED)

add_library(llmfw_flags INTERFACE)
target_compile_options(llmfw_flags INTERFACE
  -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wnon-virtual-dtor
  $<$<CONFIG:Release>:-O2>)
target_compile_definitions(llmfw_flags INTERFACE BOOST_ASIO_NO_DEPRECATED)

if (LLMFW_SANITIZE)
  target_compile_options(llmfw_flags INTERFACE
    -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  target_link_options(llmfw_flags INTERFACE -fsanitize=address,undefined)
  # Under ASan, protobuf's headers switch to a different default-instance layout,
  # which disagrees with the uninstrumented generated code and libprotobuf.
  target_compile_definitions(llmfw_flags INTERFACE PROTOBUF_MESSAGE_GLOBALS_TEMPORARY_OPTOUT)
endif()

# Generated protobuf code (shared contract with the Java collector)
set(LLMFW_PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../proto)
add_library(llmfw_proto STATIC)
protobuf_generate(
  TARGET llmfw_proto
  LANGUAGE cpp
  PROTOS ${LLMFW_PROTO_DIR}/capture.proto
  IMPORT_DIRS ${LLMFW_PROTO_DIR}
  PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen)
# SYSTEM keeps our warning flags out of generated code.
target_include_directories(llmfw_proto SYSTEM PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/gen)
target_link_libraries(llmfw_proto PUBLIC protobuf::libprotobuf)

# Core proxy library, linked by the tests
add_library(llmfw_core STATIC
  src/blind_tunnel.cpp
  src/capture_builder.cpp
  src/capture_queue.cpp
  src/capture_sink.cpp
  src/client_classifier.cpp
  src/config.cpp
  src/connect_handler.cpp
  src/counters.cpp
  src/host_scope.cpp
  src/listener.cpp
  src/log.cpp
  src/metadata_logger.cpp
  src/proxy_context.cpp)
target_include_directories(llmfw_core PUBLIC include)
target_link_libraries(llmfw_core
  PUBLIC  llmfw_flags llmfw_proto Boost::headers
  PRIVATE yaml-cpp::yaml-cpp)

if (LLMFW_BUILD_TESTS)
  enable_testing()
  find_package(GTest CONFIG REQUIRED)
  add_executable(llmfw-tests
    tests/test_blind_tunnel.cpp
    tests/test_capture_builder.cpp
    tests/test_capture_queue.cpp
    tests/test_capture_sink.cpp
    tests/test_client_connection.cpp
    tests/test_client_classifier.cpp
    tests/test_config.cpp
    tests/test_connect_request.cpp
    tests/test_counters.cpp
    tests/test_host_scope.cpp
    tests/test_metadata_logger.cpp
    tests/test_tunnel_registry.cpp)
  target_link_libraries(llmfw-tests PRIVATE llmfw_core GTest::gtest_main)
  # The config tests load the committed example config/llm-firewall.yaml.
  target_compile_definitions(llmfw-tests PRIVATE LLMFW_REPO_DIR="${CMAKE_CURRENT_SOURCE_DIR}/..")
  include(GoogleTest)
  gtest_discover_tests(llmfw-tests)
endif()
