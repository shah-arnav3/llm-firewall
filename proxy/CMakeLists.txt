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

# The PAC template config/claude.pac is embedded in the core library; editing it re-runs configure.
set(LLMFW_PAC_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/../config/claude.pac)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${LLMFW_PAC_SOURCE})
file(READ ${LLMFW_PAC_SOURCE} LLMFW_PAC_TEMPLATE)
configure_file(cmake/pac_template.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/gen-pac/llmfw/pac_template.hpp @ONLY)

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
  src/fs_util.cpp
  src/host_scope.cpp
  src/listener.cpp
  src/log.cpp
  src/metadata_logger.cpp
  src/pac.cpp
  src/proxy_context.cpp
  src/random_id.cpp)
target_include_directories(llmfw_core
  PUBLIC  include
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/gen-pac)
target_link_libraries(llmfw_core
  PUBLIC  llmfw_flags llmfw_proto Boost::headers
  PRIVATE yaml-cpp::yaml-cpp)

add_executable(llmfw-proxy src/proxy_main.cpp)
target_link_libraries(llmfw-proxy PRIVATE llmfw_core)
target_compile_definitions(llmfw-proxy PRIVATE LLMFW_VERSION="${PROJECT_VERSION}")

# Setup library
add_library(llmfw_setup_core STATIC
  src/setup_launcher.cpp
  src/setup_paths.cpp
  src/setup_profile.cpp)
target_include_directories(llmfw_setup_core PUBLIC include)
target_link_libraries(llmfw_setup_core PUBLIC llmfw_core)

add_executable(llmfw-setup src/setup_main.cpp)
target_link_libraries(llmfw-setup PRIVATE llmfw_setup_core)
target_compile_definitions(llmfw-setup PRIVATE LLMFW_VERSION="${PROJECT_VERSION}")

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
    tests/test_proxy_app.cpp
    tests/test_random_id.cpp
    tests/test_pac.cpp
    tests/test_setup_launcher.cpp
    tests/test_setup_paths.cpp
    tests/test_setup_profile.cpp
    tests/test_tunnel_registry.cpp)
  target_link_libraries(llmfw-tests PRIVATE llmfw_setup_core GTest::gtest_main)
  # The config and PAC tests read the committed files in config/; the launcher tests
  # start the fake Claude executable.
  add_executable(llmfw-fake-claude tests/fake_claude.cpp)
  target_compile_definitions(llmfw-tests PRIVATE
    LLMFW_REPO_DIR="${CMAKE_CURRENT_SOURCE_DIR}/.."
    LLMFW_FAKE_CLAUDE="$<TARGET_FILE:llmfw-fake-claude>")
  add_dependencies(llmfw-tests llmfw-fake-claude)
  include(GoogleTest)
  gtest_discover_tests(llmfw-tests)

  # The real binary: usage, version, and the config-error exit code.
  add_test(NAME llmfw-proxy.help COMMAND llmfw-proxy --help)
  add_test(NAME llmfw-proxy.version COMMAND llmfw-proxy --version)
  set_tests_properties(llmfw-proxy.version PROPERTIES PASS_REGULAR_EXPRESSION "^llmfw-proxy ${PROJECT_VERSION}")
  add_test(NAME llmfw-proxy.bad-argument COMMAND llmfw-proxy --nope)
  add_test(NAME llmfw-proxy.missing-config COMMAND llmfw-proxy --config /nonexistent/llm-firewall.yaml)
  set_tests_properties(llmfw-proxy.bad-argument llmfw-proxy.missing-config PROPERTIES WILL_FAIL TRUE)

  # The real llmfw-setup, launching a fake Claude.app with a throwaway HOME so the tests
  # never write to the real ~/Library. The HOME is short (one per build tree) because the
  # config's socket path under it must stay within macOS's 103-byte limit.
  # Each launching test gets its own app, so one test's fake Claude still running (the
  # first run of a new binary is slow while macOS checks it) cannot fail the next.
  set(LLMFW_FAKE_APP ${CMAKE_CURRENT_BINARY_DIR}/FakeClaude.app)
  set(LLMFW_FAKE_APP_DATA ${CMAKE_CURRENT_BINARY_DIR}/FakeClaudeDataUrl.app)
  string(MD5 LLMFW_BUILD_HASH ${CMAKE_CURRENT_BINARY_DIR})
  string(SUBSTRING ${LLMFW_BUILD_HASH} 0 8 LLMFW_BUILD_HASH)
  set(LLMFW_FAKE_HOME /tmp/llmfw-home-${LLMFW_BUILD_HASH})
  add_custom_command(TARGET llmfw-fake-claude POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${LLMFW_FAKE_APP}/Contents/MacOS
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:llmfw-fake-claude> ${LLMFW_FAKE_APP}/Contents/MacOS/Claude
    COMMAND ${CMAKE_COMMAND} -E make_directory ${LLMFW_FAKE_APP_DATA}/Contents/MacOS
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:llmfw-fake-claude> ${LLMFW_FAKE_APP_DATA}/Contents/MacOS/Claude)
  set(LLMFW_REPO_CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/../config/llm-firewall.yaml)
  add_test(NAME llmfw-setup.help COMMAND llmfw-setup --help)
  add_test(NAME llmfw-setup.version COMMAND llmfw-setup --version)
  set_tests_properties(llmfw-setup.version PROPERTIES PASS_REGULAR_EXPRESSION "^llmfw-setup ${PROJECT_VERSION}")
  add_test(NAME llmfw-setup.bad-command COMMAND llmfw-setup nope)
  add_test(NAME llmfw-setup.missing-config COMMAND llmfw-setup launch --config /nonexistent/llm-firewall.yaml)
  add_test(NAME llmfw-setup.missing-claude
    COMMAND llmfw-setup launch --config ${LLMFW_REPO_CONFIG} --claude-app /nonexistent/Claude.app)
  set_tests_properties(llmfw-setup.bad-command llmfw-setup.missing-config llmfw-setup.missing-claude
    PROPERTIES WILL_FAIL TRUE ENVIRONMENT "HOME=${LLMFW_FAKE_HOME}")
  add_test(NAME llmfw-setup.launch
    COMMAND llmfw-setup launch --config ${LLMFW_REPO_CONFIG} --claude-app ${LLMFW_FAKE_APP})
  set_tests_properties(llmfw-setup.launch PROPERTIES
    ENVIRONMENT "HOME=${LLMFW_FAKE_HOME}"
    PASS_REGULAR_EXPRESSION "Launched Claude \\(pid [0-9]+\\) routing claude.ai and anthropic.com to 127.0.0.1:18443"
    FIXTURES_SETUP rendered-pac)
  add_test(NAME llmfw-setup.launch-wrote-pac
    COMMAND ${CMAKE_COMMAND} -E cat "${LLMFW_FAKE_HOME}/Library/Application Support/llm-firewall/claude.pac")
  set_tests_properties(llmfw-setup.launch-wrote-pac PROPERTIES
    PASS_REGULAR_EXPRESSION "PROXY 127.0.0.1:18443; DIRECT"
    FIXTURES_REQUIRED rendered-pac)
  set(LLMFW_FAKE_PROFILE ${CMAKE_CURRENT_BINARY_DIR}/test-profile.mobileconfig)
  add_test(NAME llmfw-setup.profile
    COMMAND llmfw-setup profile --config ${LLMFW_REPO_CONFIG} --output ${LLMFW_FAKE_PROFILE})
  set_tests_properties(llmfw-setup.profile PROPERTIES
    ENVIRONMENT "HOME=${LLMFW_FAKE_HOME}"
    PASS_REGULAR_EXPRESSION "egressProxyPacUrl to http://127.0.0.1:18443/proxy.pac"
    FIXTURES_SETUP written-profile)
  add_test(NAME llmfw-setup.profile-is-valid COMMAND /usr/bin/plutil -lint ${LLMFW_FAKE_PROFILE})
  set_tests_properties(llmfw-setup.profile-is-valid PROPERTIES FIXTURES_REQUIRED written-profile)
  add_test(NAME llmfw-setup.profile-bad-scope
    COMMAND llmfw-setup profile --config ${LLMFW_REPO_CONFIG} --output ${LLMFW_FAKE_PROFILE} --scope everyone)
  set_tests_properties(llmfw-setup.profile-bad-scope PROPERTIES WILL_FAIL TRUE)
  add_test(NAME llmfw-setup.launch-data-url
    COMMAND llmfw-setup launch --config ${LLMFW_REPO_CONFIG} --claude-app ${LLMFW_FAKE_APP_DATA} --pac-data-url)
  set_tests_properties(llmfw-setup.launch-data-url PROPERTIES
    ENVIRONMENT "HOME=${LLMFW_FAKE_HOME}" PASS_REGULAR_EXPRESSION "PAC: inline data: URL")
endif()
