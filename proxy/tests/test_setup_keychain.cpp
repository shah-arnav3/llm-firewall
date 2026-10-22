// These tests never change the real keychain: changes go to a fake `security` tool
// that records its arguments, and lookups only read.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

#include "llmfw/setup_ca.hpp"
#include "llmfw/setup_keychain.hpp"

namespace llmfw::setup {
namespace {

namespace fs = std::filesystem;

/// A temp directory holding a fake `security` that appends its arguments, one run
/// per line, to calls.log and exits with the given status.
class FakeSecurityTool {
 public:
  explicit FakeSecurityTool(int exit_status) {
    std::string tmpl = (fs::temp_directory_path() / "llmfw-keychain-XXXXXX").string();
    dir_ = ::mkdtemp(tmpl.data());
    std::ofstream(tool()) << "#!/bin/sh\necho \"$*\" >> '" << log().string() << "'\nexit " << exit_status << "\n";
    fs::permissions(tool(), fs::perms::owner_all);
  }
  ~FakeSecurityTool() { fs::remove_all(dir_); }
  FakeSecurityTool(const FakeSecurityTool&) = delete;
  FakeSecurityTool& operator=(const FakeSecurityTool&) = delete;

  [[nodiscard]] fs::path tool() const { return dir_ / "security"; }
  [[nodiscard]] fs::path log() const { return dir_ / "calls.log"; }
  [[nodiscard]] const fs::path& dir() const { return dir_; }

  [[nodiscard]] std::vector<std::string> calls() const {
    std::ifstream in(log());
    std::vector<std::string> out;
    for (std::string line; std::getline(in, line);) {
      out.push_back(line);
    }
    return out;
  }

  /// Writes a fresh CA certificate, never added to any keychain, and returns its path.
  [[nodiscard]] fs::path writeCa() const {
    const EphemeralCa ca = generateConstrainedCa(CaSpec{"llm-firewall local CA (keychain test)"});
    const fs::path path = dir_ / "ca.pem";
    std::ofstream(path) << caCertificatePem(ca);
    return path;
  }

 private:
  fs::path dir_;
};

TEST(SetupKeychain, TrustRunsAddTrustedCertAsSslRootIntoTheKeychain) {
  const FakeSecurityTool fake(0);
  const fs::path ca = fake.writeCa();
  // The fake adds nothing, so the CA is missing from every keychain afterwards.
  EXPECT_THROW(KeychainTrust(fake.tool(), "/k/login.keychain-db").trustCa(ca), std::runtime_error);
  EXPECT_EQ(fake.calls(),
            std::vector<std::string>{"add-trusted-cert -r trustRoot -p ssl -k /k/login.keychain-db " + ca.string()});
}

TEST(SetupKeychain, LoginKeychainIsInTheUsersHome) {
  const fs::path keychain = KeychainTrust::loginKeychain();
  EXPECT_EQ(keychain.filename(), "login.keychain-db");
  EXPECT_EQ(keychain.parent_path().filename(), "Keychains");
}

TEST(SetupKeychain, TrustReportsAToolFailure) {
  const FakeSecurityTool fake(1);
  const fs::path ca = fake.writeCa();
  EXPECT_THROW(KeychainTrust(fake.tool()).trustCa(ca), std::runtime_error);
  // The fake added nothing, so there is no copy to roll back.
  EXPECT_EQ(fake.calls().size(), 1u);
}

TEST(SetupKeychain, TrustReportsAMissingTool) {
  const FakeSecurityTool fake(0);
  const fs::path ca = fake.writeCa();
  EXPECT_THROW(KeychainTrust(fake.dir() / "no-such-tool").trustCa(ca), std::runtime_error);
}

TEST(SetupKeychain, TrustRejectsFilesWithoutACertificateBeforeRunningTheTool) {
  const FakeSecurityTool fake(0);
  std::ofstream(fake.dir() / "garbage.pem") << "not a certificate\n";
  KeychainTrust keychain(fake.tool());
  EXPECT_THROW(keychain.trustCa(fake.dir() / "garbage.pem"), std::invalid_argument);
  EXPECT_THROW(keychain.trustCa(fake.dir() / "missing.pem"), std::invalid_argument);
  EXPECT_TRUE(fake.calls().empty());
}

TEST(SetupKeychain, UntrustRejectsMalformedFingerprints) {
  const FakeSecurityTool fake(0);
  KeychainTrust keychain(fake.tool());
  for (const std::string& bad : {std::string(), std::string(63, 'a'), std::string(65, 'a'), std::string(64, 'A'),
                                 std::string(64, 'g'), std::string(62, 'a') + ":a"}) {
    EXPECT_THROW((void)keychain.untrustCa(bad), std::invalid_argument) << bad;
  }
  EXPECT_TRUE(fake.calls().empty());
}

TEST(SetupKeychain, UntrustOfAnUnknownCaReturnsFalseWithoutRunningTheTool) {
  const FakeSecurityTool fake(0);
  const EphemeralCa ca = generateConstrainedCa(CaSpec{"llm-firewall local CA (keychain test)"});
  EXPECT_FALSE(KeychainTrust(fake.tool()).untrustCa(sha256Fingerprint(*ca.cert)));
  EXPECT_TRUE(fake.calls().empty());
}

TEST(SetupKeychain, FindInstalledListsOnlyLlmFirewallCas) {
  const std::vector<InstalledCa> installed = KeychainTrust().findInstalled();
  for (const InstalledCa& ca : installed) {
    EXPECT_TRUE(ca.common_name.starts_with(kCaCommonNamePrefix)) << ca.common_name;
    EXPECT_EQ(ca.sha256_fingerprint.size(), 64u);
  }
  for (std::size_t i = 0; i < installed.size(); ++i) {
    for (std::size_t j = i + 1; j < installed.size(); ++j) {
      EXPECT_NE(installed[i].sha256_fingerprint, installed[j].sha256_fingerprint);
    }
  }
}

}  // namespace
}  // namespace llmfw::setup
