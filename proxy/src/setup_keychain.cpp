#include "llmfw/setup_keychain.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <spawn.h>
#include <sys/wait.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "llmfw/openssl_ptr.hpp"
#include "llmfw/setup_ca.hpp"

extern char** environ;

namespace llmfw::setup {

namespace {

/// Owns one CoreFoundation reference and releases it.
template <typename T>
class CfRef {
 public:
  explicit CfRef(T ref = nullptr) : ref_(ref) {}
  ~CfRef() {
    if (ref_ != nullptr) {
      CFRelease(ref_);
    }
  }
  CfRef(const CfRef&) = delete;
  CfRef& operator=(const CfRef&) = delete;
  [[nodiscard]] T get() const { return ref_; }
  [[nodiscard]] T* out() { return &ref_; }

 private:
  T ref_;
};

std::string toString(CFStringRef text) {
  if (text == nullptr) {
    return {};
  }
  const CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(text), kCFStringEncodingUTF8) + 1;
  std::string out(static_cast<std::size_t>(max), '\0');
  if (!CFStringGetCString(text, out.data(), max, kCFStringEncodingUTF8)) {
    return {};
  }
  out.resize(std::char_traits<char>::length(out.c_str()));
  return out;
}

[[noreturn]] void throwSecurityError(const std::string& context, OSStatus status) {
  const CfRef<CFStringRef> message(SecCopyErrorMessageString(status, nullptr));
  throw std::runtime_error(context + ": " + toString(message.get()) + " (OSStatus " + std::to_string(status) + ")");
}

std::string fingerprintOf(SecCertificateRef cert) {
  const CfRef<CFDataRef> data(SecCertificateCopyData(cert));
  const unsigned char* der = CFDataGetBytePtr(data.get());
  const X509Ptr x509(d2i_X509(nullptr, &der, CFDataGetLength(data.get())));
  if (!x509) {
    throwOpenSslError("parse keychain certificate");
  }
  return sha256Fingerprint(*x509);
}

std::string commonNameOf(SecCertificateRef cert) {
  CfRef<CFStringRef> name;
  return SecCertificateCopyCommonName(cert, name.out()) == errSecSuccess ? toString(name.get()) : std::string();
}

bool hasUserTrust(SecCertificateRef cert) {
  CfRef<CFArrayRef> settings;
  return SecTrustSettingsCopyTrustSettings(cert, kSecTrustSettingsDomainUser, settings.out()) == errSecSuccess;
}

/// Every certificate in the keychain search list. Claude's engine (Bun) builds its
/// "system" CA store the same way.
CFArrayRef copyAllCertificates() {
  const void* keys[] = {kSecClass, kSecMatchLimit, kSecReturnRef};
  const void* values[] = {kSecClassCertificate, kSecMatchLimitAll, kCFBooleanTrue};
  const CfRef<CFDictionaryRef> query(CFDictionaryCreate(nullptr, keys, values, 3, &kCFTypeDictionaryKeyCallBacks,
                                                        &kCFTypeDictionaryValueCallBacks));
  CFTypeRef result = nullptr;
  const OSStatus status = SecItemCopyMatching(query.get(), &result);
  if (status == errSecItemNotFound) {
    return CFArrayCreate(nullptr, nullptr, 0, &kCFTypeArrayCallBacks);
  }
  if (status != errSecSuccess) {
    throwSecurityError("list keychain certificates", status);
  }
  return static_cast<CFArrayRef>(result);
}

bool isFingerprint(const std::string& text) {
  return text.size() == 64 &&
         std::all_of(text.begin(), text.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

/// Upper-case hex SHA-1, the hash `security delete-certificate -Z` selects by.
std::string sha1Hex(const X509& cert) {
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int length = 0;
  if (X509_digest(&cert, EVP_sha1(), digest.data(), &length) != 1) {
    throwOpenSslError("hash certificate");
  }
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string hex;
  for (unsigned int i = 0; i < length; ++i) {
    hex.push_back(kHex[digest[i] >> 4]);
    hex.push_back(kHex[digest[i] & 0x0f]);
  }
  return hex;
}

/// How many keychain copies of the certificate with this SHA-256 fingerprint exist.
int countCopies(const std::string& sha256_fingerprint) {
  const CfRef<CFArrayRef> all(copyAllCertificates());
  int copies = 0;
  for (CFIndex i = 0; i < CFArrayGetCount(all.get()); ++i) {
    if (fingerprintOf(static_cast<SecCertificateRef>(const_cast<void*>(CFArrayGetValueAtIndex(all.get(), i)))) ==
        sha256_fingerprint) {
      ++copies;
    }
  }
  return copies;
}

/// Runs the tool with `args`, without a shell, sharing this process's stdout and
/// stderr so its messages reach the user. @throws std::runtime_error unless it exits 0.
void run(const std::filesystem::path& tool, const std::vector<std::string>& args) {
  std::vector<char*> argv;
  std::string program = tool.string();
  argv.push_back(program.data());
  std::vector<std::string> owned(args);
  for (std::string& arg : owned) {
    argv.push_back(arg.data());
  }
  argv.push_back(nullptr);

  pid_t pid = 0;
  const int spawned = ::posix_spawn(&pid, program.c_str(), nullptr, nullptr, argv.data(), environ);
  if (spawned != 0) {
    throw std::runtime_error("cannot run " + program + ": " + std::strerror(spawned));
  }
  int status = 0;
  while (::waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      throw std::runtime_error("cannot wait for " + program + ": " + std::strerror(errno));
    }
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    const std::string how = WIFEXITED(status) ? "exited with " + std::to_string(WEXITSTATUS(status))
                                              : "was killed by signal " + std::to_string(WTERMSIG(status));
    throw std::runtime_error(program + " " + args.front() + " " + how);
  }
}

}  // namespace

KeychainTrust::KeychainTrust(std::filesystem::path security_tool) : security_tool_(std::move(security_tool)) {}

void KeychainTrust::trustCa(const std::filesystem::path& certificate_file) {
  const BioPtr bio(BIO_new_file(certificate_file.c_str(), "r"));
  const X509Ptr cert(bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr);
  if (!cert) {
    ERR_clear_error();
    throw std::invalid_argument(certificate_file.string() + " does not hold a PEM certificate");
  }
  const std::string fingerprint = sha256Fingerprint(*cert);
  const bool was_present = countCopies(fingerprint) > 0;
  try {
    run(security_tool_, {"add-trusted-cert", "-r", "trustRoot", "-p", "ssl", certificate_file.string()});
  } catch (const std::runtime_error&) {
    // The tool adds the certificate before it asks for trust, so a refusal would
    // leave an untrusted copy behind.
    if (!was_present && countCopies(fingerprint) > 0) {
      try {
        run(security_tool_, {"delete-certificate", "-Z", sha1Hex(*cert)});
      } catch (const std::runtime_error&) {
        // The trust failure is the error to report; untrust can still remove the copy.
      }
    }
    throw;
  }
}

bool KeychainTrust::untrustCa(const std::string& sha256_fingerprint) {
  if (!isFingerprint(sha256_fingerprint)) {
    throw std::invalid_argument("not a lower-case hex SHA-256 fingerprint: " + sha256_fingerprint);
  }
  const CfRef<CFArrayRef> all(copyAllCertificates());
  std::string sha1;
  int copies = 0;
  for (CFIndex i = 0; i < CFArrayGetCount(all.get()); ++i) {
    auto cert = static_cast<SecCertificateRef>(const_cast<void*>(CFArrayGetValueAtIndex(all.get(), i)));
    if (fingerprintOf(cert) == sha256_fingerprint) {
      ++copies;
      if (sha1.empty()) {
        const CfRef<CFDataRef> data(SecCertificateCopyData(cert));
        const unsigned char* der = CFDataGetBytePtr(data.get());
        const X509Ptr x509(d2i_X509(nullptr, &der, CFDataGetLength(data.get())));
        if (!x509) {
          throwOpenSslError("parse keychain certificate");
        }
        sha1 = sha1Hex(*x509);
      }
    }
  }
  // Each run deletes the first copy in the search list.
  for (int i = 0; i < copies; ++i) {
    run(security_tool_, {"delete-certificate", "-Z", sha1, "-t"});
  }
  return copies > 0;
}
std::vector<InstalledCa> KeychainTrust::findInstalled() const {
  const CfRef<CFArrayRef> all(copyAllCertificates());
  std::vector<InstalledCa> out;
  for (CFIndex i = 0; i < CFArrayGetCount(all.get()); ++i) {
    auto cert = static_cast<SecCertificateRef>(const_cast<void*>(CFArrayGetValueAtIndex(all.get(), i)));
    std::string name = commonNameOf(cert);
    if (!name.starts_with(kCaCommonNamePrefix)) {
      continue;
    }
    std::string fingerprint = fingerprintOf(cert);
    if (std::any_of(out.begin(), out.end(),
                    [&](const InstalledCa& ca) { return ca.sha256_fingerprint == fingerprint; })) {
      continue;
    }
    out.push_back({std::move(fingerprint), std::move(name), hasUserTrust(cert)});
  }
  return out;
}

}  // namespace llmfw::setup
