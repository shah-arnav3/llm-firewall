#include "llmfw/cert_store.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <string>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace llmfw {

namespace {

[[noreturn]] void fail(const std::string& message) { throw CertStoreError(message); }

void requirePrivateDirectory(const std::filesystem::path& dir) {
  struct stat st {};
  if (::stat(dir.c_str(), &st) != 0) {
    fail("cannot read " + dir.string() + ": " + std::strerror(errno));
  }
  if (!S_ISDIR(st.st_mode) || st.st_uid != ::getuid() || (st.st_mode & 07777) != 0700) {
    fail(dir.string() + " must be a directory owned by you with mode 0700");
  }
}

/// Reads a regular file owned by the current user. O_NOFOLLOW refuses a symlink,
/// O_NONBLOCK keeps a FIFO at the path from hanging the open, and the checks run on the
/// opened descriptor, so the file cannot be swapped in between.
std::string readOwnedFile(const std::filesystem::path& path, bool require_0600) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    fail("cannot open " + path.string() + ": " + std::strerror(errno));
  }
  struct stat st {};
  std::string contents;
  std::string problem;
  if (::fstat(fd, &st) != 0) {
    problem = std::string("cannot read: ") + std::strerror(errno);
  } else if (!S_ISREG(st.st_mode) || st.st_uid != ::getuid()) {
    problem = "must be a regular file owned by you";
  } else if (require_0600 && (st.st_mode & 07777) != 0600) {
    problem = "must have mode 0600";
  } else {
    char buf[4096];
    for (ssize_t n; (n = ::read(fd, buf, sizeof buf)) != 0;) {
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        problem = std::string("cannot read: ") + std::strerror(errno);
        break;
      }
      contents.append(buf, static_cast<std::size_t>(n));
    }
    OPENSSL_cleanse(buf, sizeof buf);
  }
  ::close(fd);
  if (!problem.empty()) {
    OPENSSL_cleanse(contents.data(), contents.size());
    fail(path.string() + " " + problem);
  }
  return contents;
}

std::vector<std::string> dnsSans(const X509& cert) {
  auto* names = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(&cert, NID_subject_alt_name, nullptr, nullptr));
  std::vector<std::string> out;
  for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
    const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
    if (name->type != GEN_DNS) {
      continue;
    }
    std::string dns(reinterpret_cast<const char*>(ASN1_STRING_get0_data(name->d.dNSName)),
                    static_cast<std::size_t>(ASN1_STRING_length(name->d.dNSName)));
    std::transform(dns.begin(), dns.end(), dns.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    out.push_back(std::move(dns));
  }
  GENERAL_NAMES_free(names);
  return out;
}

std::chrono::system_clock::time_point toTimePoint(const ASN1_TIME& time) {
  std::tm tm{};
  if (ASN1_TIME_to_tm(&time, &tm) != 1) {
    fail("leaf certificate has an unreadable validity time");
  }
  return std::chrono::system_clock::from_time_t(::timegm(&tm));
}

bool sanCovers(std::string_view san, std::string_view host) {
  if (!san.starts_with("*.")) {
    return san == host;
  }
  const std::string_view suffix = san.substr(1);  // ".claude.ai"
  if (host.size() <= suffix.size() || !host.ends_with(suffix)) {
    return false;
  }
  const std::string_view label = host.substr(0, host.size() - suffix.size());
  return label.find('.') == std::string_view::npos;
}

}  // namespace

LeafCertStore LeafCertStore::load(const CertConfig& cfg) {
  requirePrivateDirectory(cfg.dir);
  const std::filesystem::path cert_path = cfg.dir / cfg.leaf_cert_file;
  const std::filesystem::path key_path = cfg.dir / cfg.leaf_key_file;

  LeafCertStore store;
  const std::string cert_pem = readOwnedFile(cert_path, false);
  const BioPtr cert_bio(BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size())));
  store.cert_.reset(cert_bio ? PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr) : nullptr);
  if (!store.cert_) {
    fail(cert_path.string() + " is not a PEM certificate");
  }

  std::string key_pem = readOwnedFile(key_path, true);
  {
    const BioPtr key_bio(BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size())));
    store.key_.reset(key_bio ? PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr) : nullptr);
  }
  OPENSSL_cleanse(key_pem.data(), key_pem.size());
  if (!store.key_) {
    fail(key_path.string() + " is not an unencrypted PEM private key");
  }
  if (X509_check_private_key(store.cert_.get(), store.key_.get()) != 1) {
    fail(key_path.string() + " does not match " + cert_path.string());
  }

  store.dns_names_ = dnsSans(*store.cert_);
  if (store.dns_names_.empty()) {
    fail(cert_path.string() + " has no DNS names");
  }
  if (X509_cmp_current_time(X509_get0_notBefore(store.cert_.get())) > 0) {
    fail(cert_path.string() + " is not valid yet");
  }
  if (X509_cmp_current_time(X509_get0_notAfter(store.cert_.get())) < 0) {
    fail(cert_path.string() + " has expired; run llmfw-setup certs --force to replace it");
  }
  store.not_after_ = toTimePoint(*X509_get0_notAfter(store.cert_.get()));
  // OpenSSL 3's decoders can queue errors for formats they tried and rejected even
  // when parsing succeeds. Clear them so they cannot show up in a later, unrelated report.
  ERR_clear_error();
  return store;
}

bool LeafCertStore::covers(std::string_view normalized_host) const {
  return !normalized_host.empty() &&
         std::any_of(dns_names_.begin(), dns_names_.end(),
                     [&](const std::string& san) { return sanCovers(san, normalized_host); });
}

}  // namespace llmfw
