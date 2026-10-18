#include "llmfw/trust_verifier.hpp"

#include <utility>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "llmfw/openssl_ptr.hpp"

namespace llmfw {

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

std::vector<unsigned char> derOf(X509* cert) {
  unsigned char* der = nullptr;
  const int length = i2d_X509(cert, &der);
  if (length <= 0) {
    return {};
  }
  std::vector<unsigned char> out(der, der + length);
  OPENSSL_free(der);
  return out;
}

/// A CFArray of SecCertificates, or null if any DER fails to parse.
CFMutableArrayRef certificateArray(const std::vector<std::vector<unsigned char>>& ders) {
  CFMutableArrayRef array = CFArrayCreateMutable(nullptr, static_cast<CFIndex>(ders.size()), &kCFTypeArrayCallBacks);
  for (const std::vector<unsigned char>& der : ders) {
    const CfRef<CFDataRef> data(CFDataCreate(nullptr, der.data(), static_cast<CFIndex>(der.size())));
    const CfRef<SecCertificateRef> cert(data.get() == nullptr ? nullptr
                                                              : SecCertificateCreateWithData(nullptr, data.get()));
    if (cert.get() == nullptr) {
      CFRelease(array);
      return nullptr;
    }
    CFArrayAppendValue(array, cert.get());
  }
  return array;
}

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

/// Evaluates the chain for an SSL server named `hostname`. With `anchors` non-null,
/// only those certificates are trusted as roots.
VerifyResult evaluate(STACK_OF(X509)* chain, std::string_view hostname, CFArrayRef anchors) {
  if (chain == nullptr || sk_X509_num(chain) == 0) {
    return {false, "the server sent no certificate"};
  }
  if (hostname.empty()) {
    return {false, "no host name to verify"};
  }
  std::vector<std::vector<unsigned char>> ders;
  for (int i = 0; i < sk_X509_num(chain); ++i) {
    ders.push_back(derOf(sk_X509_value(chain, i)));
    if (ders.back().empty()) {
      return {false, "a certificate in the chain cannot be encoded"};
    }
  }
  const CfRef<CFMutableArrayRef> certs(certificateArray(ders));
  if (certs.get() == nullptr) {
    return {false, "a certificate in the chain cannot be parsed by Security.framework"};
  }
  const CfRef<CFStringRef> host(CFStringCreateWithBytes(nullptr, reinterpret_cast<const UInt8*>(hostname.data()),
                                                        static_cast<CFIndex>(hostname.size()), kCFStringEncodingUTF8,
                                                        false));
  const CfRef<SecPolicyRef> policy(SecPolicyCreateSSL(true, host.get()));
  CfRef<SecTrustRef> trust;
  if (host.get() == nullptr || policy.get() == nullptr ||
      SecTrustCreateWithCertificates(certs.get(), policy.get(), trust.out()) != errSecSuccess) {
    return {false, "cannot create a trust evaluation"};
  }
  if (anchors != nullptr && (SecTrustSetAnchorCertificates(trust.get(), anchors) != errSecSuccess ||
                             SecTrustSetAnchorCertificatesOnly(trust.get(), true) != errSecSuccess)) {
    return {false, "cannot set the trust anchors"};
  }
  CfRef<CFErrorRef> error;
  if (SecTrustEvaluateWithError(trust.get(), error.out())) {
    return {true, {}};
  }
  const CfRef<CFStringRef> description(error.get() == nullptr ? nullptr : CFErrorCopyDescription(error.get()));
  std::string reason = toString(description.get());
  return {false, reason.empty() ? "the chain is not trusted" : std::move(reason)};
}

}  // namespace

VerifyResult SystemTrustVerifier::verify(STACK_OF(X509)* chain, std::string_view hostname) const {
  return evaluate(chain, hostname, nullptr);
}

PemBundleTrustVerifier::PemBundleTrustVerifier(const std::filesystem::path& bundle) {
  const BioPtr bio(BIO_new_file(bundle.c_str(), "r"));
  if (!bio) {
    ERR_clear_error();
    throw ConfigError("upstream.pem_bundle: cannot read " + bundle.string());
  }
  while (const X509Ptr cert{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)}) {
    anchors_der_.push_back(derOf(cert.get()));
  }
  // Reading stops with a "no start line" error at the end of the file.
  ERR_clear_error();
  if (anchors_der_.empty()) {
    throw ConfigError("upstream.pem_bundle: no certificate in " + bundle.string());
  }
}

VerifyResult PemBundleTrustVerifier::verify(STACK_OF(X509)* chain, std::string_view hostname) const {
  const CfRef<CFMutableArrayRef> anchors(certificateArray(anchors_der_));
  if (anchors.get() == nullptr) {
    return {false, "a certificate in the PEM bundle cannot be parsed by Security.framework"};
  }
  return evaluate(chain, hostname, anchors.get());
}

std::shared_ptr<const UpstreamTrustVerifier> makeTrustVerifier(const UpstreamConfig& cfg) {
  if (cfg.trust == UpstreamTrustMode::kPemBundle) {
    return std::make_shared<PemBundleTrustVerifier>(cfg.pem_bundle);
  }
  return std::make_shared<SystemTrustVerifier>();
}

}  // namespace llmfw
