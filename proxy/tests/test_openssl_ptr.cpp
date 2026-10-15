#include <gtest/gtest.h>

#include <stdexcept>
#include <string>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "llmfw/openssl_ptr.hpp"

namespace llmfw {
namespace {

// A double free would be caught by the ASan build. Leaks are not, because
// LeakSanitizer does not run on Apple Silicon macOS.
TEST(OpenSslPtr, FreesEachOwnedType) {
  const X509Ptr cert(X509_new());
  const EvpPkeyPtr key(EVP_PKEY_new());
  const BioPtr bio(BIO_new(BIO_s_mem()));
  EXPECT_NE(cert, nullptr);
  EXPECT_NE(key, nullptr);
  EXPECT_NE(bio, nullptr);
}

TEST(OpenSslPtr, ReleasesOnlyItsOwnReference) {
  X509* raw = X509_new();
  ASSERT_EQ(X509_up_ref(raw), 1);
  { const X509Ptr owner(raw); }
  // The reference taken above is still valid after the owner is gone.
  EXPECT_EQ(X509_set_version(raw, X509_VERSION_3), 1);
  X509_free(raw);
}

TEST(OpenSslPtr, FreesChainedBios) {
  BioPtr chain(BIO_push(BIO_new(BIO_f_base64()), BIO_new(BIO_s_mem())));
  ASSERT_NE(chain, nullptr);
  chain.reset();
  EXPECT_EQ(chain, nullptr);
}

TEST(OpenSslPtr, NullIsANoOp) {
  OpenSslDeleter deleter;
  deleter(static_cast<X509*>(nullptr));
  deleter(static_cast<EVP_PKEY*>(nullptr));
  deleter(static_cast<BIO*>(nullptr));
}

TEST(OpenSslError, ReportsContextAndOldestErrorThenClearsQueue) {
  ERR_clear_error();
  ASSERT_EQ(BIO_new_file("/nonexistent/llmfw-test", "r"), nullptr);
  try {
    throwOpenSslError("open test file");
    FAIL() << "expected a throw";
  } catch (const std::runtime_error& e) {
    const std::string what = e.what();
    EXPECT_EQ(what.rfind("open test file: error:", 0), 0u) << what;
  }
  EXPECT_EQ(ERR_peek_error(), 0u);
}

TEST(OpenSslError, ReportsUnknownWhenQueueIsEmpty) {
  ERR_clear_error();
  EXPECT_THROW(
      {
        try {
          throwOpenSslError("ctx");
        } catch (const std::runtime_error& e) {
          EXPECT_STREQ(e.what(), "ctx: unknown OpenSSL error");
          throw;
        }
      },
      std::runtime_error);
}

}  // namespace
}  // namespace llmfw
