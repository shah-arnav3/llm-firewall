#pragma once
// The TLS stream type used on both sides of a decrypted connection.

#include <boost/asio/ssl/stream.hpp>

#include "llmfw/common.hpp"

namespace llmfw {

using TlsStream = asio::ssl::stream<tcp::socket>;

}  // namespace llmfw
