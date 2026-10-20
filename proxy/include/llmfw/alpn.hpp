#pragma once
// ALPN protocol lists, shared by the client and server TLS sides.

#include <string>
#include <vector>

namespace llmfw {

/// Encodes protocol names ("http/1.1") as the ALPN wire format: each name prefixed
/// by its length byte. @throws std::invalid_argument if a name is empty or over 255 bytes.
[[nodiscard]] std::vector<unsigned char> alpnWireFormat(const std::vector<std::string>& protocols);

}  // namespace llmfw
