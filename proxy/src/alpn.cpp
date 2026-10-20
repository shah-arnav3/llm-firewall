#include "llmfw/alpn.hpp"

#include <stdexcept>

namespace llmfw {

std::vector<unsigned char> alpnWireFormat(const std::vector<std::string>& protocols) {
  std::vector<unsigned char> wire;
  for (const std::string& protocol : protocols) {
    if (protocol.empty() || protocol.size() > 255) {
      throw std::invalid_argument("ALPN protocol names must be 1 to 255 bytes");
    }
    wire.push_back(static_cast<unsigned char>(protocol.size()));
    wire.insert(wire.end(), protocol.begin(), protocol.end());
  }
  return wire;
}

}  // namespace llmfw
