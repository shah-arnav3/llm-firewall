#include "llmfw/random_id.hpp"

#include <array>
#include <cstdint>
#include <random>

namespace llmfw {

std::string randomUuid() {
  std::random_device rd;
  std::array<std::uint8_t, 16> b{};
  for (std::size_t i = 0; i < b.size(); i += 4) {
    const std::uint32_t r = rd();
    for (std::size_t j = 0; j < 4; ++j) {
      b[i + j] = static_cast<std::uint8_t>(r >> (8 * j));
    }
  }
  b[6] = static_cast<std::uint8_t>((b[6] & 0x0f) | 0x40);
  b[8] = static_cast<std::uint8_t>((b[8] & 0x3f) | 0x80);
  static constexpr char kHex[] = "0123456789abcdef";
  std::string id;
  for (std::size_t i = 0; i < b.size(); ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) {
      id.push_back('-');
    }
    id.push_back(kHex[b[i] >> 4]);
    id.push_back(kHex[b[i] & 0x0f]);
  }
  return id;
}

}  // namespace llmfw
