// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace esphome {
namespace unifi_chime {

/// BINME segment types
enum BinmeType : uint8_t {
  BINME_REQUEST = 0x01,
  BINME_RESPONSE = 0x02,
};

/// Single BINME segment: 8-byte header + payload.
///
///   Offset  Size  Field
///   0       1     type (1=request, 2=response)
///   1       1     subtype (format indicator, typically 0 or 1)
///   2       1     compress (0=raw, non-zero=zlib)
///   3       1     padding (0x00)
///   4       4     length (big-endian)
///   8       N     payload (JSON or zlib-compressed JSON)
struct BinmeSegment {
  BinmeType type;
  uint8_t subtype;
  bool compressed;
  std::string payload;  // decompressed JSON string
};

/// A full BINME message is two consecutive segments: header + body.
struct BinmeMessage {
  BinmeSegment header;
  BinmeSegment body;
};

class BinmeCodec {
 public:
  static constexpr size_t HEADER_SIZE = 8;

  /// Parse a single segment from a buffer. Returns bytes consumed, or 0 on error.
  static size_t parse_segment(const uint8_t *data, size_t len, BinmeSegment &out);

  /// Parse a full message (two segments) from a WebSocket frame.
  static bool parse_message(const uint8_t *data, size_t len, BinmeMessage &out);

  /// Encode a single segment into a byte buffer.
  static std::vector<uint8_t> encode_segment(BinmeType type, uint8_t subtype,
                                              const std::string &json_payload,
                                              bool compress = false);

  /// Encode a full message (header + body segments) for sending over WebSocket.
  static std::vector<uint8_t> encode_message(const std::string &header_json,
                                              const std::string &body_json,
                                              BinmeType type = BINME_RESPONSE);

 protected:
  /// Decompress zlib payload. Returns empty string on failure.
  static std::string zlib_decompress(const uint8_t *data, size_t len);

  /// Compress payload with zlib. Returns empty vector on failure.
  static std::vector<uint8_t> zlib_compress(const uint8_t *data, size_t len);
};

}  // namespace unifi_chime
}  // namespace esphome
