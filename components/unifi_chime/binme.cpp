// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#include "binme.h"
#include "esphome/core/log.h"

#include "lwip/def.h"  // ntohl, htonl

namespace esphome {
namespace unifi_chime {

static const char *const TAG = "binme";

size_t BinmeCodec::parse_segment(const uint8_t *data, size_t len, BinmeSegment &out) {
  if (len < HEADER_SIZE) {
    ESP_LOGW(TAG, "Buffer too short for header: %zu", len);
    return 0;
  }

  uint8_t type_byte = data[0];
  if (type_byte != BINME_REQUEST && type_byte != BINME_RESPONSE) {
    ESP_LOGW(TAG, "Invalid segment type: 0x%02x", type_byte);
    return 0;
  }

  out.type = static_cast<BinmeType>(type_byte);
  out.subtype = data[1];
  out.compressed = (data[2] != 0);
  // data[3] is padding

  uint32_t payload_len;
  memcpy(&payload_len, data + 4, 4);
  payload_len = ntohl(payload_len);

  if (payload_len > 8192 || len < HEADER_SIZE + payload_len) {
    ESP_LOGW(TAG, "Buffer too short for payload: need %u, have %zu",
             (unsigned)(HEADER_SIZE + payload_len), len);
    return 0;
  }

  const uint8_t *payload_ptr = data + HEADER_SIZE;

  if (out.compressed) {
    out.payload = zlib_decompress(payload_ptr, payload_len);
    if (out.payload.empty()) {
      ESP_LOGW(TAG, "Decompression failed");
      return 0;
    }
  } else {
    out.payload.assign(reinterpret_cast<const char *>(payload_ptr), payload_len);
  }

  return HEADER_SIZE + payload_len;
}

bool BinmeCodec::parse_message(const uint8_t *data, size_t len, BinmeMessage &out) {
  size_t consumed = parse_segment(data, len, out.header);
  if (consumed == 0)
    return false;

  size_t consumed2 = parse_segment(data + consumed, len - consumed, out.body);
  if (consumed2 == 0)
    return false;

  return true;
}

std::vector<uint8_t> BinmeCodec::encode_segment(BinmeType type, uint8_t subtype,
                                                  const std::string &json_payload,
                                                  bool compress) {
  std::vector<uint8_t> payload_bytes;
  uint8_t compress_flag = 0;

  if (compress) {
    payload_bytes = zlib_compress(
        reinterpret_cast<const uint8_t *>(json_payload.data()), json_payload.size());
    if (payload_bytes.empty()) {
      compress = false;
    } else {
      compress_flag = 1;
    }
  }

  if (!compress) {
    payload_bytes.assign(json_payload.begin(), json_payload.end());
  }

  // BINME subtype is hardcoded to 0x01 in firmware outgoing frames
  std::vector<uint8_t> out(HEADER_SIZE + payload_bytes.size());
  out[0] = type;
  out[1] = 0x01;  // flags/subtype — hardcoded per firmware
  out[2] = compress_flag;
  out[3] = 0x00;  // padding

  uint32_t net_len = htonl(static_cast<uint32_t>(payload_bytes.size()));
  memcpy(out.data() + 4, &net_len, 4);
  memcpy(out.data() + HEADER_SIZE, payload_bytes.data(), payload_bytes.size());

  return out;
}

std::vector<uint8_t> BinmeCodec::encode_message(const std::string &header_json,
                                                  const std::string &body_json,
                                                  BinmeType type) {
  auto header_seg = encode_segment(type, 0x01, header_json);
  auto body_seg = encode_segment(type, 0x01, body_json);

  std::vector<uint8_t> out;
  out.reserve(header_seg.size() + body_seg.size());
  out.insert(out.end(), header_seg.begin(), header_seg.end());
  out.insert(out.end(), body_seg.begin(), body_seg.end());
  return out;
}

std::string BinmeCodec::zlib_decompress(const uint8_t *data, size_t len) {
  // ESP-IDF v5.x ROM only has tinfl (raw deflate), not the full miniz zlib wrapper.
  // Compressed BINME messages from the controller are rare for chime commands.
  // TODO: add esp_rom tinfl-based decompression if needed
  ESP_LOGW(TAG, "Received compressed BINME payload (%zu bytes) — decompression not yet implemented", len);
  return {};
}

std::vector<uint8_t> BinmeCodec::zlib_compress(const uint8_t *data, size_t len) {
  // Compression is never used for outgoing messages (firmware behavior).
  ESP_LOGW(TAG, "Compression requested but not implemented");
  return {};
}

}  // namespace unifi_chime
}  // namespace esphome
