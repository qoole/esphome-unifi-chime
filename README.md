# esphome-unifi-chime

An ESPHome component that makes a commodity ESP32 appear as a first-party **UniFi Protect Chime** to a UniFi console. The device is discovered, adopted, and controlled through the standard Protect UI — no hacks, no middleware, no Home Assistant required.

Also includes what is believed to be the **first public documentation** of the UniFi Protect device-side protocol stack (UCP4, BINME, adoption flow, discovery TLV).

## What Works

- UDP discovery (port 10001) — console finds the device automatically
- BLE advertisement — mobile app can see the device
- HTTPS management server (port 8080) — `/api/info`, `/api/adopt`, `/api/factoryReset`
- Adoption — click "Adopt" in Protect and it just works
- UCP4 WebSocket session — persistent connection with BINME binary framing
- Command handling — `getInfo`, `networkStatus`, `getAudioInfo`, `changeUserPassword`, `reboot`, `factoryReset`
- NVS persistence — survives reboots without re-adoption
- WiFi recovery — reconnects automatically after WiFi drops

## What's Stubbed

- `playSpeaker` / `playBuzzer` / `setLEDState` — logged but no hardware driver yet
- `updateFirmware` — acknowledged but doesn't OTA
- Ringtone upload (`PUT /api/uploadRingtone/*`)
- BLE GATT provisioning (advertisement works, encrypted GATT channel does not)

## Hardware

Any ESP32 dev board with WiFi. That's it for the base functionality. For full feature parity you'd want:

- I2S amplifier (TAS2560 or equivalent) for speaker output
- Buzzer on a PWM GPIO
- Addressable LEDs (5x)
- Reset button

## Quick Start

**Requirements:** ESPHome CLI, ESP-IDF framework support

1. Clone this repo
2. Create `secrets.yaml`:
   ```yaml
   wifi_ssid: "YourNetwork"
   wifi_password: "YourPassword"
   ```
3. Build and flash:
   ```bash
   esphome run chime_example.yaml
   ```
4. Open UniFi Protect — the device appears as "UP Chime" under devices
5. Click Adopt

## Project Structure

```
components/unifi_chime/       ESPHome custom component
  unifi_chime.h/cpp           Main component — identity, command handler, lifecycle
  adoption.h/cpp              HTTPS server, /api/info, /api/adopt, NVS persistence
  ucp4.h/cpp                  WebSocket client, BINME codec, command dispatch
  binme.h/cpp                 BINME binary envelope encoder/decoder
  discovery.h/cpp             BLE advertising + UDP discovery responder
  factory_certs.h/cpp         Ubiquiti factory ECDSA cert/key (secp256r1)
certs/                        PEM files extracted from firmware
chime_example.yaml                    ESPHome device configuration
```

## Protocol Documentation

These documents describe the full UniFi Protect device-side protocol, reverse-engineered from the UP Chime firmware (v1.7.20, ESP32 Xtensa LX6) using Ghidra, with corrections from live testing against a real Protect controller.

| Document | Contents |
|----------|----------|
| [unifi_protect_device_protocol.md](unifi_protect_device_protocol.md) | Complete protocol spec — discovery, adoption, UCP4, BINME, TLS, credentials, implementation checklist |
| [reimplementation_guide.md](reimplementation_guide.md) | Practical guide for building a Protect-compatible device from scratch |
| [adoption_protocol.md](adoption_protocol.md) | Deep dive on the adoption state machine, WiFi states, NVS persistence |
| [tls_cert_provisioning.md](tls_cert_provisioning.md) | TLS certificate lifecycle — factory certs, self-signed fallback, controller provisioning |
| [function_map.md](function_map.md) | 80+ named firmware functions mapped in Ghidra |
| [triage.md](triage.md) | Initial firmware triage — hardware, peripherals, task list |

### Protocol Stack

```
 UCP4 Commands (JSON)           playSpeaker, getInfo, statusReport, ...
 BINME Envelope (binary)        8-byte header + JSON payload, two segments per frame
 WebSocket (binary frames)      subprotocol: ucp4
 TLS (mTLS)                     Factory ECDSA cert (secp256r1, CN=camera.ubnt.dev)
 TCP                            To controller host:port (typically 7442)
```

### Key Protocol Details

- **Default credentials:** `ui`/`ui` (credential version v2, TLV 0x2C = 0x03)
- **Device HTTPS port:** 8080 (not 443 — Protect's `getApiPort()` returns 8080)
- **UCP4 messages:** `{"type":"request", "action":"getInfo", "id":"<uuid>"}` — NOT the `METHOD`/`ID_PATH` format suggested by static RE
- **BINME type byte:** 0x01 = request, 0x02 = response
- **x-ident header:** Bare MAC hex (`AABBCCDDEEFF`), not BLE name (`Chime-AABBCCDDEEFF`)
- **WSS subprotocol:** Must use the native WebSocket subprotocol field, not a custom header

## Prior Art

| Project | Relationship |
|---------|-------------|
| [unifi-cam-proxy](https://github.com/keshavdv/unifi-cam-proxy) | Camera emulator for Protect — uses a different adoption path (token-based, port 7442). No UCP4/BINME documentation. |
| [unifi-ble-client](https://github.com/zerotypic/unifi-ble-client) | BLE provisioning client — documents the Curve25519/NaCl BLE auth layer we also reversed. |
| [hjdhjd/unifi-protect](https://github.com/hjdhjd/unifi-protect) | Controller-facing API client (TypeScript) — different protocol (updates WebSocket, not UCP4). |
| [Unofficial UniFi Guide](https://jrjparks.github.io/unofficial-unifi-guide/) | Network AP discovery/inform protocol — shared UDP TLV format, but different transport (TNBU/AES, not UCP4/BINME). |

## Disclaimer

This project is not affiliated with or endorsed by Ubiquiti Inc. UniFi, UniFi Protect, and UP Chime are trademarks of Ubiquiti Inc. The factory TLS certificate embedded in this project was extracted from publicly available firmware. This project is intended for personal, educational, and research use only.

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for hobbyists, researchers, and non-commercial use. Not licensed for commercial purposes.
