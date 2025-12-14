# esp32-ble-tlv

A bare-minimum ESP32-C3 (ESP-IDF) + NimBLE example showing a tiny TLV protocol over BLE.

## What it does

- Advertises a GATT service with three characteristics:
  - `STATUS_UUID` (READ): returns counters as a TLV response frame.
  - `CONTROL_UUID` (READ, WRITE): reads current config; writes accept exactly one TLV.
  - `OTA_UUID` (READ, WRITE, WRITE_NO_RSP): real OTA flow (BEGIN/CHUNK/COMMIT).

See [API.md](API.md) for the on-wire protocol details (UUIDs, TLV tags, examples).
This is intentionally small and designed to be a good starting point for experiments.

## Build / Flash

Prereqs:

- ESP-IDF tools installed via `esp-idf-sys` (this repo uses `ESP_IDF_VERSION=tag:v5.3.2`)
- ESP Rust toolchain with the `riscv32imc-esp-espidf` target (typically via `espup`)
- `espflash` installed: `cargo install espflash`
- `espup` installed: `cargo install espup`
- `ldproxy` installed: `cargo install ldproxy`

### Linux Setup

For Linux users, follow these additional steps:

1. Install Rust if you haven't already:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. Install the ESP toolchain:

```bash
cargo install espup
espup install
```

3. Install ESP-IDF dependencies:

```bash
# Ubuntu/Debian
sudo apt-get install git clang libc6-dev

# For other distributions, check the ESP-IDF documentation
```

4. Install additional tools:

```bash
# ESP flashing tool
cargo install espflash

# Linker proxy
cargo install ldproxy
```

Commands:

```bash
cargo build
cargo run
```

The runner is configured in `.cargo/config.toml` as:

```toml
runner = "espflash flash --partition-table partitions-ota.csv --monitor"
```

To specify a particular serial port on Linux:

```bash
# Replace /dev/ttyUSB0 with your device's serial port
cargo run --port /dev/ttyUSB0
```

## TLV format

- Standard TLV: `tag:u8, len:u8, value[len]`
- One TLV per write (keeps write-side error handling simple)

Commands used by this example:

- `0x01` PING (len=0) → increments a counter
- `0x02` ECHO (len=N) → last payload is stored and exposed in STATUS
- `0x20` SET_CONFIG (len=N) → nested TLVs to update config
- `0x05` ACTION (len=1) → dummy action code
- `0x30/0x31/0x32` OTA BEGIN/CHUNK/COMMIT (via `OTA_UUID`)

Response format (READ `STATUS_UUID`):

```text
status:u8  { tag:u8, len:u8, value[len] }*
```
