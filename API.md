# esp32-ble-tlv — BLE API (Example)

This example exposes a single custom GATT service with two characteristics:

- `STATUS_UUID` (READ)
- `CONTROL_UUID` (READ, WRITE)
- `OTA_UUID` (READ, WRITE, WRITE_NO_RSP)

All **writes** to `CONTROL_UUID` must contain **exactly one TLV**.

## UUIDs

- `SVC_UUID` = `01000000-0000-4000-8000-000053564300`
- `STATUS_UUID` = `02000000-0000-4000-8000-000053544154`
- `CONTROL_UUID` = `03000000-0000-4000-8000-00004354524C`
- `OTA_UUID` = `05000000-0000-4000-8000-00004F544100`

## TLV format

Standard TLV:

```text
tag:u8  len:u8  value[len]
```

Extended TLV (used only for `OTA_CHUNK`):

```text
tag:u8  len:u16 LE  value[len]
```

## Response format (READ characteristics)

Both `STATUS_UUID` and `CONTROL_UUID` return a **response frame**:

```text
status:u8  { tag:u8 len:u8 value[len] }*
```

- `status`:
  - `0x00` = Ok
  - `0x01` = BadRequest
  - `0x02` = InternalError

## OTA (real-world TLV example)

This example implements an OTA flow similar to the main firmware:

1. Write `OTA_BEGIN` (with response)
2. Stream `OTA_CHUNK` packets (typically write-no-response)
3. Write `OTA_COMMIT` (with response)
4. Reboot the device to boot the new image

### OTA commands (write to `OTA_UUID`)

#### `OTA_BEGIN` (0x30)

- TLV: `30 24 <total_len:u32 LE> <sha256:[32]>`
- `sha256` is the SHA-256 of the exact bytes you will send via chunks.

#### `OTA_CHUNK` (0x31)

- Uses the **extended TLV header** (`len:u16 LE`).
- Value: `offset:u32 LE` followed by raw bytes.
- The device requires `offset == bytes_received` (sequential upload).

Shape:

```text
31 <len:u16 LE>  <offset:u32 LE> <data...>
```

#### `OTA_COMMIT` (0x32)

- TLV: `32 40 <sig_ed25519:[64]>`
- Signature is Ed25519 over the **32-byte SHA-256** from `OTA_BEGIN`.

The demo public key is embedded in firmware (see `src/ota.rs`).

Demo key material (for testing only):

- Public key (hex): `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`
- Private key seed (hex): `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`

You can generate a signature over the 32-byte SHA-256 from `OTA_BEGIN` using that seed in any Ed25519 library.

### OTA progress (read `OTA_UUID`)

Reading `OTA_UUID` returns a response frame containing:

- `OTA_PROGRESS` (0x50): `u32 LE` bytes received
- `OTA_TOTAL` (0x51): `u32 LE` total bytes (from `OTA_BEGIN`)

## CONTROL writes (commands)

### `PING` (0x01)

- Tag: `0x01`
- Len: `0`
- Value: empty
- Behavior: increments an internal ping counter.

Example write:

```text
01 00
```

### `ECHO` (0x02)

- Tag: `0x02`
- Len: N
- Value: any bytes
- Behavior: records the last payload length (for debugging).

Example write ("hi"):

```text
02 02 68 69
```

### `ACTION` (0x05)

- Tag: `0x30`
- Len: `1`
- Value: `action_code:u8`
- Behavior: records the last action code and increments an action counter.

Example write:

```text
05 01 01
```

### `SET_CONFIG` (0x20)

- Tag: `0x20`
- Len: N
- Value: a **nested TLV stream**: `{ tag:u8 len:u8 value[len] }*`
- Behavior:
  - Parses items in order
  - Applies recognized items
  - Ignores unknown items
  - Increments `CONFIG_VERSION` if anything changed

#### Config item TLVs (nested inside `SET_CONFIG`)

- `NAME` (0x06)
  - Len: `0..=20`
  - Value: UTF-8 bytes
- `NEAR_FAR_THRESHOLD` (0x0A)
  - Len: `1`
  - Value: `i8` dBm (two’s complement)
- `INITIAL_QUIET` (0x0B)
  - Len: `1`
  - Value: `u8` seconds
- `ALARM_ESCALATION_AFTER` (0x0C)
  - Len: `1`
  - Value: `u8` seconds

Example write (set name="demo", threshold=-60dBm):

```text
20 09
   06 04 64 65 6D 6F
   0A 01 C4
```

## CONTROL read

Reading `CONTROL_UUID` returns the current config packed into a `CONFIG` TLV:

- Tag: `0x20` (same as `SET_CONFIG`)
- Value: the nested TLV stream described above

Example read (shape only):

```text
00
20 ..  { 06 .. <name> 0A 01 <thr> 0B 01 <quiet> 0C 01 <escalate> }
```

## STATUS read

Reading `STATUS_UUID` returns a few debug counters:

- `PING_COUNT` (0x10): `u32 LE`
- `LAST_ECHO_LEN` (0x11): `u32 LE`
- `CONFIG_VERSION` (0x12): `u32 LE`
- `LAST_ACTION` (0x13): `u8`
- `OTA_SUCCESS_COUNT` (0x14): `u32 LE`

Example read (shape only):

```text
00
10 04 <ping:u32>
11 04 <echo_len:u32>
12 04 <cfg_ver:u32>
13 01 <last_action:u8>
14 04 <ota_success:u32>
```
