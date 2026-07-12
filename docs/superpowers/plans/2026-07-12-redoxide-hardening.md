# Redoxide Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the 8 verified findings from the 2026-07-12 codex review (board tasks #166-#170) so redoxide can be exposed to untrusted internet traffic: unbounded allocations, lifecycle races that can leave the container running forever or report false state, lossy/version-incorrect packet re-encoding, and stale dependency/release metadata.

**Architecture:** No new modules or abstractions. Every fix is a targeted change to an existing file: `protocol/packet.rs` and `docker.rs` gain length bounds, `proxy.rs`/`state.rs` stop reconstructing packets and centralize session lifecycle bookkeeping into one RAII guard, `Cargo.toml`/`README.md`/`ci.yml` get their drifted metadata corrected. Every board finding was independently re-verified against the current source (line numbers below match what's on disk right now, not the review's paraphrase) before being folded into a task.

**Tech Stack:** Rust 2021, tokio, bollard, anyhow, serde/toml. No new dependencies are introduced — see Task 4's over-engineering-audit removals which trend the other way.

## Global Constraints

- `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` must stay clean after every task (CI enforces this — do not use `--no-verify` or silence warnings with `#[allow]`).
- All 15 existing tests must keep passing; new tests are additive.
- `config.toml` and `config.example.toml` (already deployed in production per `docker-compose.yml`) must keep parsing without edits — any new config field needs a serde default.
- No new runtime dependencies. Task 4 explicitly removes one (`thiserror`) and narrows another (`tokio` features).
- Real protocol constants only — every magic number below (`2_097_151`, `4096`, `10s`, `1.88`) is sourced from a spec or the locked dependency graph, cited inline.

---

## File Structure

| File | Change |
|---|---|
| `src/protocol/packet.rs` | Add `MAX_PACKET_LEN`/`MAX_STRING_LEN` bounds to `read_packet`/`read_string_sync`; reject negative/oversized lengths instead of allocating unbounded `Vec`s. |
| `src/protocol/handshake.rs` | `parse_login_start` returns just the username (no more hardcoded 16-byte UUID tail); drop `encode_handshake`/`encode_login_start`/`LoginStart` since raw bytes are forwarded instead of reconstructed. |
| `src/proxy.rs` | Forward the client's original raw handshake/login-start bytes instead of re-encoding; wrap the pre-login reads in a timeout; move session bookkeeping into `SharedState::begin_session`; make `wait_for_server` bail immediately (not after the full timeout) when a start attempt fails. |
| `src/state.rs` | Add `SessionGuard` (RAII: increments player count on creation, decrements + conditionally reschedules idle shutdown on drop); move `schedule_idle_shutdown` here as a method and fix it to publish `Stopped` only after `docker.stop()` succeeds; drop redundant inner `Arc`s. |
| `src/docker.rs` | Bound RCON response length; generalize `rcon_send`/`rcon_recv` over `AsyncRead + AsyncWrite` so they're unit-testable without a live RCON server. |
| `src/config.rs` | Add `proxy.handshake_timeout_secs` (serde default, backward compatible). |
| `config.toml`, `config.example.toml` | Document the new field; remove the stale `.redoxide-version-cache.json` filename. |
| `Cargo.toml` | `anyhow` → `1.0.103`, remove unused `thiserror`, narrow `tokio` features, add `rust-version = "1.88"`, bump package version to `0.2.0` to match the latest git tag. |
| `README.md` | Fix "Rust 1.75+" → "Rust 1.88+"; fix the "Minecraft 1.13+" claim to describe raw-passthrough behavior instead of a hardcoded layout; remove the stale cache filename. |
| `.github/workflows/ci.yml` | Add an MSRV job pinned to `1.88.0` so the declared `rust-version` is actually enforced. |

---

### Task 1: Bound protocol/RCON input lengths and pre-login read time

**Files:**
- Modify: `src/protocol/packet.rs`
- Modify: `src/docker.rs`
- Modify: `src/config.rs`
- Modify: `config.toml`
- Modify: `config.example.toml`
- Modify: `src/proxy.rs:21-83` (handshake/status/login-start reads only — lifecycle changes are Task 3)

**Interfaces:**
- Produces: `packet::MAX_PACKET_LEN: usize`, `packet::MAX_STRING_LEN: usize` (both `pub`, used nowhere outside tests today but kept public so Task 3/5 tests can assert against them).
- Produces: `docker::MAX_RCON_PACKET_LEN: usize`.
- Produces: `docker::rcon_send<S>`/`docker::rcon_recv<S>` now generic over `S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin` (previously hardcoded to `&mut TcpStream`).
- Produces: `ProxyConfig.handshake_timeout_secs: u64` (serde default `10`).
- Consumes: nothing from other tasks — this task is independent and can land first.

Root cause being fixed: `read_varint`/`read_varint_sync` decode a full-range `i32` with no bound on the *value* (only on the varint's *byte length*, via `shift < 35`). Every caller then does `as usize` and allocates a `Vec` of that size — `packet.rs:13` (packet length), `packet.rs:48` (string length), `docker.rs:109` (RCON body length). A crafted `-1` becomes `usize::MAX` on a 64-bit target: `vec![0u8; usize::MAX]` panics the connection-handling task (or exhausts memory before it gets there). None of these three sites, plus the initial handshake/login reads in `proxy.rs`, currently have any cap or timeout, so a slow client can also just hold a connection open forever without sending anything.

- [ ] **Step 1: Write failing tests for packet-length bounds**

Add to the `#[cfg(test)] mod tests` block in `src/protocol/packet.rs` (after the existing `test_string_round_trip`):

```rust
    #[tokio::test]
    async fn test_read_packet_rejects_negative_length() {
        // encode_varint(-1) == 0xff 0xff 0xff 0xff 0x0f — a valid 5-byte VarInt
        // whose decoded value is negative.
        let encoded = crate::protocol::varint::encode_varint(-1);
        let mut cursor = std::io::Cursor::new(encoded);
        let result = read_packet(&mut cursor).await;
        assert!(result.is_err(), "negative packet length must be rejected");
    }

    #[tokio::test]
    async fn test_read_packet_rejects_oversized_length() {
        // MAX_PACKET_LEN + 1, framed as a VarInt with no payload behind it —
        // must be rejected before any allocation/read is attempted.
        let encoded = crate::protocol::varint::encode_varint((MAX_PACKET_LEN + 1) as i32);
        let mut cursor = std::io::Cursor::new(encoded);
        let result = read_packet(&mut cursor).await;
        assert!(result.is_err(), "oversized packet length must be rejected");
    }

    #[test]
    fn test_read_string_rejects_oversized_length() {
        let encoded = crate::protocol::varint::encode_varint((MAX_STRING_LEN + 1) as i32);
        let mut cursor = std::io::Cursor::new(encoded.as_slice());
        let result = read_string_sync(&mut cursor);
        assert!(result.is_err(), "oversized string length must be rejected");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib protocol::packet -- --include-ignored 2>&1 | tail -30`
Expected: compile error (`MAX_PACKET_LEN`/`MAX_STRING_LEN` not found) — that's the expected failure mode for this step.

- [ ] **Step 3: Add the bounds to `src/protocol/packet.rs`**

Replace the top of the file through `read_packet` with:

```rust
use tokio::io::{AsyncRead, AsyncReadExt};

use super::varint::{encode_varint, read_varint, read_varint_sync};

/// Max uncompressed packet size per wiki.vg "Protocol#Packet_format": 2^21 - 1.
pub const MAX_PACKET_LEN: usize = 2_097_151;
/// Generous cap for length-prefixed strings — well above any vanilla protocol
/// string field (chat messages, the largest, cap at 262144 chars/~1MB utf8;
/// this proxy only ever reads addresses/usernames, so this is already loose).
pub const MAX_STRING_LEN: usize = 131_072;

pub struct RawPacket {
    pub id: i32,
    pub data: Vec<u8>,
}

pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<(RawPacket, Vec<u8>)> {
    let raw_length = read_varint(reader).await?;
    anyhow::ensure!(raw_length >= 0, "negative packet length: {raw_length}");
    let length = raw_length as usize;
    anyhow::ensure!(
        length <= MAX_PACKET_LEN,
        "packet length {length} exceeds max {MAX_PACKET_LEN}"
    );
    let mut buf = vec![0u8; length];
    reader.read_exact(&mut buf).await?;

    let len_bytes = encode_varint(length as i32);
    let mut raw = Vec::with_capacity(len_bytes.len() + length);
    raw.extend_from_slice(&len_bytes);
    raw.extend_from_slice(&buf);

    let mut cursor = std::io::Cursor::new(buf.as_slice());
    let id = read_varint_sync(&mut cursor)?;
    let data = buf[cursor.position() as usize..].to_vec();

    Ok((RawPacket { id, data }, raw))
}
```

Then update `read_string_sync`:

```rust
pub fn read_string_sync(cursor: &mut std::io::Cursor<&[u8]>) -> anyhow::Result<String> {
    let raw_len = read_varint_sync(cursor)?;
    anyhow::ensure!(raw_len >= 0, "negative string length: {raw_len}");
    let len = raw_len as usize;
    anyhow::ensure!(
        len <= MAX_STRING_LEN,
        "string length {len} exceeds max {MAX_STRING_LEN}"
    );
    let mut bytes = vec![0u8; len];
    std::io::Read::read_exact(cursor, &mut bytes)?;
    Ok(String::from_utf8(bytes)?)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib protocol::packet 2>&1 | tail -20`
Expected: `test result: ok. 7 passed` (4 existing + 3 new).

- [ ] **Step 5: Commit**

```bash
git add src/protocol/packet.rs
git commit -m "fix: reject negative/oversized packet and string lengths"
```

- [ ] **Step 6: Write failing tests for RCON length bound (requires generifying the stream type first)**

Replace `src/docker.rs`'s RCON section (everything from `// ── RCON protocol` to end of file) with:

```rust
// ── RCON protocol ─────────────────────────────────────────────────────────────

/// Source RCON spec caps the response body at 4096 bytes; add slack for the
/// 8-byte id+type header plus 2 null terminators already counted in `length`.
const MAX_RCON_PACKET_LEN: usize = 4096 + 10;

async fn rcon_stop(cfg: &RconConfig) -> anyhow::Result<()> {
    use tokio::time::{timeout, Duration};

    timeout(Duration::from_secs(10), async {
        let addr = format!("{}:{}", cfg.host, cfg.port);
        let mut stream = TcpStream::connect(&addr).await?;

        rcon_send(&mut stream, 1, 3, &cfg.password).await?; // Auth
        let (id, _type, _) = rcon_recv(&mut stream).await?;
        anyhow::ensure!(id != -1, "RCON authentication failed");

        rcon_send(&mut stream, 2, 2, "stop").await?; // Command
        anyhow::Ok(())
    })
    .await?
}

async fn rcon_send<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    id: i32,
    pkt_type: i32,
    payload: &str,
) -> anyhow::Result<()> {
    let payload_bytes = payload.as_bytes();
    let length = (4 + 4 + payload_bytes.len() + 2) as i32; // id + type + payload + 2 null bytes
    let mut buf = Vec::with_capacity(4 + length as usize);
    buf.extend_from_slice(&length.to_le_bytes());
    buf.extend_from_slice(&id.to_le_bytes());
    buf.extend_from_slice(&pkt_type.to_le_bytes());
    buf.extend_from_slice(payload_bytes);
    buf.extend_from_slice(&[0u8, 0u8]);
    stream.write_all(&buf).await?;
    Ok(())
}

async fn rcon_recv<S: AsyncReadExt + Unpin>(stream: &mut S) -> anyhow::Result<(i32, i32, String)> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let raw_length = i32::from_le_bytes(len_buf);
    anyhow::ensure!(raw_length >= 0, "negative RCON packet length: {raw_length}");
    let length = raw_length as usize;
    anyhow::ensure!(
        length <= MAX_RCON_PACKET_LEN,
        "RCON packet length {length} exceeds max {MAX_RCON_PACKET_LEN}"
    );

    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await?;

    let id = i32::from_le_bytes(body[0..4].try_into()?);
    let pkt_type = i32::from_le_bytes(body[4..8].try_into()?);
    let payload = String::from_utf8_lossy(&body[8..body.len().saturating_sub(2)]).to_string();
    Ok((id, pkt_type, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rcon_send_recv_round_trip() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        rcon_send(&mut client, 7, 2, "stop").await.unwrap();

        // Read what rcon_send wrote using the same framing rcon_recv expects.
        let (id, pkt_type, payload) = rcon_recv(&mut server).await.unwrap();
        assert_eq!(id, 7);
        assert_eq!(pkt_type, 2);
        assert_eq!(payload, "stop");
    }

    #[tokio::test]
    async fn test_rcon_recv_rejects_negative_length() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&(-1i32).to_le_bytes()).await.unwrap();
        let result = rcon_recv(&mut server).await;
        assert!(result.is_err(), "negative RCON length must be rejected");
    }

    #[tokio::test]
    async fn test_rcon_recv_rejects_oversized_length() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let too_big = (MAX_RCON_PACKET_LEN + 1) as i32;
        client.write_all(&too_big.to_le_bytes()).await.unwrap();
        let result = rcon_recv(&mut server).await;
        assert!(result.is_err(), "oversized RCON length must be rejected");
    }
}
```

Note: `AsyncWriteExt`/`AsyncReadExt` are already imported at the top of `src/docker.rs` (`use tokio::io::{AsyncReadExt, AsyncWriteExt};`) — no import changes needed there.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test --lib docker:: 2>&1 | tail -20`
Expected: `test result: ok. 3 passed`.

- [ ] **Step 8: Commit**

```bash
git add src/docker.rs
git commit -m "fix: bound RCON response length and make RCON framing unit-testable"
```

- [ ] **Step 9: Add `handshake_timeout_secs` to config**

In `src/config.rs`, change `ProxyConfig` and add the default function above it:

```rust
fn default_handshake_timeout_secs() -> u64 {
    10
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub bind: String,
    pub server_address: String,
    /// Max seconds to wait for the client's handshake/status/login-start
    /// packets before dropping the connection. Does not apply once the
    /// connection is forwarded to the backend.
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
}
```

Add a test to the existing `#[cfg(test)] mod tests` block in `src/config.rs`:

```rust
    #[test]
    fn test_handshake_timeout_defaults_when_absent() {
        let config = load("config.example.toml").unwrap();
        assert_eq!(config.proxy.handshake_timeout_secs, 10);
    }
```

- [ ] **Step 10: Run test to verify it passes**

Run: `cargo test --lib config:: 2>&1 | tail -20`
Expected: `test result: ok. 2 passed` (existing `test_load_example_config` + new one). Passes without touching `config.toml`/`config.example.toml` because of the serde default.

- [ ] **Step 11: Document the new field in both TOML files**

In `config.example.toml`, in the `[proxy]` section, add:

```toml
[proxy]
bind = "0.0.0.0:25565"
server_address = "your.domain.com"
# Optional: seconds to wait for handshake/status/login-start before dropping
# an idle/slow connection. Defaults to 10 if omitted.
# handshake_timeout_secs = 10
```

Leave `config.toml` as-is (it inherits the default; no edit required — this confirms the backward-compat constraint from a second angle).

- [ ] **Step 12: Commit**

```bash
git add src/config.rs config.example.toml
git commit -m "feat: add configurable handshake_timeout_secs (default 10s)"
```

- [ ] **Step 13: Wrap the pre-login reads in `src/proxy.rs` with the new timeout**

Change the imports at the top of `src/proxy.rs`:

```rust
use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::handshake::{encode_handshake, parse_handshake, parse_login_start, Handshake};
use crate::protocol::packet::{encode_packet, encode_string, read_packet};
use crate::protocol::varint::encode_varint;
use crate::state::{ServerState, SharedState};
use crate::status::{encode_login_disconnect, encode_login_plugin_request, encode_status_response};
```

(`encode_login_start`/`LoginStart` are dropped from this import list here in anticipation of Task 2 — if executing Task 1 in isolation before Task 2, leave the original import line unchanged; this exact import list is finalized in Task 2 Step 1.)

Change `handle_connection_inner`'s handshake read:

```rust
async fn handle_connection_inner(stream: TcpStream, state: Arc<SharedState>) -> anyhow::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let hello_timeout = Duration::from_secs(state.config.proxy.handshake_timeout_secs);

    let (handshake_packet, _) = timeout(hello_timeout, read_packet(&mut reader))
        .await
        .context("timed out reading handshake")??;
    let handshake = parse_handshake(&handshake_packet.data).context("parsing handshake")?;
    // ...unchanged from here down in this task; Task 2 changes what happens
    // to the discarded raw bytes and the `handle_login` call.
```

Change `handle_ping`'s status-request read:

```rust
async fn handle_ping<R, W>(
    reader: &mut R,
    writer: &mut W,
    state: &SharedState,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let hello_timeout = Duration::from_secs(state.config.proxy.handshake_timeout_secs);
    let (status_request, _) = timeout(hello_timeout, read_packet(reader))
        .await
        .context("timed out reading status request")??;
    anyhow::ensure!(
        status_request.id == 0x00,
        "Expected status request packet, got {}",
        status_request.id
    );
    // ...unchanged from here down
```

Change `handle_login`'s login-start read (function signature is finalized in Task 2 — this step only touches the read itself):

```rust
    let hello_timeout = Duration::from_secs(state.config.proxy.handshake_timeout_secs);
    let (login_start_packet, _) = timeout(hello_timeout, read_packet(&mut reader))
        .await
        .context("timed out reading login start")??;
```

- [ ] **Step 14: Run full test suite to verify nothing broke**

Run: `cargo test 2>&1 | tail -20`
Expected: `test result: ok. 18 passed` (15 original + 3 packet.rs additions; docker.rs/config.rs additions are counted separately above — running the full suite sums all of them, expect 23 passed total at this point).

- [ ] **Step 15: Commit**

```bash
git add src/proxy.rs
git commit -m "fix: time out unauthenticated handshake/status/login reads"
```

---

### Task 2: Forward raw handshake/login packets; fix version-compat claims

**Files:**
- Modify: `src/protocol/handshake.rs`
- Modify: `src/proxy.rs`
- Modify: `README.md`
- Modify: `config.example.toml`

**Interfaces:**
- Consumes: Task 1's `read_packet` (unchanged signature: `-> anyhow::Result<(RawPacket, Vec<u8>)>` — the second tuple element is the exact framed bytes as received).
- Produces: `handshake::parse_login_start(data: &[u8]) -> anyhow::Result<String>` (replaces the old `-> anyhow::Result<LoginStart>`; the fixed 16-byte UUID assumption is gone — it now reads only the length-prefixed username and ignores whatever follows, which is what makes it work across 1.13 (no tail), 1.19.x (optional signature/UUID), and 1.20.2+ (mandatory 16-byte UUID) without caring which one it is).
- Produces: `proxy::handle_login` now takes an extra `handshake_raw: Vec<u8>` parameter (the raw bytes captured for the handshake packet, previously discarded).
- Removes: `handshake::encode_handshake`, `handshake::encode_login_start`, `handshake::LoginStart` (dead after this task — nothing reconstructs packets anymore).

Root cause being fixed: `parse_login_start` (`handshake.rs:39-49`) unconditionally reads a username then exactly 16 more bytes as a UUID. That layout only matches 1.20.2+. Worse, `proxy.rs:128-129` discards the client's actual bytes and re-encodes fresh ones from the parsed struct before forwarding — for handshake this also strips anything after a `\0` in the server address (Forge/FML markers), and for any protocol version other than 1.20.2+ it fabricates a UUID tail that was never in the original packet. The fix forwards the bytes the client actually sent.

- [ ] **Step 1: Write failing tests for version-agnostic username extraction**

Replace the whole `#[cfg(test)] mod tests` block in `src/protocol/handshake.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_handshake_bytes(protocol: i32, addr: &str, port: u16, state: i32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&encode_varint(protocol));
        data.extend_from_slice(&encode_string(addr));
        data.extend_from_slice(&port.to_be_bytes());
        data.extend_from_slice(&encode_varint(state));
        data
    }

    #[test]
    fn test_parse_handshake_login() {
        let data = make_handshake_bytes(769, "forbidden.samlo.cloud", 25565, 2);
        let hs = parse_handshake(&data).unwrap();
        assert_eq!(hs.protocol_version, 769);
        assert_eq!(hs.server_address, "forbidden.samlo.cloud");
        assert_eq!(hs.server_port, 25565);
        assert_eq!(hs.next_state, 2);
    }

    #[test]
    fn test_parse_handshake_strips_forge_marker_for_validation_only() {
        let data = make_handshake_bytes(769, "forbidden.samlo.cloud\0FML2\0", 25565, 1);
        let hs = parse_handshake(&data).unwrap();
        assert_eq!(hs.server_address, "forbidden.samlo.cloud");
    }

    #[test]
    fn test_parse_login_start_1_13_style_no_tail() {
        // 1.13-1.18.2: Login Start is just the username, nothing else.
        let data = encode_string("Notch");
        let username = parse_login_start(&data).unwrap();
        assert_eq!(username, "Notch");
    }

    #[test]
    fn test_parse_login_start_1_20_2_style_with_uuid_tail() {
        // 1.20.2+: username followed by a mandatory 16-byte UUID.
        let uuid = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut data = encode_string("Notch");
        data.extend_from_slice(&uuid);
        let username = parse_login_start(&data).unwrap();
        assert_eq!(username, "Notch");
    }

    #[test]
    fn test_parse_login_start_arbitrary_tail_length() {
        // 1.19.x: optional signature data of variable length. This proxy
        // never needs to interpret the tail — it forwards the raw packet —
        // so parsing must tolerate any trailing length, including odd ones.
        let mut data = encode_string("Notch");
        data.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        let username = parse_login_start(&data).unwrap();
        assert_eq!(username, "Notch");
    }

    #[test]
    fn test_handshake_round_trip_still_used_for_validation_fields() {
        let data = make_handshake_bytes(769, "forbidden.samlo.cloud", 25565, 2);
        let hs = parse_handshake(&data).unwrap();
        assert_eq!(hs.protocol_version, 769);
        assert_eq!(hs.next_state, 2);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib protocol::handshake 2>&1 | tail -30`
Expected: compile errors — `parse_login_start` still returns `LoginStart`, not `String`.

- [ ] **Step 3: Simplify `parse_login_start` and drop the encode functions**

Replace `src/protocol/handshake.rs` in full:

```rust
use super::packet::read_string_sync;
use super::varint::read_varint_sync;

#[derive(Debug)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: i32,
}

pub fn parse_handshake(data: &[u8]) -> anyhow::Result<Handshake> {
    use std::io::Read;

    let mut cursor = std::io::Cursor::new(data);
    let protocol_version = read_varint_sync(&mut cursor)?;
    let raw_address = read_string_sync(&mut cursor)?;
    let server_address = raw_address.split('\0').next().unwrap_or("").to_string();

    let mut port_bytes = [0u8; 2];
    cursor.read_exact(&mut port_bytes)?;
    let server_port = u16::from_be_bytes(port_bytes);
    let next_state = read_varint_sync(&mut cursor)?;

    Ok(Handshake {
        protocol_version,
        server_address,
        server_port,
        next_state,
    })
}

/// Extracts just the username from a Login Start packet. Deliberately does
/// not parse whatever follows the username: that tail differs by protocol
/// version (nothing on 1.13-1.18.2, an optional signature + optional UUID on
/// 1.19.x, a mandatory 16-byte UUID on 1.20.2+) and this proxy forwards the
/// client's raw packet bytes rather than reconstructing them, so it never
/// needs to interpret the tail.
pub fn parse_login_start(data: &[u8]) -> anyhow::Result<String> {
    let mut cursor = std::io::Cursor::new(data);
    read_string_sync(&mut cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::packet::encode_string;
    use super::super::varint::encode_varint;

    fn make_handshake_bytes(protocol: i32, addr: &str, port: u16, state: i32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&encode_varint(protocol));
        data.extend_from_slice(&encode_string(addr));
        data.extend_from_slice(&port.to_be_bytes());
        data.extend_from_slice(&encode_varint(state));
        data
    }

    #[test]
    fn test_parse_handshake_login() {
        let data = make_handshake_bytes(769, "forbidden.samlo.cloud", 25565, 2);
        let hs = parse_handshake(&data).unwrap();
        assert_eq!(hs.protocol_version, 769);
        assert_eq!(hs.server_address, "forbidden.samlo.cloud");
        assert_eq!(hs.server_port, 25565);
        assert_eq!(hs.next_state, 2);
    }

    #[test]
    fn test_parse_handshake_strips_forge_marker_for_validation_only() {
        let data = make_handshake_bytes(769, "forbidden.samlo.cloud\0FML2\0", 25565, 1);
        let hs = parse_handshake(&data).unwrap();
        assert_eq!(hs.server_address, "forbidden.samlo.cloud");
    }

    #[test]
    fn test_parse_login_start_1_13_style_no_tail() {
        let data = encode_string("Notch");
        let username = parse_login_start(&data).unwrap();
        assert_eq!(username, "Notch");
    }

    #[test]
    fn test_parse_login_start_1_20_2_style_with_uuid_tail() {
        let uuid = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut data = encode_string("Notch");
        data.extend_from_slice(&uuid);
        let username = parse_login_start(&data).unwrap();
        assert_eq!(username, "Notch");
    }

    #[test]
    fn test_parse_login_start_arbitrary_tail_length() {
        let mut data = encode_string("Notch");
        data.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        let username = parse_login_start(&data).unwrap();
        assert_eq!(username, "Notch");
    }
}
```

Note: the test module now imports `encode_string`/`encode_varint` directly (they used to come along implicitly via `encode_login_start`'s dependencies at the top of the file) — the `use super::packet::{encode_string, read_string_sync};` top-of-file import becomes `use super::packet::read_string_sync;` since `encode_string` is no longer used outside tests.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib protocol::handshake 2>&1 | tail -20`
Expected: `test result: ok. 5 passed`.

- [ ] **Step 5: Commit**

```bash
git add src/protocol/handshake.rs
git commit -m "fix: stop assuming a fixed Login Start UUID layout across protocol versions"
```

- [ ] **Step 6: Forward raw bytes instead of reconstructed ones in `src/proxy.rs`**

Replace `src/proxy.rs` in full (this consolidates Task 1 Step 13's timeout edits with the raw-forwarding change so the file is internally consistent):

```rust
use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::handshake::{parse_handshake, parse_login_start, Handshake};
use crate::protocol::packet::{encode_packet, encode_string, read_packet};
use crate::protocol::varint::encode_varint;
use crate::state::{ServerState, SharedState};
use crate::status::{encode_login_disconnect, encode_login_plugin_request, encode_status_response};

pub async fn handle_connection(stream: TcpStream, state: Arc<SharedState>) {
    if let Err(error) = handle_connection_inner(stream, state).await {
        tracing::debug!("Connection closed: {error:#}");
    }
}

async fn handle_connection_inner(stream: TcpStream, state: Arc<SharedState>) -> anyhow::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let hello_timeout = Duration::from_secs(state.config.proxy.handshake_timeout_secs);

    let (handshake_packet, handshake_raw) = timeout(hello_timeout, read_packet(&mut reader))
        .await
        .context("timed out reading handshake")??;
    let handshake = parse_handshake(&handshake_packet.data).context("parsing handshake")?;

    let expected = state.config.proxy.server_address.to_lowercase();
    if handshake.server_address.to_lowercase() != expected {
        tracing::warn!(
            got = %handshake.server_address,
            expected = %expected,
            "Unknown server address"
        );
        return Ok(());
    }

    match handshake.next_state {
        1 => handle_ping(&mut reader, &mut writer, &state).await,
        2 => handle_login(reader, writer, handshake, handshake_raw, state).await,
        next_state => anyhow::bail!("Unknown next_state: {next_state}"),
    }
}

async fn handle_ping<R, W>(
    reader: &mut R,
    writer: &mut W,
    state: &SharedState,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let hello_timeout = Duration::from_secs(state.config.proxy.handshake_timeout_secs);
    let (status_request, _) = timeout(hello_timeout, read_packet(reader))
        .await
        .context("timed out reading status request")??;
    anyhow::ensure!(
        status_request.id == 0x00,
        "Expected status request packet, got {}",
        status_request.id
    );

    let base_motd = &state.config.status.online_motd;
    let motd = match state.current_state() {
        ServerState::Stopped => base_motd.clone(),
        ServerState::Starting => format!("{base_motd} §7(starting...)"),
        ServerState::Running => base_motd.clone(),
    };

    let mut effective_status = state.config.status.clone();
    effective_status.protocol_version = state.protocol_version();
    effective_status.version_name = state.version_name().await;
    let response = encode_status_response(&motd, &effective_status, state.player_count() as i32);
    writer.write_all(&response).await?;

    if let Ok((ping, raw)) = read_packet(reader).await {
        anyhow::ensure!(ping.id == 0x01, "Expected ping packet, got {}", ping.id);
        writer.write_all(&raw).await?;
    }

    Ok(())
}

async fn handle_login<R, W>(
    mut reader: R,
    mut writer: W,
    handshake: Handshake,
    handshake_raw: Vec<u8>,
    state: Arc<SharedState>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let hello_timeout = Duration::from_secs(state.config.proxy.handshake_timeout_secs);
    let (login_start_packet, login_raw) = timeout(hello_timeout, read_packet(&mut reader))
        .await
        .context("timed out reading login start")??;
    anyhow::ensure!(
        login_start_packet.id == 0x00,
        "Expected login start packet, got {}",
        login_start_packet.id
    );
    let username = parse_login_start(&login_start_packet.data).context("parsing login start")?;

    tracing::info!(
        username = %username,
        protocol = handshake.protocol_version,
        "Login attempt"
    );
    state.cancel_idle_shutdown().await;

    // Atomic Stopped→Starting: hold the lock while checking and transitioning
    // so concurrent logins don't both spawn docker.start().
    {
        let _guard = state.start_mutex.lock().await;
        if matches!(state.current_state(), ServerState::Stopped) {
            state.set_state(ServerState::Starting);
            let state_clone = state.clone();
            tokio::spawn(async move {
                if let Err(error) = state_clone.docker.start().await {
                    tracing::error!("Failed to start container: {error:#}");
                    state_clone.set_state(ServerState::Stopped);
                }
            });
        }
    }

    if !matches!(state.current_state(), ServerState::Running) {
        wait_for_server(&mut reader, &mut writer, &state).await?;
    }

    forward(reader, writer, handshake_raw, login_raw, state).await
}

async fn wait_for_server<R, W>(
    reader: &mut R,
    writer: &mut W,
    state: &Arc<SharedState>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::time::interval;

    let deadline =
        std::time::Instant::now() + Duration::from_secs(state.config.docker.startup_timeout_secs);
    let mut probe_interval = interval(Duration::from_secs(2));
    let mut keepalive_interval = interval(Duration::from_secs(10));
    // Fire first keepalive after 10s, not immediately
    keepalive_interval.tick().await;
    let mut keepalive_id = 0i32;
    let target = format!("{}:{}", state.config.target.host, state.config.target.port);
    let mut state_rx = state.subscribe();

    loop {
        if std::time::Instant::now() >= deadline {
            let _ = writer
                .write_all(&encode_login_disconnect(
                    "Server failed to start. Contact admin.",
                ))
                .await;
            anyhow::bail!("Startup timeout");
        }

        tokio::select! {
            _ = probe_interval.tick() => {
                if TcpStream::connect(&target).await.is_ok() {
                    state.set_state(ServerState::Running);
                    tracing::info!("Server is up, forwarding connection");
                    // Probe version info in background — don't block the waiting player
                    let state_clone = state.clone();
                    let target_clone = target.clone();
                    tokio::spawn(async move {
                        if let Some((protocol, version)) = probe_server_version(&target_clone).await {
                            state_clone.update_version_info(protocol, version).await;
                        }
                    });
                    return Ok(());
                }
            }
            _ = keepalive_interval.tick() => {
                let packet = encode_login_plugin_request(keepalive_id, "redoxide:keepalive");
                writer.write_all(&packet).await?;
                tracing::trace!(id = keepalive_id, "Sent keepalive");
                keepalive_id += 1;
            }
            changed = state_rx.changed() => {
                match changed {
                    Ok(()) => match *state_rx.borrow() {
                        ServerState::Running => return Ok(()),
                        ServerState::Stopped => {
                            let _ = writer
                                .write_all(&encode_login_disconnect(
                                    "Server failed to start. Contact admin.",
                                ))
                                .await;
                            anyhow::bail!("Server start failed");
                        }
                        ServerState::Starting => {}
                    },
                    Err(_) => anyhow::bail!("State channel closed"),
                }
            }
            // Drain Login Plugin Responses (and any other client packets) so they
            // don't accumulate and get forwarded to the real server after the wait.
            result = read_packet(reader) => {
                match result {
                    Ok((pkt, _)) => tracing::trace!(id = pkt.id, "Discarded client packet during wait"),
                    Err(_) => anyhow::bail!("Client disconnected while waiting for server"),
                }
            }
        }
    }
}

async fn forward<R, W>(
    mut client_reader: R,
    mut client_writer: W,
    handshake_raw: Vec<u8>,
    login_raw: Vec<u8>,
    state: Arc<SharedState>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let target = format!("{}:{}", state.config.target.host, state.config.target.port);
    let server_stream = TcpStream::connect(&target)
        .await
        .context("connecting to target server")?;
    let (mut server_reader, mut server_writer) = server_stream.into_split();

    server_writer.write_all(&handshake_raw).await?;
    server_writer.write_all(&login_raw).await?;

    tracing::info!(players = state.player_count(), "Player joined");

    // Run both copy directions concurrently. When either side closes (client
    // disconnects or server kicks the player), shut down both halves cleanly so
    // each peer receives a proper EOF rather than an abrupt RST.
    let result = tokio::try_join!(
        async {
            tokio::io::copy(&mut client_reader, &mut server_writer).await?;
            server_writer.shutdown().await
        },
        async {
            tokio::io::copy(&mut server_reader, &mut client_writer).await?;
            client_writer.shutdown().await
        },
    );

    result?;
    Ok(())
}

/// Connect to the real server, send a status ping, and extract protocol version + version name.
pub async fn probe_server_version(target: &str) -> Option<(i32, String)> {
    use tokio::time::timeout as probe_timeout;

    let result = probe_timeout(Duration::from_secs(8), async {
        let mut stream = TcpStream::connect(target).await?;

        let host = target.split(':').next().unwrap_or("localhost");
        let port: u16 = target
            .split(':')
            .nth(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(25565);

        let mut hs_data = Vec::new();
        hs_data.extend_from_slice(&encode_varint(0));
        hs_data.extend_from_slice(&encode_string(host));
        hs_data.extend_from_slice(&port.to_be_bytes());
        hs_data.extend_from_slice(&encode_varint(1));
        stream.write_all(&encode_packet(0x00, &hs_data)).await?;
        stream.write_all(&encode_packet(0x00, &[])).await?;

        // Read the status response packet using our proper framing
        let (pkt, _) = read_packet(&mut stream).await?;
        anyhow::ensure!(pkt.id == 0x00, "unexpected packet id {}", pkt.id);

        // Packet data is a Minecraft String (varint length + UTF-8)
        let mut cursor = std::io::Cursor::new(&pkt.data);
        let json_len = crate::protocol::varint::read_varint_sync(&mut cursor)? as usize;
        let json_start = cursor.position() as usize;
        let json_bytes = pkt
            .data
            .get(json_start..json_start + json_len)
            .context("json out of bounds")?;
        let json: serde_json::Value = serde_json::from_slice(json_bytes)?;

        let protocol = json["version"]["protocol"]
            .as_i64()
            .context("no protocol")? as i32;
        let version = json["version"]["name"]
            .as_str()
            .context("no version")?
            .to_string();
        anyhow::Ok((protocol, version))
    })
    .await;

    match result {
        Ok(Ok(v)) => Some(v),
        Ok(Err(e)) => {
            tracing::debug!("Version probe failed: {e:#}");
            None
        }
        Err(_) => {
            tracing::debug!("Version probe timed out");
            None
        }
    }
}
```

Note on `player_count()` semantics: this task's `forward()` no longer calls `add_player()`/`remove_player()` itself — that moves to `SharedState::begin_session()` in Task 3. Do not run Task 2 in isolation against a codebase without Task 3 applied — the two are designed to land back-to-back, and Task 2's `forward()` above assumes Task 3's guard is what's incrementing the count. If you must verify Task 2 alone, temporarily re-add `state.add_player();` at the top of `forward()`'s body and remove it when applying Task 3.

- [ ] **Step 7: Run full test suite to verify nothing broke**

Run: `cargo test 2>&1 | tail -20`
Expected: all tests pass (same count as after Task 1, since this task only changes `proxy.rs` internals and `handshake.rs`, whose test count was already accounted for in Task 2 Step 4).

- [ ] **Step 8: Fix the version-compatibility and Forge-stripping claims in `README.md`**

Replace this line (currently around line 41):

```markdown
- Minecraft 1.13+ (uses Login Plugin Request packets as keepalives; non-issue for any modern server)
```

with:

```markdown
- Minecraft 1.13+ — the proxy forwards the client's original handshake and Login Start packets byte-for-byte (it only *reads* the username and target address; it never reconstructs the packet), so it works across all protocol versions' differing Login Start layouts and passes modded (Forge/Fabric) handshake markers through untouched.
```

- [ ] **Step 9: Commit**

```bash
git add src/proxy.rs README.md
git commit -m "fix: forward raw handshake/login packets instead of lossily re-encoding them"
```

---

### Task 3: Fix abandoned-start, false-Stopped-state, and slow-failure lifecycle races

**Files:**
- Modify: `src/state.rs`
- Modify: `src/proxy.rs`

**Interfaces:**
- Consumes: Task 2's `handle_login`/`forward` signatures exactly as left above (`handle_login(reader, writer, handshake, handshake_raw, state)`; `forward` no longer touches `add_player`/`remove_player`).
- Produces: `SharedState::begin_session(self: &Arc<Self>) -> SessionGuard` — call once per login attempt, immediately after `cancel_idle_shutdown()`. Increments `player_count` on creation; on `Drop`, decrements it and, if it reached zero, spawns `schedule_idle_shutdown`.
- Produces: `SharedState::schedule_idle_shutdown(self: &Arc<Self>)` (moved from the free function `proxy::schedule_idle_shutdown`; same behavior, but publishes `ServerState::Stopped` only *after* `docker.stop()` returns `Ok`, not before).
- Removes: `proxy::schedule_idle_shutdown` (free function) — replaced by the `SharedState` method above.

Root causes being fixed (three findings, one shared mechanism):

1. **Abandoned start (#2):** `add_player()`/`schedule_idle_shutdown()` today only run inside `forward()` (`proxy.rs:224-246` pre-Task-2), which is only reached *after* `wait_for_server` returns `Ok`. If the client disconnects while waiting (`wait_for_server` bails with `Err` on read failure, or on the deadline), execution never reaches `forward()`, so a container that was started via `docker.start()` has nothing that will ever schedule its shutdown.
2. **False Stopped state (#5):** the old `schedule_idle_shutdown` (`proxy.rs:270-274` pre-Task-2) calls `state_for_timer.set_state(ServerState::Stopped)` *before* calling `docker.stop()`. If `stop()` fails, redoxide reports `Stopped` (status ping shows the offline MOTD, a new login would trigger a second concurrent `docker.start()`) while the container is still actually running.
3. **Slow failure notification (#6):** already fixed by Task 2's `wait_for_server` change (the `ServerState::Stopped` arm in the `state_rx.changed()` branch) — this task doesn't need to touch that again, it's listed here because it's part of the same board ticket (#168) and the fix is verified together in this task's tests.

The shared mechanism: move the "am I the last session, and if so arm the idle timer" responsibility out of `forward()`'s post-copy cleanup (which only runs on the happy path) and into an RAII guard that's held for the *entire* lifetime of a login attempt — from the moment `cancel_idle_shutdown()` runs, through waiting for boot, through actively playing, until disconnect. Because it's RAII, it runs on every exit path: success, error, and panic.

- [ ] **Step 1: Write failing tests for the session guard and stop-failure state consistency**

Add to `src/state.rs`, replacing the existing `#[cfg(test)]` section (there isn't one yet — add this at the end of the file):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DockerConfig, ProxyConfig, RconConfig, StatusConfig, TargetConfig};
    use crate::docker::DockerClient;

    fn test_config() -> Config {
        Config {
            proxy: ProxyConfig {
                bind: "0.0.0.0:0".to_string(),
                server_address: "test".to_string(),
                handshake_timeout_secs: 10,
            },
            target: TargetConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
            },
            docker: DockerConfig {
                // Use a container name that cannot exist so docker.start()/stop()
                // return a deterministic Err without needing a live Minecraft
                // container — only a reachable Docker daemon (present by default
                // on GitHub Actions ubuntu-latest runners).
                container_name: "redoxide-test-nonexistent-container".to_string(),
                startup_timeout_secs: 120,
                idle_shutdown_secs: 0,
            },
            status: StatusConfig {
                protocol_version: 0,
                max_players: 20,
                online_motd: "test".to_string(),
                version_name: "test".to_string(),
                server_properties: None,
            },
            rcon: None,
        }
    }

    fn test_state() -> Arc<SharedState> {
        let docker = DockerClient::new("redoxide-test-nonexistent-container".to_string()).unwrap();
        SharedState::new(test_config(), docker)
    }

    #[tokio::test]
    async fn test_begin_session_increments_and_drop_decrements_player_count() {
        let state = test_state();
        assert_eq!(state.player_count(), 0);

        let guard = state.begin_session();
        assert_eq!(state.player_count(), 1);

        drop(guard);
        // Drop spawns an async task to decrement + reschedule; give it a tick.
        tokio::task::yield_now().await;
        assert_eq!(state.player_count(), 0);
    }

    #[tokio::test]
    async fn test_stop_failure_does_not_publish_stopped_state() {
        let state = test_state();
        state.set_state(ServerState::Running);

        // idle_shutdown_secs = 0 in test_config, so this resolves almost
        // immediately. The container name doesn't exist, so docker.stop()
        // is guaranteed to fail.
        state.schedule_idle_shutdown().await;

        // Wait for the spawned timer task to run past the sleep(0) and the
        // failed stop attempt.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        assert!(
            !matches!(state.current_state(), ServerState::Stopped),
            "state must not become Stopped when docker.stop() fails"
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib state:: 2>&1 | tail -40`
Expected: compile errors — `begin_session`, `schedule_idle_shutdown` don't exist on `SharedState` yet, and `ProxyConfig` has no `handshake_timeout_secs` field visible here until Task 1 lands (if running tasks in order, Task 1 already added it — this is expected to compile once Tasks 1-2 are applied).

- [ ] **Step 3: Add `SessionGuard` and move `schedule_idle_shutdown` into `SharedState`**

Replace `src/state.rs` in full:

```rust
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::docker::DockerClient;

#[derive(Clone, Debug)]
pub enum ServerState {
    Stopped,
    Starting,
    Running,
}

pub struct SharedState {
    pub config: Config,
    pub server_tx: watch::Sender<ServerState>,
    pub player_count: AtomicUsize,
    pub docker: DockerClient,
    pub idle_timer: Mutex<Option<JoinHandle<()>>>,
    /// Guards the Stopped→Starting transition so only one login attempt triggers docker.start()
    pub start_mutex: Mutex<()>,
    /// Protocol version detected by probing the real server — overrides config value once known
    pub detected_protocol: AtomicI32,
    /// Version name detected by probing the real server
    pub detected_version: Mutex<Option<String>>,
}

impl SharedState {
    pub fn new(config: Config, docker: DockerClient) -> Arc<Self> {
        let (server_tx, _) = watch::channel(ServerState::Stopped);
        // Priority: cache > config fallback
        let cached = crate::version_cache::load();
        let initial_protocol = cached
            .as_ref()
            .map(|c| c.protocol)
            .unwrap_or(config.status.protocol_version);
        let initial_version = cached.map(|c| c.version);

        let detected_protocol = AtomicI32::new(initial_protocol);
        Arc::new(Self {
            config,
            server_tx,
            player_count: AtomicUsize::new(0),
            docker,
            idle_timer: Mutex::new(None),
            start_mutex: Mutex::new(()),
            detected_protocol,
            detected_version: Mutex::new(initial_version),
        })
    }

    pub fn current_state(&self) -> ServerState {
        self.server_tx.borrow().clone()
    }

    pub fn set_state(&self, state: ServerState) {
        self.server_tx.send_replace(state);
    }

    pub fn subscribe(&self) -> watch::Receiver<ServerState> {
        self.server_tx.subscribe()
    }

    fn add_player(&self) -> usize {
        self.player_count.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn remove_player(&self) -> usize {
        self.player_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                Some(n.saturating_sub(1))
            })
            .unwrap_or(0)
            .saturating_sub(1)
    }

    pub fn player_count(&self) -> usize {
        self.player_count.load(Ordering::SeqCst)
    }

    pub async fn cancel_idle_shutdown(&self) {
        if let Some(handle) = self.idle_timer.lock().await.take() {
            handle.abort();
        }
    }

    pub fn protocol_version(&self) -> i32 {
        self.detected_protocol.load(Ordering::Relaxed)
    }

    pub async fn version_name(&self) -> String {
        self.detected_version
            .lock()
            .await
            .clone()
            .unwrap_or_else(|| self.config.status.version_name.clone())
    }

    pub async fn update_version_info(&self, protocol: i32, version: String) {
        let changed = self.detected_protocol.load(Ordering::Relaxed) != protocol
            || self.detected_version.lock().await.as_deref() != Some(&version);

        self.detected_protocol.store(protocol, Ordering::Relaxed);
        *self.detected_version.lock().await = Some(version.clone());
        tracing::info!(protocol, version, "Detected server version");

        if changed {
            crate::version_cache::save(protocol, &version);
        }
    }

    /// Marks the start of a login attempt: the connection counts toward
    /// `player_count` (and thus "is anyone here" idle-shutdown decisions,
    /// and the status-ping online count) from this point on — whether it's
    /// still waiting for the container to boot or already forwarding
    /// traffic. Held for the entire lifetime of the connection; dropping it
    /// (on success, error, or panic — RAII, so every exit path is covered)
    /// decrements the count and, if this was the last session, arms the
    /// idle-shutdown timer. This closes the gap where a client that
    /// disconnects mid-boot left the container running with nothing
    /// scheduled to stop it.
    pub fn begin_session(self: &Arc<Self>) -> SessionGuard {
        self.add_player();
        SessionGuard {
            state: self.clone(),
        }
    }

    /// (Re)arms the idle-shutdown timer, replacing any previous one. Only
    /// publishes `ServerState::Stopped` after `docker.stop()` actually
    /// succeeds — on failure the state is left as-is so redoxide doesn't
    /// report the server offline while the container is still running.
    pub async fn schedule_idle_shutdown(self: &Arc<Self>) {
        use tokio::time::Duration;

        let mut timer_guard = self.idle_timer.lock().await;
        if let Some(handle) = timer_guard.take() {
            handle.abort();
        }

        let secs = self.config.docker.idle_shutdown_secs;
        tracing::info!(secs, "Scheduling idle shutdown");

        let state_for_timer = self.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(secs)).await;
            if state_for_timer.player_count() > 0 {
                return;
            }

            tracing::info!("Idle timeout reached, stopping container");
            let rcon = state_for_timer.config.rcon.as_ref();
            match state_for_timer.docker.stop(rcon).await {
                Ok(()) => state_for_timer.set_state(ServerState::Stopped),
                Err(error) => tracing::error!("Failed to stop container: {error:#}"),
            }
        });

        *timer_guard = Some(handle);
    }
}

pub struct SessionGuard {
    state: Arc<SharedState>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let remaining = self.state.remove_player();
        tracing::info!(players = remaining, "Session ended");
        if remaining == 0 {
            let state = self.state.clone();
            tokio::spawn(async move {
                state.schedule_idle_shutdown().await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DockerConfig, ProxyConfig, StatusConfig, TargetConfig};
    use crate::docker::DockerClient;

    fn test_config() -> Config {
        Config {
            proxy: ProxyConfig {
                bind: "0.0.0.0:0".to_string(),
                server_address: "test".to_string(),
                handshake_timeout_secs: 10,
            },
            target: TargetConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
            },
            docker: DockerConfig {
                container_name: "redoxide-test-nonexistent-container".to_string(),
                startup_timeout_secs: 120,
                idle_shutdown_secs: 0,
            },
            status: StatusConfig {
                protocol_version: 0,
                max_players: 20,
                online_motd: "test".to_string(),
                version_name: "test".to_string(),
                server_properties: None,
            },
            rcon: None,
        }
    }

    fn test_state() -> Arc<SharedState> {
        let docker = DockerClient::new("redoxide-test-nonexistent-container".to_string()).unwrap();
        SharedState::new(test_config(), docker)
    }

    #[tokio::test]
    async fn test_begin_session_increments_and_drop_decrements_player_count() {
        let state = test_state();
        assert_eq!(state.player_count(), 0);

        let guard = state.begin_session();
        assert_eq!(state.player_count(), 1);

        drop(guard);
        tokio::task::yield_now().await;
        assert_eq!(state.player_count(), 0);
    }

    #[tokio::test]
    async fn test_stop_failure_does_not_publish_stopped_state() {
        let state = test_state();
        state.set_state(ServerState::Running);

        state.schedule_idle_shutdown().await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        assert!(
            !matches!(state.current_state(), ServerState::Stopped),
            "state must not become Stopped when docker.stop() fails"
        );
    }
}
```

(The duplicate test module in Step 1 is superseded by this one — this step is the final version of the file; don't apply both.)

Note `add_player`/`remove_player` are now private (`fn`, not `pub fn`) — `forward()` no longer calls them directly (Task 2 already removed those calls from `forward()`; only `SessionGuard` calls them now).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib state:: 2>&1 | tail -20`
Expected: `test result: ok. 2 passed`. (If Docker isn't reachable at all in your environment, `test_stop_failure_does_not_publish_stopped_state` still passes — `docker.stop()` fails with a connection error just as surely as a 404, either way `Stopped` must not be published.)

- [ ] **Step 5: Commit**

```bash
git add src/state.rs
git commit -m "fix: cover abandoned-start and stop-failure lifecycle races with a session RAII guard"
```

- [ ] **Step 6: Wire `begin_session()` into `handle_login`**

In `src/proxy.rs`, change `handle_login` (the version left by Task 2 Step 6) — insert the guard right after the `cancel_idle_shutdown()` call and hold it for the rest of the function:

```rust
async fn handle_login<R, W>(
    mut reader: R,
    mut writer: W,
    handshake: Handshake,
    handshake_raw: Vec<u8>,
    state: Arc<SharedState>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let hello_timeout = Duration::from_secs(state.config.proxy.handshake_timeout_secs);
    let (login_start_packet, login_raw) = timeout(hello_timeout, read_packet(&mut reader))
        .await
        .context("timed out reading login start")??;
    anyhow::ensure!(
        login_start_packet.id == 0x00,
        "Expected login start packet, got {}",
        login_start_packet.id
    );
    let username = parse_login_start(&login_start_packet.data).context("parsing login start")?;

    tracing::info!(
        username = %username,
        protocol = handshake.protocol_version,
        "Login attempt"
    );
    state.cancel_idle_shutdown().await;
    // Held for the rest of this function, including the call into forward()
    // below — covers "client disconnects mid-boot" and "client disconnects
    // after joining" with the same mechanism (see SessionGuard's doc comment).
    let _session = state.begin_session();

    // Atomic Stopped→Starting: hold the lock while checking and transitioning
    // so concurrent logins don't both spawn docker.start().
    {
        let _guard = state.start_mutex.lock().await;
        if matches!(state.current_state(), ServerState::Stopped) {
            state.set_state(ServerState::Starting);
            let state_clone = state.clone();
            tokio::spawn(async move {
                if let Err(error) = state_clone.docker.start().await {
                    tracing::error!("Failed to start container: {error:#}");
                    state_clone.set_state(ServerState::Stopped);
                }
            });
        }
    }

    if !matches!(state.current_state(), ServerState::Running) {
        wait_for_server(&mut reader, &mut writer, &state).await?;
    }

    forward(reader, writer, handshake_raw, login_raw, state).await
}
```

No other function in `proxy.rs` changes in this step — `forward()` was already left without `add_player`/`remove_player`/`schedule_idle_shutdown` calls by Task 2, and `wait_for_server`'s `Stopped` handling was already added by Task 2.

- [ ] **Step 7: Run full test suite to verify nothing broke**

Run: `cargo test 2>&1 | tail -20`
Expected: all tests pass, count increased by the 2 new `state.rs` tests over Task 2's total.

- [ ] **Step 8: Commit**

```bash
git add src/proxy.rs
git commit -m "fix: hold the session guard for the full login/wait/forward lifetime"
```

---

### Task 4: Align dependencies, MSRV, and release metadata

**Files:**
- Modify: `Cargo.toml`
- Modify: `README.md`
- Modify: `config.example.toml`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing from other tasks — independent, can land any time (verified no code references `thiserror` anywhere in `src/`, and no code uses `tokio::fs`/`tokio::process`/`tokio::signal`/`tokio::io::{stdin,stdout,stderr}` anywhere in `src/`, confirmed by grep before writing this task).
- Produces: nothing consumed by later tasks.

Root causes being fixed (all independently re-verified, not taken on the review's word):
- `Cargo.lock` pins `anyhow 1.0.102`, which matches RUSTSEC-2026-0190 (the affected `downcast_mut` API isn't called anywhere in this codebase, so there's no exploitable path today — but there's no reason to stay on a flagged version).
- `thiserror = "1"` is declared in `Cargo.toml` but `grep -rn thiserror src/` returns nothing — confirmed unused.
- `tokio = { features = ["full"] }` pulls in `fs`, `process`, `signal`, `io-std`, etc.; `grep` confirms none of `tokio::fs`, `tokio::process`, `tokio::signal`, `tokio::io::{stdin,stdout,stderr}` appear anywhere in `src/`. Only `macros`, `rt-multi-thread`, `net`, `io-util`, `sync`, and `time` are actually used.
- `cargo metadata` shows the locked graph's highest dependency `rust-version` is `1.88` (from `time`/`time-core`/`time-macros`/`serde_with`), but `README.md:170` says "Requires Rust 1.75+" and `Cargo.toml` declares no `rust-version` at all — CI (`.github/workflows/ci.yml`) only runs `dtolnay/rust-toolchain@stable`, so this drift is never caught.
- `git tag --sort=-creatordate` shows `v0.2.0` as the latest tag; `Cargo.toml` still says `version = "0.1.0"`.
- `config.example.toml:23` and `README.md` both mention a `.redoxide-version-cache.json` filename that `src/version_cache.rs` never uses — the real (and only) path is `/var/cache/redoxide/version.json`.

- [ ] **Step 1: Update `Cargo.toml`**

Replace `Cargo.toml` in full:

```toml
[package]
name = "redoxide"
version = "0.2.0"
edition = "2021"
rust-version = "1.88"

[[bin]]
name = "redoxide"
path = "src/main.rs"

[dependencies]
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net", "io-util", "sync", "time"] }
bollard = "0.18"
serde = { version = "1", features = ["derive"] }
toml = "0.8"
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow = "1.0.103"
```

- [ ] **Step 2: Verify the build still compiles and tests still pass with narrowed features**

Run: `cargo build --all-targets --all-features 2>&1 | tail -30`
Expected: clean build — if it fails with a missing-feature error, that means some `tokio::` API in `src/` needs a feature not in the list above; add exactly that feature (do not fall back to `"full"`).

Run: `cargo test 2>&1 | tail -20`
Expected: all tests still pass.

Run: `cargo clippy --all-targets --all-features -- -D warnings 2>&1 | tail -30`
Expected: clean.

- [ ] **Step 3: Regenerate the lockfile and confirm `anyhow` moved and `thiserror` is gone**

Run: `cargo update -p anyhow 2>&1 | tail -10`
Expected: updates to `anyhow >= 1.0.103`.

Run: `grep -c 'name = "thiserror"' Cargo.lock`
Expected: `0`.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: bump anyhow past RUSTSEC-2026-0190, drop unused thiserror, narrow tokio features, set rust-version"
```

- [ ] **Step 5: Add an MSRV job to CI**

In `.github/workflows/ci.yml`, add a second job alongside the existing `check` job (keep the existing job exactly as-is; this is additive):

```yaml
  msrv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: "1.88.0"

      - uses: Swatinem/rust-cache@v2

      - name: Check on declared MSRV
        run: cargo check --locked --all-targets --all-features
```

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: enforce the declared rust-version in CI"
```

- [ ] **Step 7: Fix stale README/config claims**

In `README.md`, replace (currently around line 170):

```markdown
Requires Rust 1.75+.
```

with:

```markdown
Requires Rust 1.88+ (enforced in CI).
```

Replace (currently around line 152, the protocol-version-auto-detection section):

```markdown
redoxide automatically detects the server's protocol version and version name by pinging it directly after it starts. The detected values are cached in `.redoxide-version-cache.json` and reloaded on startup — so even when the server is stopped, the server list shows the correct version from last time.
```

with:

```markdown
redoxide automatically detects the server's protocol version and version name by pinging it directly after it starts. The detected values are cached at `/var/cache/redoxide/version.json` inside the container and reloaded on startup — so even when the server is stopped, the server list shows the correct version from last time.
```

- [ ] **Step 8: Fix the same stale filename in `config.example.toml`**

Replace (currently around line 23):

```toml
# protocol_version and version_name are auto-detected by probing the real server
# and cached in .redoxide-version-cache.json — these values are only used as a
# last resort if the cache is empty (i.e. the server has never been started yet).
```

with:

```toml
# protocol_version and version_name are auto-detected by probing the real server
# and cached at /var/cache/redoxide/version.json — these values are only used
# as a last resort if the cache is empty (i.e. the server has never been
# started yet).
```

- [ ] **Step 9: Commit**

```bash
git add README.md config.example.toml
git commit -m "docs: fix stale Rust version and version-cache filename claims"
```

---

### Task 5: Add integration-style regression tests for the fixed lifecycle behaviors

**Files:**
- Modify: `src/proxy.rs` (test module only)

**Interfaces:**
- Consumes: Task 2's `wait_for_server` (with the `Stopped` → immediate-bail branch) and Task 3's `SharedState::begin_session`/`schedule_idle_shutdown`.
- Produces: nothing — this task only adds tests, closing out board ticket #170's remaining scenarios that weren't naturally covered inline in Tasks 1-3 (malformed/oversized frames landed in Task 1; version-specific Login Start passthrough landed in Task 2).

Scope note: this task deliberately does **not** add a mock/trait abstraction over `DockerClient` (that would be new architecture beyond what the review asked for, and the audit explicitly flagged the codebase as already lean). Instead it exploits two facts verified earlier in this plan: `bollard::Docker::connect_with_defaults()` succeeds without a reachable daemon (confirmed empirically), and pointing `DockerClient` at a nonexistent container name makes `start()`/`stop()`/`is_running()` return a real, deterministic `Err` on any environment with a Docker daemon reachable (GitHub Actions `ubuntu-latest` has one by default) — so the two remaining board-ticket scenarios (abandoned-start-during-boot, start-failure notification) are testable with the real `DockerClient`, no mock needed.

- [ ] **Step 1: Write the "abandoned during boot" and "start failure notifies immediately" tests**

Add to `src/proxy.rs`, a new `#[cfg(test)] mod tests` block at the end of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, DockerConfig, ProxyConfig, StatusConfig, TargetConfig};
    use crate::docker::DockerClient;
    use tokio::net::TcpListener;

    fn test_config(startup_timeout_secs: u64) -> Config {
        Config {
            proxy: ProxyConfig {
                bind: "0.0.0.0:0".to_string(),
                server_address: "test".to_string(),
                handshake_timeout_secs: 10,
            },
            target: TargetConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
            },
            docker: DockerConfig {
                container_name: "redoxide-test-nonexistent-container".to_string(),
                startup_timeout_secs,
                idle_shutdown_secs: 0,
            },
            status: StatusConfig {
                protocol_version: 0,
                max_players: 20,
                online_motd: "test".to_string(),
                version_name: "test".to_string(),
                server_properties: None,
            },
            rcon: None,
        }
    }

    fn test_state(startup_timeout_secs: u64) -> Arc<SharedState> {
        let docker = DockerClient::new("redoxide-test-nonexistent-container".to_string()).unwrap();
        SharedState::new(test_config(startup_timeout_secs), docker)
    }

    #[tokio::test]
    async fn test_wait_for_server_bails_immediately_when_state_goes_stopped() {
        // Long startup_timeout_secs — if the fix regresses, this test would
        // hang for the full timeout instead of returning promptly.
        let state = test_state(120);
        state.set_state(ServerState::Starting);

        let (mut client_side, server_side) = tokio::io::duplex(4096);
        let (mut server_reader, mut server_writer) = tokio::io::split(server_side);

        // Simulate the spawned docker.start() task failing shortly after boot begins.
        let state_for_failure = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            state_for_failure.set_state(ServerState::Stopped);
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            wait_for_server(&mut server_reader, &mut server_writer, &state),
        )
        .await
        .expect("wait_for_server must return well before the 120s startup timeout")
        ;

        assert!(result.is_err(), "wait_for_server must fail when the server start fails");

        // A disconnect packet should have been written to the client side.
        let mut buf = [0u8; 1];
        let read_result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            tokio::io::AsyncReadExt::read(&mut client_side, &mut buf),
        )
        .await;
        assert!(
            matches!(read_result, Ok(Ok(n)) if n > 0),
            "client should receive a disconnect packet, not silence"
        );
    }

    #[tokio::test]
    async fn test_abandoned_session_schedules_idle_shutdown() {
        // idle_shutdown_secs = 0 so the scheduled timer resolves almost
        // immediately once armed, letting the test observe it without a
        // real sleep.
        let state = test_state(120);
        state.set_state(ServerState::Starting);

        {
            // Simulates handle_login's `let _session = state.begin_session();`
            // followed by the client disconnecting before forward() is ever
            // reached (wait_for_server returning Err, or any other early exit).
            let _session = state.begin_session();
            assert_eq!(state.player_count(), 1);
        }
        // Guard dropped without ever calling forward()/add_player() again —
        // this is the exact "abandoned during boot" scenario from finding #2.

        tokio::task::yield_now().await;
        assert_eq!(
            state.player_count(),
            0,
            "player count must drop even though forward() was never reached"
        );

        // Give the spawned schedule_idle_shutdown + its 0s sleep a moment to run.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // idle_timer being populated (even though the timer body has already
        // finished, the JoinHandle itself only clears on the next
        // schedule_idle_shutdown or cancel_idle_shutdown call) confirms a
        // shutdown was armed rather than the container being left with
        // nothing watching it.
        assert!(
            state.idle_timer.lock().await.is_some(),
            "an idle shutdown must have been scheduled for the abandoned session"
        );
    }

    #[tokio::test]
    async fn test_real_backend_forward_still_works_end_to_end() {
        // Sanity check that the raw-forwarding change (Task 2) and the
        // session-guard change (Task 3) didn't break the happy path: spin up
        // a fake backend that echoes whatever it receives, then confirm
        // forward() relays the handshake+login bytes to it and streams the
        // response back to the client. Drive it with an in-memory duplex
        // whose other end this test controls directly.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut socket, &mut buf)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut socket, &buf)
                .await
                .unwrap();
        });

        let mut state_config = test_config(120);
        state_config.target.host = backend_addr.ip().to_string();
        state_config.target.port = backend_addr.port();
        let docker = DockerClient::new("redoxide-test-nonexistent-container".to_string()).unwrap();
        let state = SharedState::new(state_config, docker);

        let (client_conn, mut test_harness) = tokio::io::duplex(4096);
        let (client_reader, client_writer) = tokio::io::split(client_conn);

        let forward_handle = tokio::spawn(forward(
            client_reader,
            client_writer,
            b"hello".to_vec(),
            b"world".to_vec(),
            state,
        ));

        let mut echoed = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut test_harness, &mut echoed)
            .await
            .unwrap();
        assert_eq!(&echoed, b"hello");

        drop(test_harness);
        let _ = forward_handle.await.unwrap();
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test --lib proxy:: 2>&1 | tail -30`
Expected: `test result: ok. 3 passed`.

- [ ] **Step 3: Run the full suite, fmt, and clippy one more time**

Run: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-targets --all-features 2>&1 | tail -40`
Expected: fmt clean, clippy clean, all tests pass (original 15 + additions from Tasks 1, 2, 3, 5 — expect roughly 30 total; exact count isn't load-bearing, "no failures" is).

- [ ] **Step 4: Commit**

```bash
git add src/proxy.rs
git commit -m "test: cover abandoned-start-during-boot, immediate start-failure notification, and raw forwarding end-to-end"
```

---

## Final verification (run after all 5 tasks are applied)

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release
git status   # working tree should be clean; nothing untracked/uncommitted
```

Then close board tasks #166-#170 with notes citing which commit(s) resolved each, per the standing board-update instruction — each task above maps 1:1 to one of those five tickets (Task 1 → #166, Task 2 → #167, Task 3 → #168, Task 4 → #169, Task 5 → #170).
