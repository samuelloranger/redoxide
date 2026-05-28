# Redoxide — Design Spec

**Date:** 2026-05-28  
**Status:** Approved

## Overview

Redoxide is a lightweight Rust TCP proxy for a single Minecraft server. It replaces Infrared v1.3.4 with two key improvements:

1. **Hold connections during boot** — players wait transparently instead of being kicked and retrying manually. Login Plugin Request keepalives prevent client timeout.
2. **Ping never wakes the server** — only an actual login attempt starts the container.

## Project Structure

```
redoxide/
├── Cargo.toml
├── Dockerfile                        # multi-stage: rust:alpine → scratch
├── config.example.toml
└── src/
    ├── main.rs                       # startup, config loading, TCP listener
    ├── config.rs                     # Config struct, TOML deserialization
    ├── proxy.rs                      # connection handler state machine
    ├── protocol/
    │   ├── mod.rs
    │   ├── varint.rs                 # VarInt read/write
    │   ├── packet.rs                 # raw packet framing
    │   └── handshake.rs             # handshake + login-start parsing
    ├── docker.rs                     # bollard wrapper — start/stop/probe
    └── status.rs                     # MOTD/status response builder
└── .github/
    └── workflows/
        └── docker.yml                # build + push to ghcr.io on push to main
```

**Dependencies:**
- `tokio` — async runtime + TCP
- `bollard` — Docker socket API
- `serde` + `toml` — config parsing
- `serde_json` — Minecraft status JSON
- `tracing` + `tracing-subscriber` — structured logging

## Config (config.toml)

```toml
[proxy]
bind = "0.0.0.0:25565"
server_address = "forbidden.samlo.cloud"  # must match client handshake exactly

[target]
host = "minecraft"      # Docker service name / hostname
port = 25565

[docker]
container_name = "minecraft-minecraft-1"
startup_timeout_secs = 120
idle_shutdown_secs = 600

[status]
protocol_version = 769
max_players = 20
offline_motd = "§eServer is waking up! §7Please wait..."
online_motd = "§c🎉 §9§lForbidden Server§c! 🎉"
version_name = "1.21.4"
```

## Connection State Machine

```
Accept TCP
    │
    ▼
Read Handshake packet
    │
    ├─ next_state = 1 (Ping)
    │       │
    │       ▼
    │   Read Status Request
    │   → respond with MOTD JSON (offline or online variant)
    │   → does NOT wake the server
    │   → if server starting: show "⏳ Starting... Xs elapsed" in MOTD
    │   → done
    │
    └─ next_state = 2 (Login)
            │
            ▼
        Read Login Start (buffer handshake + login packets)
            │
            ├─ Server already running → forward immediately
            │
            └─ Server stopped
                    │
                    ▼
                docker.start(container_name)
                    │
                    ▼
                Loop every 2s: TCP probe to target host:port
                Every 10s: send Login Plugin Request (channel: "redoxide:keepalive")
                           ← client replies with Login Plugin Response (ignored)
                Update MOTD with elapsed time for concurrent pings
                    │
                    ├─ Timeout (startup_timeout_secs) → Login Disconnect "Server failed to start"
                    │
                    └─ Probe succeeds
                            │
                            ▼
                        Replay buffered handshake + login start to real server
                        → bidirectional pipe (client ↔ server)
                            │
                            ▼
                        Player disconnects
                        → decrement player count
                        → if count == 0: start idle timer (idle_shutdown_secs)
                        → timer fires → docker.stop(container_name)
```

## Multiple Simultaneous Logins During Boot

If multiple players connect while the server is starting, only the first triggers `docker.start()`. Subsequent connections join the same probe loop via a shared `tokio::sync::watch` channel broadcasting server state (`Stopped | Starting(Instant) | Running`). All waiting connections receive keepalives independently.

## Error Handling

| Scenario | Behaviour |
|---|---|
| Server fails to start within `startup_timeout_secs` | `Login Disconnect`: "Server failed to start, contact admin" |
| Docker socket unreachable | Log error + `Login Disconnect`: "Proxy misconfigured" |
| Client disconnects while server is starting | Cancel wait; don't stop an already-starting container |
| Server crashes mid-session | TCP close propagates naturally; idle timer starts |
| Multiple players connect while starting | One triggers start, all wait on shared state watch channel |
| Client < 1.13 (no Login Plugin support) | `Login Disconnect` after 5s timeout (non-issue: server runs 1.21.4) |

## Docker Integration

Redoxide communicates with the Docker daemon via Unix socket (`/var/run/docker.sock`) using the `bollard` crate. Required operations:

- `ContainerStart` — wake the server on login
- `ContainerStop` — idle shutdown
- `ContainerInspect` — check running state on startup

The container must exist in a stopped state (created via `docker-compose up --no-start minecraft`) for `ContainerStart` to work.

## Docker Image & CI/CD

**Dockerfile**: multi-stage build.
- Stage 1: `rust:alpine` — `cargo build --release` with static linking (`RUSTFLAGS="-C target-feature=+crt-static"`)
- Stage 2: `scratch` — copy binary only. Final image ~5MB.

**GitHub Actions** (`.github/workflows/docker.yml`):
- Trigger: push to `main`
- Build multi-platform: `linux/amd64`, `linux/arm64`
- Push to `ghcr.io/samuelloranger/redoxide:latest` and `ghcr.io/samuelloranger/redoxide:<sha>`

**Production docker-compose** (in `servers/minecraft/docker-compose.yml`):
```yaml
infrared:  # rename to redoxide
  image: ghcr.io/samuelloranger/redoxide:latest
  restart: unless-stopped
  ports:
    - "25565:25565"
  volumes:
    - ./config.toml:/config.toml:ro
    - /var/run/docker.sock:/var/run/docker.sock
  networks:
    - homelab_network
```

## Minimum Supported Minecraft Version

1.13 (Login Plugin Request introduced). Non-issue since server runs 1.21.4.
