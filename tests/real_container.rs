//! One end-to-end redoxide lifecycle against a real Minecraft server
//! container: status while stopped, login that boots the container, a real
//! Login Success through the raw forward path, idle timeout, shutdown, and
//! status after the stop.
//!
//! Skipped unless `REDOXIDE_REAL_CONTAINER_IT=1` is set and a Docker daemon
//! answers. CI sets the variable via `integration.yml`. Run locally with:
//!
//! ```text
//! REDOXIDE_REAL_CONTAINER_IT=1 cargo test --test real_container -- --nocapture
//! ```
//!
//! What the test stands up (all inside Docker, mirroring the documented
//! compose deployment):
//!
//! - a Docker network with a **stopped** `itzg/minecraft-server` container
//!   (1.21.4, offline mode) aliased as `minecraft`;
//! - a redoxide container built from the repo `Dockerfile`, with the Docker
//!   socket mounted and the config bind-mounted read-only;
//! - a raw protocol client that speaks the real Minecraft handshake, status
//!   and login packets, and answers redoxide's login-phase keepalives —
//!   including zlib-compressed framing once the server enables compression,
//!   which also proves the proxy forwards bytes it never parses.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail, ensure};
use flate2::read::ZlibDecoder;
use serde_json::Value;

use redoxide::protocol::packet::{encode_packet, encode_string, read_string_sync};
use redoxide::protocol::varint::{encode_varint, read_varint_sync};

const GATE_ENV: &str = "REDOXIDE_REAL_CONTAINER_IT";
/// Must match `server_address` in the generated config and the host the
/// client puts in its handshake.
const HANDSHAKE_HOST: &str = "mc.example.com";
const MC_VERSION: &str = "1.21.4";
const PROTOCOL: i32 = 769;
const USERNAME: &str = "it_probe";
const MOTD: &str = "§ait-test online";
/// Distinctive fallback so a passing test can tell *detected* version info
/// apart from the config values.
const FALLBACK_VERSION: &str = "fallback";
const STARTUP_SECS: u64 = 300;
const IDLE_SECS: u64 = 12;

fn gated() -> bool {
    if std::env::var(GATE_ENV).as_deref() != Ok("1") {
        return false;
    }
    Command::new("docker")
        .arg("info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn docker(args: &[&str]) -> String {
    let output = Command::new("docker")
        .args(args)
        .output()
        .expect("failed to spawn docker");
    if !output.status.success() {
        panic!(
            "docker {} failed:\n{}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        );
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn mc_running(container: &str) -> bool {
    let output = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", container])
        .output()
        .expect("failed to spawn docker");
    String::from_utf8_lossy(&output.stdout).trim() == "true"
}

/// Holds the names of everything the test creates. `Drop` runs on both
/// success and failure, so a panicking assertion never leaks containers.
struct TestEnv {
    network: String,
    mc: String,
    proxy: String,
    image: String,
    temp_dir: std::path::PathBuf,
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        eprintln!("--- redoxide log tail ---");
        let _ = Command::new("docker")
            .args(["logs", "--tail", "80", &self.proxy])
            .status();
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.mc, &self.proxy])
            .status();
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network])
            .status();
        let _ = Command::new("docker")
            .args(["image", "rm", "-f", &self.image])
            .status();
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

// ── Minimal Minecraft protocol client ─────────────────────────────────────

struct McClient {
    stream: TcpStream,
    /// Set once the server sends Set Compression; every later frame uses the
    /// compressed length prefix, even when the payload itself is uncompressed.
    threshold: Option<i32>,
}

impl McClient {
    fn connect(addr: &str) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(90)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(Self {
            stream,
            threshold: None,
        })
    }

    fn send(&mut self, id: i32, data: &[u8]) -> anyhow::Result<()> {
        self.stream.write_all(&encode_packet(id, data))?;
        Ok(())
    }

    fn recv(&mut self) -> anyhow::Result<(i32, Vec<u8>)> {
        let frame_len = read_varint_sync(&mut self.stream)? as usize;
        let mut frame = vec![0u8; frame_len];
        self.stream
            .read_exact(&mut frame)
            .context("connection closed mid-frame")?;
        let body: Vec<u8> = match self.threshold {
            None => frame,
            Some(_) => {
                let mut cursor = std::io::Cursor::new(frame.as_slice());
                let data_len = read_varint_sync(&mut cursor)?;
                let rest = frame[cursor.position() as usize..].to_vec();
                if data_len == 0 {
                    rest
                } else {
                    let mut out = Vec::with_capacity(data_len as usize);
                    ZlibDecoder::new(rest.as_slice())
                        .read_to_end(&mut out)
                        .context("decompressing packet")?;
                    out
                }
            }
        };
        let mut cursor = std::io::Cursor::new(body.as_slice());
        let id = read_varint_sync(&mut cursor)?;
        Ok((id, body[cursor.position() as usize..].to_vec()))
    }
}

fn handshake_data(next_state: i32) -> Vec<u8> {
    let mut data = encode_varint(PROTOCOL);
    data.extend(encode_string(HANDSHAKE_HOST));
    data.extend(25565u16.to_be_bytes());
    data.extend(encode_varint(next_state));
    data
}

fn login_start_data() -> Vec<u8> {
    let mut data = encode_string(USERNAME);
    data.extend([0u8; 16]); // client UUID (unused in offline mode)
    data
}

/// Full status round trip: handshake → status request → status response,
/// parsed as JSON.
fn status_round(addr: &str) -> anyhow::Result<Value> {
    let mut client = McClient::connect(addr)?;
    client.send(0x00, &handshake_data(1))?;
    client.send(0x00, &[])?; // Status Request
    let (id, data) = client.recv()?;
    ensure!(id == 0x00, "expected Status Response, got packet {id:#x}");
    let mut cursor = std::io::Cursor::new(data.as_slice());
    let json = read_string_sync(&mut cursor)?;
    Ok(serde_json::from_str(&json)?)
}

fn assert_status(
    status: &Value,
    online: i32,
    version_name: &str,
    where_: &str,
) -> anyhow::Result<()> {
    ensure!(
        status["description"]["text"] == MOTD,
        "{where_}: motd is {:?}, expected {MOTD:?} (a suffix would mean an \
         unexpected Starting/Stopping state)",
        status["description"]["text"]
    );
    ensure!(
        status["players"]["online"] == online,
        "{where_}: players.online is {}, expected {online}",
        status["players"]["online"]
    );
    ensure!(
        status["version"]["name"] == version_name,
        "{where_}: version.name is {:?}, expected {version_name:?}",
        status["version"]["name"]
    );
    ensure!(
        status["version"]["protocol"] == PROTOCOL,
        "{where_}: version.protocol is {:?}, expected {PROTOCOL}",
        status["version"]["protocol"]
    );
    Ok(())
}

/// Login through the proxy and read packets until the server sends Login
/// Success, answering redoxide's keepalives and adopting compression framing
/// on the way.
fn login_until_success(client: &mut McClient) -> anyhow::Result<()> {
    client.send(0x00, &login_start_data())?;
    let deadline = Instant::now() + Duration::from_secs(STARTUP_SECS + 60);
    loop {
        ensure!(
            Instant::now() < deadline,
            "no Login Success within the startup window"
        );
        let (id, data) = client
            .recv()
            .context("connection closed by redoxide while waiting for the server")?;
        match id {
            // Login Plugin Request: redoxide's login-phase keepalive.
            0x04 => {
                let mut cursor = std::io::Cursor::new(data.as_slice());
                let message_id = read_varint_sync(&mut cursor)?;
                let mut answer = encode_varint(message_id);
                answer.push(0); // not understood
                client.send(0x02, &answer)?;
            }
            // Set Compression: adopt the compressed framing.
            0x03 => {
                let mut cursor = std::io::Cursor::new(data.as_slice());
                let threshold = read_varint_sync(&mut cursor)?;
                client.threshold = Some(threshold);
            }
            // Login Success: the forwarded login worked end to end.
            0x02 => {
                let mut cursor = std::io::Cursor::new(data.as_slice());
                let mut uuid = [0u8; 16];
                cursor
                    .read_exact(&mut uuid)
                    .context("short Login Success packet")?;
                let name = read_string_sync(&mut cursor)?;
                ensure!(
                    name == USERNAME,
                    "server logged in {name:?}, expected {USERNAME:?}"
                );
                return Ok(());
            }
            // Login Disconnect: surface the server's reason and fail.
            0x00 => {
                let mut cursor = std::io::Cursor::new(data.as_slice());
                let reason = read_string_sync(&mut cursor).unwrap_or_default();
                bail!("server rejected the login: {reason}");
            }
            other => bail!("unexpected packet {other:#x} during login"),
        }
    }
}

// ── The lifecycle test ─────────────────────────────────────────────────────

#[test]
fn real_container_boot_login_idle_shutdown() -> anyhow::Result<()> {
    if !gated() {
        eprintln!(
            "skipping: set {GATE_ENV}=1 (with Docker running) to execute the \
             real-container integration test"
        );
        return Ok(());
    }

    let started = Instant::now();
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_millis()
    );
    let network = format!("redoxide-it-{suffix}");
    let mc = format!("redoxide-it-mc-{suffix}");
    let proxy = format!("redoxide-it-proxy-{suffix}");
    let image = format!("redoxide-it:{suffix}");
    let temp_dir = std::env::temp_dir().join(format!("redoxide-it-{suffix}"));
    std::fs::create_dir_all(&temp_dir)?;

    eprintln!("[it] building image {image} (cold builds take a few minutes)");
    docker(&["build", "-t", &image, "."]);

    let env = TestEnv {
        network: network.clone(),
        mc: mc.clone(),
        proxy: proxy.clone(),
        image: image.clone(),
        temp_dir: temp_dir.clone(),
    };

    docker(&["network", "create", &network]);
    // Created *stopped*, like the documented deployment: redoxide must be the
    // one to boot it on login.
    docker(&[
        "create",
        "--name",
        &mc,
        "--network",
        &network,
        "--network-alias",
        "minecraft",
        "-e",
        "EULA=TRUE",
        "-e",
        &format!("VERSION={MC_VERSION}"),
        "-e",
        "ONLINE_MODE=false",
        "-e",
        "MEMORY=1024M",
        "-e",
        "VIEW_DISTANCE=4",
        "itzg/minecraft-server",
    ]);
    ensure!(!mc_running(&mc), "minecraft container must start stopped");

    let config_path = temp_dir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "[proxy]\n\
             bind = \"0.0.0.0:25565\"\n\
             server_address = \"{HANDSHAKE_HOST}\"\n\
             handshake_timeout_secs = 30\n\
             \n\
             [target]\n\
             host = \"minecraft\"\n\
             port = 25565\n\
             \n\
             [docker]\n\
             container_name = \"{mc}\"\n\
             startup_timeout_secs = {STARTUP_SECS}\n\
             idle_shutdown_secs = {IDLE_SECS}\n\
             \n\
             [status]\n\
             protocol_version = {PROTOCOL}\n\
             max_players = 20\n\
             online_motd = \"{MOTD}\"\n\
             version_name = \"{FALLBACK_VERSION}\"\n"
        ),
    )?;

    docker(&[
        "run",
        "-d",
        "--name",
        &proxy,
        "--network",
        &network,
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        &format!("{}:/config.toml:ro", config_path.display()),
        "-p",
        "127.0.0.1::25565",
        &image,
    ]);
    let addr = docker(&["port", &proxy, "25565/tcp"]);
    ensure!(!addr.is_empty(), "redoxide published no host port");

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpStream::connect(&addr).is_ok() {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "redoxide did not listen within 30s (addr {addr})"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("[it] proxy up on {addr} after {:?}", started.elapsed());

    // Phase 1: the server container is stopped — status must be answered
    // locally from the config fallback (version has never been detected).
    let status = status_round(&addr)?;
    assert_status(&status, 0, FALLBACK_VERSION, "status while stopped")?;
    eprintln!("[it] status while stopped OK after {:?}", started.elapsed());

    // Phase 2: a login boots the container and is held until the server is
    // up, then forwarded — a real offline-mode Login Success proves the raw
    // forward path end to end, compressed framing included.
    let mut client = McClient::connect(&addr)?;
    client.send(0x00, &handshake_data(2))?;
    login_until_success(&mut client)?;
    ensure!(mc_running(&mc), "minecraft container must be running now");
    eprintln!("[it] login success after {:?}", started.elapsed());

    // Phase 3: status now shows the version detected by probing the real
    // server (not the config fallback) and our session.
    let status = status_round(&addr)?;
    assert_status(&status, 1, MC_VERSION, "status after login")?;
    eprintln!("[it] status after login OK after {:?}", started.elapsed());

    // Phase 4: disconnect and let the idle timer fire.
    drop(client);
    ensure!(
        mc_running(&mc),
        "container must survive the disconnect until the idle window closes"
    );

    let stop_deadline = Instant::now() + Duration::from_secs(IDLE_SECS + 150);
    while mc_running(&mc) {
        ensure!(
            Instant::now() < stop_deadline,
            "container still running {}s after the last disconnect — idle \
             shutdown did not fire",
            IDLE_SECS + 150
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    eprintln!("[it] idle shutdown complete after {:?}", started.elapsed());

    // Phase 5: stopped again — status answered locally, no session left, but
    // the detected version survives in the proxy's state.
    let status = status_round(&addr)?;
    assert_status(&status, 0, MC_VERSION, "status after idle shutdown")?;
    eprintln!("[it] lifecycle complete in {:?}", started.elapsed());

    drop(env); // explicit cleanup while the result is still inspectable
    Ok(())
}
