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
                    Ok(()) => {
                        // Clone out of the borrow before awaiting below — a
                        // held `watch::Ref` isn't `Send` across an `.await`.
                        let current = state_rx.borrow().clone();
                        match current {
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
                        }
                    }
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
        .expect("wait_for_server must return well before the 120s startup timeout");

        assert!(
            result.is_err(),
            "wait_for_server must fail when the server start fails"
        );

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
