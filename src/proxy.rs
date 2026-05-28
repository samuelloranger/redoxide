use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::protocol::handshake::{
    encode_handshake, encode_login_start, parse_handshake, parse_login_start, Handshake,
};
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

    let (handshake_packet, _) = read_packet(&mut reader)
        .await
        .context("reading handshake")?;
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
        2 => handle_login(reader, writer, handshake, state).await,
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
    let (status_request, _) = read_packet(reader)
        .await
        .context("reading status request")?;
    anyhow::ensure!(
        status_request.id == 0x00,
        "Expected status request packet, got {}",
        status_request.id
    );

    let base_motd = &state.config.status.online_motd;
    let motd = match state.current_state() {
        ServerState::Stopped => base_motd.clone(),
        ServerState::Starting(_) => format!("{base_motd} §7(starting...)"),
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
    state: Arc<SharedState>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (login_start_packet, _) = read_packet(&mut reader)
        .await
        .context("reading login start")?;
    anyhow::ensure!(
        login_start_packet.id == 0x00,
        "Expected login start packet, got {}",
        login_start_packet.id
    );
    let login_start = parse_login_start(&login_start_packet.data).context("parsing login start")?;

    tracing::info!(username = %login_start.username, "Login attempt");
    state.cancel_idle_shutdown().await;

    // Atomic Stopped→Starting: hold the lock while checking and transitioning
    // so concurrent logins don't both spawn docker.start().
    {
        let _guard = state.start_mutex.lock().await;
        if matches!(state.current_state(), ServerState::Stopped) {
            state.set_state(ServerState::Starting(Instant::now()));
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

    let handshake_raw = encode_packet(0x00, &encode_handshake(&handshake));
    let login_raw = encode_packet(0x00, &encode_login_start(&login_start));

    forward(reader, writer, handshake_raw, login_raw, state).await
}

async fn wait_for_server<R, W>(reader: &mut R, writer: &mut W, state: &Arc<SharedState>) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::time::{interval, Duration};

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
                if changed.is_ok() && matches!(*state_rx.borrow(), ServerState::Running) {
                    return Ok(());
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

    state.add_player();
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

    let remaining = state.remove_player();
    tracing::info!(players = remaining, "Player left");

    if remaining == 0 {
        schedule_idle_shutdown(state).await;
    }

    result?;
    Ok(())
}

async fn schedule_idle_shutdown(state: Arc<SharedState>) {
    use tokio::time::Duration;

    let mut timer_guard = state.idle_timer.lock().await;
    if let Some(handle) = timer_guard.take() {
        handle.abort();
    }

    let secs = state.config.docker.idle_shutdown_secs;
    tracing::info!(secs, "Scheduling idle shutdown");

    let state_for_timer = state.clone();
    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(secs)).await;
        if state_for_timer.player_count() > 0 {
            return;
        }

        tracing::info!("Idle timeout reached, stopping container");
        state_for_timer.set_state(ServerState::Stopped);
        let rcon = state_for_timer.config.rcon.as_ref();
        if let Err(error) = state_for_timer.docker.stop(rcon).await {
            tracing::error!("Failed to stop container: {error:#}");
        }
    });

    *timer_guard = Some(handle);
}

/// Connect to the real server, send a status ping, and extract protocol version + version name.
pub async fn probe_server_version(target: &str) -> Option<(i32, String)> {
    use tokio::time::{timeout, Duration};

    let result = timeout(Duration::from_secs(8), async {
        let mut stream = TcpStream::connect(target).await?;

        let host = target.split(':').next().unwrap_or("localhost");
        let port: u16 = target.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(25565);

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
        let json_bytes = pkt.data.get(json_start..json_start + json_len)
            .context("json out of bounds")?;
        let json: serde_json::Value = serde_json::from_slice(json_bytes)?;

        let protocol = json["version"]["protocol"].as_i64().context("no protocol")? as i32;
        let version = json["version"]["name"].as_str().context("no version")?.to_string();
        anyhow::Ok((protocol, version))
    })
    .await;

    match result {
        Ok(Ok(v)) => Some(v),
        Ok(Err(e)) => { tracing::debug!("Version probe failed: {e:#}"); None }
        Err(_) => { tracing::debug!("Version probe timed out"); None }
    }
}
