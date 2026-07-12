use bollard::container::{InspectContainerOptions, StartContainerOptions, StopContainerOptions};
use bollard::Docker;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::RconConfig;

#[derive(Clone)]
pub struct DockerClient {
    client: Docker,
    pub container_name: String,
}

impl DockerClient {
    pub fn new(container_name: String) -> anyhow::Result<Self> {
        let client = Docker::connect_with_defaults()?;
        Ok(Self {
            client,
            container_name,
        })
    }

    pub async fn is_running(&self) -> anyhow::Result<bool> {
        let info = self
            .client
            .inspect_container(&self.container_name, None::<InspectContainerOptions>)
            .await?;
        Ok(info.state.and_then(|s| s.running).unwrap_or(false))
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        self.client
            .start_container(&self.container_name, None::<StartContainerOptions<String>>)
            .await?;
        tracing::info!(container = %self.container_name, "Container started");
        Ok(())
    }

    /// Graceful stop: send RCON /stop if configured, fall back to docker stop.
    pub async fn stop(&self, rcon: Option<&RconConfig>) -> anyhow::Result<()> {
        if let Some(rcon) = rcon {
            match rcon_stop(rcon).await {
                Ok(()) => {
                    tracing::info!(container = %self.container_name, "Sent RCON /stop");
                    // Wait for container to exit (up to 30s) before returning
                    for _ in 0..30 {
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        if !self.is_running().await.unwrap_or(true) {
                            tracing::info!(container = %self.container_name, "Container stopped gracefully");
                            return Ok(());
                        }
                    }
                    tracing::warn!("Server did not stop after RCON /stop, forcing docker stop");
                }
                Err(e) => {
                    tracing::warn!("RCON /stop failed ({e:#}), falling back to docker stop");
                }
            }
        }

        self.client
            .stop_container(&self.container_name, None::<StopContainerOptions>)
            .await?;
        tracing::info!(container = %self.container_name, "Container stopped");
        Ok(())
    }
}

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
