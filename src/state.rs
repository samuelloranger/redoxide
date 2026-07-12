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
