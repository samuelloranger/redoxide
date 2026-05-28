use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::docker::DockerClient;

#[derive(Clone, Debug)]
pub enum ServerState {
    Stopped,
    Starting(Instant),
    Running,
}

pub struct SharedState {
    pub config: Config,
    pub server_tx: watch::Sender<ServerState>,
    pub player_count: Arc<AtomicUsize>,
    pub docker: DockerClient,
    pub idle_timer: Arc<Mutex<Option<JoinHandle<()>>>>,
    /// Guards the Stopped→Starting transition so only one login attempt triggers docker.start()
    pub start_mutex: Mutex<()>,
}

impl SharedState {
    pub fn new(config: Config, docker: DockerClient) -> Arc<Self> {
        let (server_tx, _) = watch::channel(ServerState::Stopped);
        Arc::new(Self {
            config,
            server_tx,
            player_count: Arc::new(AtomicUsize::new(0)),
            docker,
            idle_timer: Arc::new(Mutex::new(None)),
            start_mutex: Mutex::new(()),
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

    pub fn add_player(&self) -> usize {
        self.player_count.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn remove_player(&self) -> usize {
        self.player_count.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            Some(n.saturating_sub(1))
        }).unwrap_or(0).saturating_sub(1)
    }

    pub fn player_count(&self) -> usize {
        self.player_count.load(Ordering::SeqCst)
    }

    pub async fn cancel_idle_shutdown(&self) {
        if let Some(handle) = self.idle_timer.lock().await.take() {
            handle.abort();
        }
    }
}
