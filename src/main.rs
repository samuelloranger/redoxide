mod config;
mod docker;
mod protocol;
mod proxy;
mod state;
mod status;
mod version_cache;

use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "redoxide=info".into()),
        )
        .init();

    let config = config::load("config.toml")?;
    info!(
        bind = %config.proxy.bind,
        server = %config.proxy.server_address,
        "redoxide starting"
    );

    let docker = docker::DockerClient::new(config.docker.container_name.clone())?;
    let initial_state = if docker.is_running().await.unwrap_or(false) {
        info!("Container already running at startup");
        state::ServerState::Running
    } else {
        state::ServerState::Stopped
    };

    let shared = state::SharedState::new(config.clone(), docker);
    shared.set_state(initial_state.clone());

    // If already running at startup, detect version immediately
    if matches!(initial_state, state::ServerState::Running) {
        let target = format!("{}:{}", config.target.host, config.target.port);
        match proxy::probe_server_version(&target).await {
            Some((protocol, version)) => shared.update_version_info(protocol, version).await,
            None => tracing::warn!("Could not detect server version from {target}, using config values"),
        }
    }

    let listener = TcpListener::bind(&config.proxy.bind).await?;
    info!("Listening on {}", config.proxy.bind);

    loop {
        let (stream, addr) = listener.accept().await?;
        tracing::debug!(%addr, "Accepted connection");
        let state = shared.clone();
        tokio::spawn(proxy::handle_connection(stream, state));
    }
}
