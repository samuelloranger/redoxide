use bollard::container::{InspectContainerOptions, StartContainerOptions, StopContainerOptions};
use bollard::Docker;

#[derive(Clone)]
pub struct DockerClient {
    client: Docker,
    pub container_name: String,
}

impl DockerClient {
    pub fn new(container_name: String) -> anyhow::Result<Self> {
        let client = Docker::connect_with_unix_defaults()?;
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
        Ok(info.state.and_then(|state| state.running).unwrap_or(false))
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        self.client
            .start_container(&self.container_name, None::<StartContainerOptions<String>>)
            .await?;
        tracing::info!(container = %self.container_name, "Container started");
        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        self.client
            .stop_container(&self.container_name, None::<StopContainerOptions>)
            .await?;
        tracing::info!(container = %self.container_name, "Container stopped");
        Ok(())
    }
}
