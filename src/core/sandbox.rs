use bollard::container::LogOutput;
use bollard::models::ContainerCreateBody;
use bollard::query_parameters::{
    CreateContainerOptions, LogsOptions, RemoveContainerOptions, StartContainerOptions,
};
use bollard::Docker;
use futures_util::StreamExt;

#[derive(Debug)]
pub struct Sandbox {
    docker: Docker,
    container_id: String,
    target: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("docker: {0}")]
    Docker(#[from] bollard::errors::Error),
    #[error("docker daemon not reachable")]
    Unavailable,
}

impl Sandbox {
    pub fn is_available() -> bool {
        Docker::connect_with_local_defaults()
            .and_then(|d| {
                std::thread::spawn(move || {
                    tokio::runtime::Runtime::new().unwrap().block_on(d.ping())
                })
                .join()
                .map_err(|_| {
                    bollard::errors::Error::DockerResponseServerError {
                        status_code: 500,
                        message: "join failed".into(),
                    }
                })?
            })
            .is_ok()
    }

    pub async fn freeze(target: &str, image: &str) -> Result<Self, SandboxError> {
        let docker =
            Docker::connect_with_local_defaults().map_err(|_| SandboxError::Unavailable)?;
        docker.ping().await.map_err(|_| SandboxError::Unavailable)?;

        let name = format!("icebox-sandbox-{}", std::process::id());
        let config = ContainerCreateBody {
            image: Some(image.to_string()),
            cmd: Some(vec!["sleep".to_string(), "300".to_string()]),
            hostname: Some("icebox-sandbox".to_string()),
            ..Default::default()
        };

        let resp = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: Some(name.clone()),
                    ..Default::default()
                }),
                config,
            )
            .await?;

        docker
            .start_container(&resp.id, None::<StartContainerOptions>)
            .await?;

        Ok(Sandbox {
            docker,
            container_id: resp.id,
            target: target.to_string(),
        })
    }

    pub fn container_id(&self) -> &str {
        &self.container_id
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub async fn capture_logs(&self) -> Vec<String> {
        let opts = LogsOptions {
            stdout: true,
            stderr: true,
            ..Default::default()
        };
        let mut stream = self.docker.logs(&self.container_id, Some(opts));
        let mut lines = Vec::new();
        while let Some(Ok(chunk)) = stream.next().await {
            let text = match chunk {
                LogOutput::StdOut { message } => String::from_utf8_lossy(&message).to_string(),
                LogOutput::StdErr { message } => String::from_utf8_lossy(&message).to_string(),
                _ => continue,
            };
            for line in text.lines() {
                if !line.is_empty() {
                    lines.push(format!("[SANDBOX] {line}"));
                }
            }
        }
        lines
    }

    pub async fn melt(self) -> Result<(), SandboxError> {
        self.docker
            .remove_container(
                &self.container_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await?;
        Ok(())
    }
}
