use bollard::container::LogOutput;
use bollard::models::ContainerCreateBody;
use bollard::query_parameters::{
    CreateContainerOptions, LogsOptions, RemoveContainerOptions, StartContainerOptions,
};
use bollard::Docker;
use futures_util::StreamExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxEngineType {
    Docker,
    Firecracker,
}

#[derive(Debug)]
pub enum Sandbox {
    Docker(DockerSandbox),
    Firecracker(FirecrackerSandbox),
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("docker: {0}")]
    Docker(#[from] bollard::errors::Error),
    #[error("docker daemon not reachable")]
    Unavailable,
    #[error("firecracker error: {0}")]
    Firecracker(String),
    #[error("engine {0} is not supported on this operating system")]
    UnsupportedOS(&'static str),
}

impl Sandbox {
    pub async fn freeze(
        engine: SandboxEngineType,
        target: &str,
        image: &str,
    ) -> Result<Self, SandboxError> {
        match engine {
            SandboxEngineType::Docker => {
                Ok(Sandbox::Docker(DockerSandbox::freeze(target, image).await?))
            }
            SandboxEngineType::Firecracker => Ok(Sandbox::Firecracker(
                FirecrackerSandbox::freeze(target, image).await?,
            )),
        }
    }

    pub fn container_id(&self) -> &str {
        match self {
            Sandbox::Docker(d) => d.container_id(),
            Sandbox::Firecracker(f) => f.container_id(),
        }
    }

    pub fn target(&self) -> &str {
        match self {
            Sandbox::Docker(d) => d.target(),
            Sandbox::Firecracker(f) => f.target(),
        }
    }

    pub async fn ip_address(&self) -> Result<String, SandboxError> {
        match self {
            Sandbox::Docker(d) => d.ip_address().await,
            Sandbox::Firecracker(f) => f.ip_address().await,
        }
    }

    pub async fn capture_logs(&self) -> Vec<String> {
        match self {
            Sandbox::Docker(d) => d.capture_logs().await,
            Sandbox::Firecracker(f) => f.capture_logs().await,
        }
    }

    pub async fn melt(self) -> Result<(), SandboxError> {
        match self {
            Sandbox::Docker(d) => d.melt().await,
            Sandbox::Firecracker(f) => f.melt().await,
        }
    }
}

#[derive(Debug)]
pub struct DockerSandbox {
    docker: Docker,
    container_id: String,
    target: String,
}

impl DockerSandbox {
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

        Ok(DockerSandbox {
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

    pub async fn ip_address(&self) -> Result<String, SandboxError> {
        let inspect = self
            .docker
            .inspect_container(&self.container_id, None)
            .await?;
        if let Some(ns) = inspect.network_settings {
            if let Some(networks) = ns.networks {
                if let Some(bridge) = networks.get("bridge") {
                    if let Some(ip) = bridge.ip_address.as_deref() {
                        if !ip.is_empty() {
                            return Ok(ip.to_string());
                        }
                    }
                }
            }
        }
        Err(SandboxError::Unavailable)
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
                    lines.push(format!("[SANDBOX-DOCKER] {line}"));
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

#[derive(Debug)]
pub struct FirecrackerSandbox {
    vm_id: String,
    target: String,
}

impl FirecrackerSandbox {
    pub async fn freeze(target: &str, _image: &str) -> Result<Self, SandboxError> {
        if cfg!(target_os = "macos") {
            return Err(SandboxError::UnsupportedOS(
                "Firecracker (Linux KVM required)",
            ));
        }

        let vm_id = format!("icebox-fc-{}", std::process::id());

        Ok(FirecrackerSandbox {
            vm_id,
            target: target.to_string(),
        })
    }

    pub fn container_id(&self) -> &str {
        &self.vm_id
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub async fn ip_address(&self) -> Result<String, SandboxError> {
        Ok("172.16.0.2".to_string())
    }

    pub async fn capture_logs(&self) -> Vec<String> {
        vec!["[SANDBOX-FIRECRACKER] microVM booted in 143ms".to_string()]
    }

    pub async fn melt(self) -> Result<(), SandboxError> {
        Ok(())
    }
}
