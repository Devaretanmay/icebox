use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::models::ContainerCreateBody;
use bollard::query_parameters::{
    CreateContainerOptions, LogsOptions, RemoveContainerOptions, StartContainerOptions,
};
use bollard::Docker;
use futures_util::StreamExt;
use crate::core::module::ModuleResult;
use hyperlocal::{Uri, UnixConnector};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Request;

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
    #[error("worker error: {0}")]
    Worker(String),
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
            SandboxEngineType::Firecracker => {
                Err(SandboxError::UnsupportedOS("Firecracker (Linux KVM required)"))
            }
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

    pub async fn exec_module(
        &self,
        name: &str,
        target: &str,
        options: &serde_json::Value,
    ) -> Result<ModuleResult, SandboxError> {
        match self {
            Sandbox::Docker(d) => d.exec_module(name, target, options).await,
            Sandbox::Firecracker(_) => {
                Err(SandboxError::UnsupportedOS("worker exec requires Docker"))
            }
        }
    }
}

#[derive(Debug)]
pub struct DockerSandbox {
    docker: Docker,
    container_id: String,
    target: String,
}

async fn ensure_image(docker: &Docker, image: &str) -> Result<(), SandboxError> {
    if docker.inspect_image(image).await.is_ok() {
        return Ok(());
    }
    if image == "icebox-sandbox:latest" {
        let worker = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("icebox-worker")))
            .filter(|p| p.exists())
            .or_else(|| {
                let p = std::path::Path::new("dist/icebox-worker");
                p.exists().then(|| p.to_path_buf())
            });
        let Some(worker) = worker else {
            return Err(SandboxError::Unavailable);
        };
        let dir = std::env::temp_dir().join("icebox-sandbox-build");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("icebox-worker"), std::fs::read(&worker).map_err(|e| {
            SandboxError::Worker(e.to_string())
        })?);
        let _ = std::fs::write(
            dir.join("Dockerfile"),
            "FROM alpine:3.20\nCOPY icebox-worker /usr/local/bin/icebox-worker\nRUN chmod +x /usr/local/bin/icebox-worker\n",
        );
        let ok = std::process::Command::new("docker")
            .args(["build", "-t", "icebox-sandbox:latest", "."])
            .current_dir(&dir)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok && docker.inspect_image(image).await.is_ok() {
            return Ok(());
        }
        return Err(SandboxError::Unavailable);
    }
    let mut stream = docker
        .create_image(
            Some(
                bollard::query_parameters::CreateImageOptions {
                    from_image: Some(image.to_string()),
                    ..Default::default()
                },
            ),
            None,
            None,
        );
    while stream.next().await.is_some() {}
    Ok(())
}

impl DockerSandbox {
    pub fn is_available() -> bool {
        Docker::connect_with_local_defaults()
            .and_then(|d| {
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().map_err(
                        |_| bollard::errors::Error::DockerResponseServerError {
                            status_code: 500,
                            message: "runtime creation failed".into(),
                        },
                    )?;
                    rt.block_on(d.ping())
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

        ensure_image(&docker, image).await?;

        let name = format!("icebox-sandbox-{}", std::process::id());

        let cmd = Some(vec!["sleep".to_string(), "3600".to_string()]);

        let config = ContainerCreateBody {
            image: Some(image.to_string()),
            cmd,
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

    pub async fn exec_module(
        &self,
        name: &str,
        target: &str,
        options: &serde_json::Value,
    ) -> Result<ModuleResult, SandboxError> {
        let opts = serde_json::to_string(options).unwrap_or_else(|_| "{}".into());
        let cmd = vec![
            "icebox-worker".to_string(),
            "worker".to_string(),
            "--module".to_string(),
            name.to_string(),
            "--target".to_string(),
            target.to_string(),
            "--options".to_string(),
            opts,
        ];
        let create = self
            .docker
            .create_exec(
                &self.container_id,
                CreateExecOptions {
                    cmd: Some(cmd),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let id = create.id;
        let mut stdout: Vec<u8> = Vec::new();
        let stream = self.docker.start_exec(&id, None::<StartExecOptions>).await?;
        if let StartExecResults::Attached { mut output, .. } = stream {
            while let Some(chunk) = output.next().await {
                match chunk {
                    Ok(LogOutput::StdOut { message }) => stdout.extend_from_slice(&message),
                    Ok(LogOutput::StdErr { message }) => {
                        tracing::info!("[SANDBOX-WORKER] {}", String::from_utf8_lossy(&message));
                    }
                    _ => {}
                }
            }
        }
        let inspect = self.docker.inspect_exec(&id).await?;
        if inspect.exit_code.unwrap_or(1) != 0 {
            return Err(SandboxError::Worker(format!(
                "worker exited with code {}",
                inspect.exit_code.unwrap_or(-1)
            )));
        }
        serde_json::from_slice::<ModuleResult>(&stdout)
            .map_err(|e| SandboxError::Worker(format!("failed to parse worker output: {e}")))
    }
}

use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::io::Read;

#[derive(Debug)]
pub struct FirecrackerSandbox {
    vm_id: String,
    target: String,
    socket_path: String,
    child: Arc<Mutex<Option<Child>>>,
    logs: Arc<Mutex<Vec<String>>>,
}

impl FirecrackerSandbox {
    pub async fn freeze(target: &str, _image: &str) -> Result<Self, SandboxError> {
        if cfg!(target_os = "macos") {
            return Err(SandboxError::UnsupportedOS(
                "Firecracker (Linux KVM required)",
            ));
        }

        let vm_id = format!("icebox-fc-{}", std::process::id());
        let socket_path = format!("/tmp/{}.socket", vm_id);
        
        // Spawn firecracker process with `--api-sock` = socket_path
        let mut child = std::process::Command::new("firecracker")
            .arg("--api-sock")
            .arg(&socket_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::Firecracker(format!("failed to spawn firecracker: {e}")))?;

        let logs = Arc::new(Mutex::new(Vec::new()));
        let logs_clone = logs.clone();
        
        if let Some(mut stdout) = child.stdout.take() {
            std::thread::spawn(move || {
                let mut buf = String::new();
                if stdout.read_to_string(&mut buf).is_ok() {
                    if let Ok(mut l) = logs_clone.lock() {
                        for line in buf.lines() {
                            l.push(format!("[FC-STDOUT] {}", line));
                        }
                    }
                }
            });
        }
        
        let logs_clone2 = logs.clone();
        if let Some(mut stderr) = child.stderr.take() {
            std::thread::spawn(move || {
                let mut buf = String::new();
                if stderr.read_to_string(&mut buf).is_ok() {
                    if let Ok(mut l) = logs_clone2.lock() {
                        for line in buf.lines() {
                            l.push(format!("[FC-STDERR] {}", line));
                        }
                    }
                }
            });
        }

        let sandbox = FirecrackerSandbox {
            vm_id,
            target: target.to_string(),
            socket_path: socket_path.clone(),
            child: Arc::new(Mutex::new(Some(child))),
            logs,
        };

        // Wait for socket to become available
        for _ in 0..50 {
            if std::path::Path::new(&socket_path).exists() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        
        // Configure boot source
        sandbox.put_uds("/boot-source", serde_json::json!({
            "kernel_image_path": format!("{}/.cache/icebox/firecracker/vmlinux.bin", std::env::var("HOME").unwrap_or_default()),
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
        })).await?;

        // Configure rootfs
        sandbox.put_uds("/drives/rootfs", serde_json::json!({
            "drive_id": "rootfs",
            "path_on_host": format!("{}/.cache/icebox/firecracker/bionic.rootfs.ext4", std::env::var("HOME").unwrap_or_default()),
            "is_root_device": true,
            "is_read_only": false
        })).await?;

        // Configure network
        let tap_name = format!("tap-{}", sandbox.vm_id.chars().rev().take(4).collect::<String>());
        
        // Create the tap device on the host
        let _ = std::process::Command::new("ip")
            .args(["tuntap", "add", "dev", &tap_name, "mode", "tap"])
            .status();
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", &tap_name, "up"])
            .status();
            
        sandbox.put_uds("/network-interfaces/eth0", serde_json::json!({
            "iface_id": "eth0",
            "guest_mac": "AA:FC:00:00:00:01",
            "host_dev_name": tap_name
        })).await?;

        // Start instance
        sandbox.put_uds("/actions", serde_json::json!({
            "action_type": "InstanceStart"
        })).await?;

        Ok(sandbox)
    }

    async fn put_uds(&self, path: &str, payload: serde_json::Value) -> Result<(), SandboxError> {
        let connector = UnixConnector;
        let client: Client<UnixConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);
        
        let url: hyper::Uri = Uri::new(&self.socket_path, path).into();
        
        let req = Request::builder()
            .method("PUT")
            .uri(url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(payload.to_string())))
            .map_err(|e| SandboxError::Firecracker(e.to_string()))?;
            
        let res = client.request(req).await
            .map_err(|e| SandboxError::Firecracker(e.to_string()))?;
            
        if !res.status().is_success() {
            return Err(SandboxError::Firecracker(format!("UDS Error: {}", res.status())));
        }
        
        Ok(())
    }

    pub fn container_id(&self) -> &str {
        &self.vm_id
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub async fn ip_address(&self) -> Result<String, SandboxError> {
        // In Firecracker, we assign this statically via the tap bridge
        Ok("172.16.0.2".to_string())
    }

    pub async fn capture_logs(&self) -> Vec<String> {
        if let Ok(l) = self.logs.lock() {
            l.clone()
        } else {
            vec!["[SANDBOX-FIRECRACKER] Error locking logs".to_string()]
        }
    }

    pub async fn melt(self) -> Result<(), SandboxError> {
        if let Ok(mut c) = self.child.lock() {
            if let Some(mut child) = c.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        let _ = std::process::Command::new("rm")
            .arg("-f")
            .arg(&self.socket_path)
            .status();
        Ok(())
    }
}
