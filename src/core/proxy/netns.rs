use async_trait::async_trait;
use std::process::Command;
use tracing::info;

use super::{NetworkIsolator, ProxyListener};

pub struct LinuxNetnsIsolator {
    pub namespace_name: String,
}

#[async_trait]
impl NetworkIsolator for LinuxNetnsIsolator {
    async fn setup(&self) -> anyhow::Result<()> {
        if !cfg!(target_os = "linux") {
            anyhow::bail!("Linux netns isolator is only supported on Linux");
        }

        info!("Setting up network namespace: {}", self.namespace_name);

        run_cmd("ip", &["netns", "add", &self.namespace_name])?;

        let veth_host = format!(
            "veth-{}-h",
            &self.namespace_name[..std::cmp::min(self.namespace_name.len(), 4)]
        );
        let veth_guest = format!(
            "veth-{}-g",
            &self.namespace_name[..std::cmp::min(self.namespace_name.len(), 4)]
        );

        run_cmd(
            "ip",
            &[
                "link",
                "add",
                &veth_host,
                "type",
                "veth",
                "peer",
                "name",
                &veth_guest,
            ],
        )?;

        run_cmd(
            "ip",
            &["link", "set", &veth_guest, "netns", &self.namespace_name],
        )?;

        run_cmd("ip", &["addr", "add", "10.0.0.1/24", "dev", &veth_host])?;
        run_cmd("ip", &["link", "set", &veth_host, "up"])?;

        run_cmd(
            "ip",
            &[
                "netns",
                "exec",
                &self.namespace_name,
                "ip",
                "addr",
                "add",
                "10.0.0.2/24",
                "dev",
                &veth_guest,
            ],
        )?;
        run_cmd(
            "ip",
            &[
                "netns",
                "exec",
                &self.namespace_name,
                "ip",
                "link",
                "set",
                &veth_guest,
                "up",
            ],
        )?;

        run_cmd(
            "ip",
            &[
                "netns",
                "exec",
                &self.namespace_name,
                "ip",
                "route",
                "add",
                "default",
                "via",
                "10.0.0.1",
            ],
        )?;

        run_cmd(
            "ip",
            &[
                "netns",
                "exec",
                &self.namespace_name,
                "iptables",
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-p",
                "udp",
                "--dport",
                "53",
                "-j",
                "DNAT",
                "--to-destination",
                "10.0.0.1:53",
            ],
        )?;

        Ok(())
    }

    async fn teardown(&self) -> anyhow::Result<()> {
        if !cfg!(target_os = "linux") {
            return Ok(());
        }

        info!("Tearing down network namespace: {}", self.namespace_name);
        let _ = run_cmd("ip", &["netns", "delete", &self.namespace_name]);
        Ok(())
    }

    async fn spawn_proxy(
        &self,
        target_ip: &str,
        target_port: u16,
    ) -> anyhow::Result<(ProxyListener, tokio::task::JoinHandle<()>)> {
        let tcp_isolator = super::tcp::TcpProxyIsolator;
        let (proxy, handle) = tcp_isolator.spawn_proxy(target_ip, target_port).await?;

        tokio::spawn(async move {
            if let Ok(socket) = tokio::net::UdpSocket::bind("10.0.0.1:53").await {
                tracing::info!("DNS Interceptor listening on 10.0.0.1:53");
                let mut buf = [0u8; 512];
                while let Ok((size, peer)) = socket.recv_from(&mut buf).await {
                    tracing::info!("Intercepted DNS query from {} size {}", peer, size);
                    if size >= 12 {
                        if let Ok(upstream) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                            let _ = upstream.send_to(&buf[..size], "8.8.8.8:53").await;
                            let mut resp_buf = [0u8; 512];
                            if let Ok((resp_size, _)) = tokio::time::timeout(
                                std::time::Duration::from_secs(2),
                                upstream.recv_from(&mut resp_buf),
                            )
                            .await
                            .unwrap_or(Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "timeout",
                            ))) {
                                let _ = socket.send_to(&resp_buf[..resp_size], peer).await;
                            }
                        }
                    }
                }
            }
        });

        Ok((proxy, handle))
    }
}

fn run_cmd(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!(
            "Command `{} {:?}` failed with status: {}",
            cmd,
            args,
            status
        );
    }
    Ok(())
}
