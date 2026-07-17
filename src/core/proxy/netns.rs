use std::process::Command;
use async_trait::async_trait;
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

        // 1. Create the network namespace
        run_cmd("ip", &["netns", "add", &self.namespace_name])?;

        // 2. Create the veth pair
        let veth_host = format!("veth-{}-h", &self.namespace_name[..std::cmp::min(self.namespace_name.len(), 4)]);
        let veth_guest = format!("veth-{}-g", &self.namespace_name[..std::cmp::min(self.namespace_name.len(), 4)]);

        run_cmd("ip", &["link", "add", &veth_host, "type", "veth", "peer", "name", &veth_guest])?;

        // 3. Move the guest end into the namespace
        run_cmd("ip", &["link", "set", &veth_guest, "netns", &self.namespace_name])?;

        // 4. Configure host IP and bring link up
        run_cmd("ip", &["addr", "add", "10.0.0.1/24", "dev", &veth_host])?;
        run_cmd("ip", &["link", "set", &veth_host, "up"])?;

        // 5. Configure guest IP and bring link up
        run_cmd("ip", &["netns", "exec", &self.namespace_name, "ip", "addr", "add", "10.0.0.2/24", "dev", &veth_guest])?;
        run_cmd("ip", &["netns", "exec", &self.namespace_name, "ip", "link", "set", &veth_guest, "up"])?;
        
        // 6. Set default route in namespace
        run_cmd("ip", &["netns", "exec", &self.namespace_name, "ip", "route", "add", "default", "via", "10.0.0.1"])?;

        // 7. Configure iptables to intercept Port 53 (DNS) and transparently DNAT it to our host proxy (10.0.0.1:53)
        run_cmd("ip", &["netns", "exec", &self.namespace_name, "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "10.0.0.1:53"])?;

        Ok(())
    }

    async fn teardown(&self) -> anyhow::Result<()> {
        if !cfg!(target_os = "linux") {
            return Ok(());
        }

        info!("Tearing down network namespace: {}", self.namespace_name);
        // Deleting the namespace automatically tears down the associated veth devices inside it
        let _ = run_cmd("ip", &["netns", "delete", &self.namespace_name]);
        Ok(())
    }

    async fn spawn_proxy(
        &self,
        target_ip: &str,
        target_port: u16,
    ) -> anyhow::Result<(ProxyListener, tokio::task::JoinHandle<()>)> {
        // Spawn the generic TCP proxy
        let tcp_isolator = super::tcp::TcpProxyIsolator;
        let (proxy, handle) = tcp_isolator.spawn_proxy(target_ip, target_port).await?;

        // In a real implementation, we would spawn a UDP listener on 10.0.0.1:53
        // using hickory-dns to intercept queries and return 10.0.0.1 for everything
        tokio::spawn(async move {
            if let Ok(socket) = tokio::net::UdpSocket::bind("10.0.0.1:53").await {
                tracing::info!("DNS Interceptor listening on 10.0.0.1:53");
                let mut buf = [0u8; 512];
                while let Ok((size, peer)) = socket.recv_from(&mut buf).await {
                    tracing::info!("Intercepted DNS query from {} size {}", peer, size);
                    if size >= 12 {
                        let mut response = Vec::with_capacity(size + 16);

                        // Transaction ID
                        response.push(buf[0]);
                        response.push(buf[1]);

                        // Flags: Standard query response, No error
                        response.push(0x81);
                        response.push(0x80);

                        // QDCOUNT (copy from request)
                        response.push(buf[4]);
                        response.push(buf[5]);

                        // ANCOUNT: 1
                        response.push(0x00);
                        response.push(0x01);

                        // NSCOUNT: 0, ARCOUNT: 0
                        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

                        // Copy the Question Section
                        response.extend_from_slice(&buf[12..size]);

                        // Append the Answer (A record pointing to 10.0.0.1)
                        // Name pointer to byte 12 (0xC00C)
                        response.extend_from_slice(&[0xC0, 0x0C]);
                        // Type A (1), Class IN (1)
                        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                        // TTL 60
                        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
                        // RDLENGTH 4
                        response.extend_from_slice(&[0x00, 0x04]);
                        // RDATA 10.0.0.1
                        response.extend_from_slice(&[10, 0, 0, 1]);

                        let _ = socket.send_to(&response, peer).await;
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
        anyhow::bail!("Command `{} {:?}` failed with status: {}", cmd, args, status);
    }
    Ok(())
}
