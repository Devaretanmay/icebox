use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::modules::hex_encode;

pub struct ProxyListener {
    pub local_addr: SocketAddr,
    pub target_addr: SocketAddr,
}

impl ProxyListener {
    pub async fn spawn(target_ip: &str, target_port: u16) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        let target_str = format!("{}:{}", target_ip, target_port);
        let target_addr: SocketAddr = tokio::net::lookup_host(&target_str)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("could not resolve hostname: {}", target_ip))?;

        tokio::spawn(async move {
            if let Ok((mut client_stream, _client_addr)) = listener.accept().await {
                info!("Proxy accepted connection for {}", target_addr);
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    TcpStream::connect(target_addr),
                )
                .await
                {
                    Ok(Ok(mut target_stream)) => {
                        let (mut cr, mut cw) = client_stream.split();
                        let (mut tr, mut tw) = target_stream.split();

                        let client_to_target = async {
                            let mut buf = vec![0u8; 8192];
                            loop {
                                match cr.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        info!(
                                            "Proxy C->S {} bytes: {}",
                                            n,
                                            hex_encode(&buf[..n.min(32)])
                                        );
                                        if tw.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        };

                        let target_to_client = async {
                            let mut buf = vec![0u8; 8192];
                            loop {
                                match tr.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        info!(
                                            "Proxy S->C {} bytes: {}",
                                            n,
                                            hex_encode(&buf[..n.min(32)])
                                        );
                                        if cw.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        };

                        tokio::select! {
                            _ = client_to_target => {}
                            _ = target_to_client => {}
                        }
                    }
                    Ok(Err(e)) => warn!("Proxy failed to connect to target {}: {}", target_addr, e),
                    Err(_) => warn!("Proxy connect timeout to target {}", target_addr),
                }
            }
        });

        Ok(Self {
            local_addr,
            target_addr,
        })
    }
}
