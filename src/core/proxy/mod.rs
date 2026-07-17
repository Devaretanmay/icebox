use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{LazyLock, RwLock};

use async_trait::async_trait;

pub mod netns;
pub mod tcp;

#[async_trait]
pub trait NetworkIsolator: Send + Sync {
    /// Sets up the isolated network environment (e.g., creating a netns or tap device).
    async fn setup(&self) -> anyhow::Result<()>;

    async fn spawn_proxy(
        &self,
        target_ip: &str,
        target_port: u16,
    ) -> anyhow::Result<(ProxyListener, tokio::task::JoinHandle<()>)>;

    /// Tears down the isolated network environment.
    async fn teardown(&self) -> anyhow::Result<()>;
}

pub struct ProxyListener {
    pub local_addr: SocketAddr,
    pub target_addr: SocketAddr,
}

/// Maps a real target host to the local proxy address it should be dialed through.
/// Populated when an operator binds a proxy for a target; empty by default, which
/// means modules dial targets directly (no egress routing).
static REGISTRY: LazyLock<RwLock<HashMap<String, SocketAddr>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub fn bind_proxy(target: &str, local: SocketAddr) {
    if let Ok(mut g) = REGISTRY.write() {
        g.insert(target.to_string(), local);
    }
}

pub fn unbind_proxy(target: &str) {
    if let Ok(mut g) = REGISTRY.write() {
        g.remove(target);
    }
}

pub fn is_proxied(target: &str) -> bool {
    REGISTRY
        .read()
        .map(|g| g.contains_key(target))
        .unwrap_or(false)
}

/// Resolve the address a module should connect to for `host:port`.
/// When a proxy is bound for `host`, returns the local proxy address; otherwise
/// returns the direct `host:port`. Modules must route their `TcpStream::connect`
/// calls through this so egress can be isolated on demand.
pub fn resolve_dial(host: &str, port: u16) -> String {
    if let Ok(g) = REGISTRY.read() {
        if let Some(addr) = g.get(host) {
            return addr.to_string();
        }
    }
    format!("{host}:{port}")
}
