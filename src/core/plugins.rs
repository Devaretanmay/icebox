//! Optional Rust-layer plugins that harden an ICEBOX Session.
//!
//! The v2 product is Python-native: the SDK opens a Docker-backed Session and
//! runs the agent's workflow inside. These plugins are the *Rust-layer*
//! hardening that an optional plugin can mount — they are NOT on by default.
//!
//! - [`ResourceLimits`] bounds CPU / memory / process count of the Session
//!   container.
//! - [`NetworkPolicy`] reuses the egress-isolation proxy in
//!   [`crate::core::proxy`] so a Session's outbound traffic is intercepted.

use crate::core::proxy;

/// Limits applied to the Session's isolation container.
///
/// `None` fields mean "unchanged from the Docker default" — passing an empty
/// `ResourceLimits` is equivalent to no limits.
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    pub cpu_shares: Option<i64>,
    pub memory_bytes: Option<i64>,
    pub pids_limit: Option<i64>,
    pub nano_cpus: Option<i64>,
}

impl ResourceLimits {
    /// Render the limits as a `HostConfig` fragment for `ContainerCreateBody`.
    ///
    /// Returns `None` entirely when no limit is set, so callers that do not opt
    /// into limits see no behavioral change.
    pub fn host_config(&self) -> Option<bollard::service::HostConfig> {
        let any = self.cpu_shares.is_some()
            || self.memory_bytes.is_some()
            || self.pids_limit.is_some()
            || self.nano_cpus.is_some();
        if !any {
            return None;
        }
        Some(bollard::service::HostConfig {
            cpu_shares: self.cpu_shares,
            memory: self.memory_bytes,
            pids_limit: self.pids_limit,
            nano_cpus: self.nano_cpus,
            ..Default::default()
        })
    }
}

/// Egress-isolation policy for a Session.
///
/// Wraps the existing proxy so that, when mounted, a Session's outbound
/// traffic to a given target is routed through an intercepting proxy instead
/// of reaching the real host directly.
#[derive(Debug, Clone, Default)]
pub struct NetworkPolicy {
    bindings: Vec<(String, std::net::SocketAddr)>,
}

impl NetworkPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a target host to a local proxy address for egress interception.
    pub fn bind(&mut self, target: impl Into<String>, local: std::net::SocketAddr) {
        self.bindings.push((target.into(), local));
        proxy::bind_proxy(&self.bindings.last().unwrap().0, local);
    }

    /// Whether a target is currently proxied.
    pub fn is_proxied(&self, target: &str) -> bool {
        proxy::is_proxied(target)
    }

    /// Tear down all bindings this policy created.
    pub fn teardown(&self) {
        for (target, _) in &self.bindings {
            proxy::unbind_proxy(target);
        }
    }
}

/// A Rust-layer plugin mounted on a Session.
///
/// Mirrors the Python `SessionPlugin`. The daemon (the preserved v1 governance
/// kernel) is itself a plugin; `NetworkPolicy` and `ResourceLimits` are
/// optional isolators an agent may request.
pub trait SessionPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    /// Called when the Session container is provisioned.
    fn on_enter(&self) {}
    /// Called when the Session is torn down.
    fn on_exit(&self) {}
}

impl SessionPlugin for NetworkPolicy {
    fn name(&self) -> &'static str {
        "network-policy"
    }
    fn on_exit(&self) {
        self.teardown();
    }
}

impl SessionPlugin for ResourceLimits {
    fn name(&self) -> &'static str {
        "resource-limits"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_limits_render_to_none() {
        assert!(ResourceLimits::default().host_config().is_none());
    }

    #[test]
    fn limits_render_to_host_config() {
        let lim = ResourceLimits {
            memory_bytes: Some(256 * 1024 * 1024),
            pids_limit: Some(128),
            ..Default::default()
        };
        let _ = lim.cpu_shares;
        let cfg = lim.host_config().expect("should render");
        assert_eq!(cfg.memory, Some(256 * 1024 * 1024));
        assert_eq!(cfg.pids_limit, Some(128));
    }

    #[test]
    fn network_policy_bind_and_query() {
        let addr: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let mut np = NetworkPolicy::new();
        np.bind("example.invalid", addr);
        assert!(np.is_proxied("example.invalid"));
        np.teardown();
        assert!(!np.is_proxied("example.invalid"));
    }
}
