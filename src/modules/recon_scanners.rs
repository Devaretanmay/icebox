use crate::core::module::{Module, ModuleError, ModuleResult};
use async_trait::async_trait;
use icebox_macro::module;
use sha1::{Digest, Sha1};
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::modules::hex_encode;

#[module(
    name = "mysql_scanner",
    kind = "Scanner",
    description = "MySQL service scanner  -  version detection and default credential check",
    author = "ICEBOX",
    sandbox_image = "mysql:5.7"
)]
pub struct MysqlScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "MySQL port (default 3306)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
    #[option(help = "Check default/built-in credentials")]
    pub check_defaults: bool,
    #[option(help = "Custom creds as user:pass,user:pass,... (overrides built-in when set)")]
    pub wordlist: String,
}

fn mysql_parse_greeting(data: &[u8]) -> Option<(String, Vec<u8>, u8, Vec<u8>)> {
    if data.len() < 5 {
        return None;
    }
    let payload =
        if data.len() > 4 && (data[0] as usize + 1 + data[1] as usize * 256 + 1) <= data.len() {
            &data[4..]
        } else {
            data
        };
    if payload.is_empty() {
        return None;
    }
    let proto_ver = payload[0];
    let mut pos = 1;
    let mut version_bytes = Vec::new();
    while pos < payload.len() && payload[pos] != 0 {
        version_bytes.push(payload[pos]);
        pos += 1;
    }
    pos += 1;
    if pos + 4 > payload.len() {
        return None;
    }
    let _conn_id = u32::from_le_bytes([
        payload[pos],
        payload[pos + 1],
        payload[pos + 2],
        payload[pos + 3],
    ]);
    pos += 4;
    if pos + 8 > payload.len() {
        return None;
    }
    let auth_plugin_part1 = payload[pos..pos + 8].to_vec();
    pos += 8;
    pos += 1;
    if pos + 2 > payload.len() {
        return None;
    }
    let _caps_lower = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
    pos += 2;
    pos += 1;
    pos += 2;
    let _caps_upper = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
    pos += 2;
    let auth_plugin_len = if pos < payload.len() { payload[pos] } else { 0 };
    pos += 1;
    pos += 10;
    let part2_len = if auth_plugin_len > 8 {
        auth_plugin_len as usize - 8
    } else {
        12
    };
    let auth_plugin_part2 = if pos + part2_len <= payload.len() {
        payload[pos..pos + part2_len].to_vec()
    } else {
        vec![]
    };
    let mut scramble = auth_plugin_part1.clone();
    scramble.extend_from_slice(&auth_plugin_part2);
    let version = String::from_utf8_lossy(&version_bytes).to_string();
    Some((version, scramble, proto_ver, auth_plugin_part1))
}

fn mysql_native_password(password: &str, scramble: &[u8]) -> Vec<u8> {
    let mut hasher1 = Sha1::new();
    hasher1.update(password.as_bytes());
    let stage1 = hasher1.finalize();

    let mut hasher2 = Sha1::new();
    hasher2.update(stage1);
    let stage2 = hasher2.finalize();

    let mut hasher3 = Sha1::new();
    hasher3.update(scramble);
    hasher3.update(stage2);
    let stage3 = hasher3.finalize();

    stage1
        .iter()
        .zip(stage3.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

fn mysql_build_handshake(username: &str, auth_response: &[u8]) -> Vec<u8> {
    let caps: u32 = 0x08820F;
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&caps.to_le_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    pkt.push(0x2D);
    pkt.extend_from_slice(&[0x00; 23]);

    pkt.extend_from_slice(username.as_bytes());
    pkt.push(0x00);

    if auth_response.is_empty() {
        pkt.push(0x00);
    } else {
        pkt.push(auth_response.len() as u8);
        pkt.extend_from_slice(auth_response);
    }

    pkt.push(0x00);

    pkt
}

fn mysql_prepend_header(payload: &[u8], seq: u8) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&len.to_le_bytes()[..3]);
    pkt.push(seq);
    pkt.extend_from_slice(payload);
    pkt
}

fn mysql_parse_response(data: &[u8]) -> Result<serde_json::Value, String> {
    if data.len() < 4 {
        return Err("response too short".into());
    }
    let payload = &data[4..];
    if payload.is_empty() {
        return Err("empty payload".into());
    }
    match payload[0] {
        0x00 => Ok(
            serde_json::json!({"status": "ok", "affected_rows": payload.get(1).copied().unwrap_or(0)}),
        ),
        0xFF => {
            let code = if payload.len() > 3 {
                u16::from_le_bytes([payload[1], payload[2]])
            } else {
                0
            };
            let msg = if payload.len() > 9 {
                String::from_utf8_lossy(&payload[9..]).to_string()
            } else if payload.len() > 3 {
                String::from_utf8_lossy(&payload[3..]).to_string()
            } else {
                "unknown error".into()
            };
            Ok(serde_json::json!({"status": "error", "code": code, "message": msg}))
        }
        0xFE => Ok(serde_json::json!({"status": "eof"})),
        _ => Ok(serde_json::json!({"status": "unknown", "first_byte": payload[0]})),
    }
}

#[async_trait]
impl Module for MysqlScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&MysqlScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_defaults: self.check_defaults,
            wordlist: self.wordlist.clone(),
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = MysqlScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_defaults: self.check_defaults,
            wordlist: self.wordlist.clone(),
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.timeout_ms = o.timeout_ms;
        self.check_defaults = o.check_defaults;
        self.wordlist = o.wordlist;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        MysqlScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_defaults: self.check_defaults,
            wordlist: self.wordlist.clone(),
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 3306 };
        let timeout = std::time::Duration::from_millis(if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        });
        let addr = format!("{}:{}", self.host, port);

        let mut stream =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(ModuleError::Other(format!("connection failed: {e}"))),
                Err(_) => return Err(ModuleError::Other("connection timed out".into())),
            };

        let mut buf = vec![0u8; 8192];
        let n = match tokio::time::timeout(timeout, stream.readable()).await {
            Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
            _ => 0,
        };
        if n < 5 {
            return Ok(ModuleResult {
                success: true,
                finding: Some(format!("MySQL on tcp/{port}: no greeting received")),
                data: serde_json::json!({"host": self.host, "port": port}),
                ..Default::default()
            });
        }

        let (version, _scramble, _proto_ver, _part1) = match mysql_parse_greeting(&buf[..n]) {
            Some(v) => v,
            None => {
                return Ok(ModuleResult {
                    success: true,
                    finding: Some(format!("MySQL on tcp/{port}: unrecognized response")),
                    data: serde_json::json!({"host": self.host, "port": port, "raw": hex_encode(&buf[..n.min(128)])}),
                    ..Default::default()
                })
            }
        };

        let mut findings = vec![format!("version: {version}")];
        let mut evidence = vec![format!("mysql/{version}")];

        let mut found_creds: Vec<(String, String)> = Vec::new();

        let creds_to_try: Vec<(&str, &str)> = if !self.wordlist.is_empty() {
            self.wordlist
                .split(',')
                .filter_map(|pair| {
                    let pair = pair.trim();
                    if let Some((u, p)) = pair.split_once(':') {
                        let u = u.trim();
                        let p = p.trim();
                        if !u.is_empty() {
                            Some((u, p))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect()
        } else if self.check_defaults {
            vec![
                ("root", ""),
                ("root", "root"),
                ("root", "admin"),
                ("admin", ""),
                ("mysql", ""),
                ("test", ""),
            ]
        } else {
            vec![]
        };

        for (user, pass) in &creds_to_try {
            let addr = addr.clone();
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => {
                    stream = s;
                }
                _ => continue,
            };
            let mut buf2 = vec![0u8; 8192];
            let n2 = match tokio::time::timeout(timeout, stream.readable()).await {
                Ok(Ok(_)) => stream.try_read(&mut buf2).unwrap_or(0),
                _ => 0,
            };
            if n2 < 5 {
                continue;
            }
            let (_v2, scramble2, _pv, _p1) = match mysql_parse_greeting(&buf2[..n2]) {
                Some(v) => v,
                None => continue,
            };
            let auth_resp = mysql_native_password(pass, &scramble2);
            let login = mysql_build_handshake(user, &auth_resp);
            let login_pkt = mysql_prepend_header(&login, 1);
            if tokio::time::timeout(timeout, stream.writable())
                .await
                .is_ok()
            {
                let _ = stream.try_write(&login_pkt);
            }
            let mut buf3 = vec![0u8; 1024];
            let n3 = match tokio::time::timeout(timeout, stream.readable()).await {
                Ok(Ok(_)) => stream.try_read(&mut buf3).unwrap_or(0),
                _ => 0,
            };
            if n3 > 4 {
                if let Ok(resp) = mysql_parse_response(&buf3[..n3]) {
                    if resp.get("status").and_then(|s| s.as_str()) == Some("ok") {
                        let label = if pass.is_empty() {
                            format!("{user}:\"\"")
                        } else {
                            format!("{user}:{pass}")
                        };
                        findings.push(format!("cred: {label}  -  SUCCESS"));
                        evidence.push(format!("mysql/cred:{label}"));
                        found_creds.push((user.to_string(), pass.to_string()));
                    }
                }
            }
        }

        let finding = if found_creds.is_empty() {
            format!(
                "MySQL on tcp/{port}: {version} (no valid credentials found, tried {} pair(s))",
                creds_to_try.len()
            )
        } else {
            let labels: Vec<String> = found_creds
                .iter()
                .map(|(u, p)| {
                    if p.is_empty() {
                        format!("{u}:\"\"")
                    } else {
                        format!("{u}:{p}")
                    }
                })
                .collect();
            format!(
                "MySQL on tcp/{port}: {version}  -  {} credential(s) work! {}",
                found_creds.len(),
                labels.join(", ")
            )
        };

        Ok(ModuleResult {
            success: true,
            finding: Some(finding),
            evidence,
            data: serde_json::json!({
                "host": self.host,
                "port": port,
                "version": version,
                "found_credentials": found_creds,
                "tried_count": creds_to_try.len(),
            }),
            ..Default::default()
        })
    }
}

const DEFAULT_WORDLIST: &[&str] = &[
    "admin",
    "login",
    "wp-admin",
    "wp-content",
    "backup",
    ".git",
    ".env",
    "config",
    "robots.txt",
    "sitemap.xml",
    "api",
    "test",
    "dev",
    "uploads",
    "images",
    "css",
    "js",
    "includes",
    "assets",
    "private",
    "restricted",
    "bak",
    "old",
    "src",
    "data",
    "console",
    "dashboard",
    "manager",
    "phpmyadmin",
    "adminer",
    "setup",
    "install",
    "readme",
    "changelog",
    "LICENSE",
    ".htaccess",
    ".htpasswd",
    "server-status",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "web.config",
    "phpinfo.php",
    "info.php",
    "status",
    "health",
    "healthcheck",
    "actuator",
    "swagger",
    "api-docs",
    "openapi.json",
    "graphql",
    "v2",
    "v1",
    "api/v1",
    "api/v2",
    "ws",
    "websocket",
    "sockjs",
    "sockjs-node",
    ".well-known",
];

#[module(
    name = "web_path_scanner",
    kind = "Scanner",
    description = "HTTP path/directory brute-forcer  -  discover hidden files and web resources",
    author = "ICEBOX"
)]
pub struct WebPathScanner {
    #[option(
        required = true,
        help = "Target base URL (e.g. http://10.0.0.1:80 or http://example.com)"
    )]
    pub target: String,
    #[option(help = "Path wordlist, comma-separated (default: built-in common paths)")]
    pub wordlist: String,
    #[option(help = "Timeout per request in milliseconds (default 3000)")]
    pub timeout_ms: u64,
    #[option(help = "Concurrent requests (default 20)")]
    pub concurrency: usize,
    #[option(help = "Interesting status codes, comma-separated (default: 200,301,302,401,403)")]
    pub filter_codes: String,
}

fn parse_url(target: &str) -> Result<(String, u16, bool), ModuleError> {
    let target = target.trim();
    let (rest, default_port, tls) = if let Some(r) = target.strip_prefix("https://") {
        (r, 443u16, true)
    } else if let Some(r) = target.strip_prefix("http://") {
        (r, 80u16, false)
    } else {
        (target, 80u16, false)
    };
    let rest = rest.trim_end_matches('/');
    if let Some((host, ps)) = rest.rsplit_once(':') {
        let p: u16 = ps
            .parse()
            .map_err(|_| ModuleError::Parse("bad port".into()))?;
        Ok((host.to_string(), p, tls))
    } else {
        Ok((rest.to_string(), default_port, tls))
    }
}

#[async_trait]
impl Module for WebPathScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&WebPathScannerOptions {
            target: self.target.clone(),
            wordlist: self.wordlist.clone(),
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
            filter_codes: self.filter_codes.clone(),
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = WebPathScannerOptions {
            target: self.target.clone(),
            wordlist: self.wordlist.clone(),
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
            filter_codes: self.filter_codes.clone(),
        };
        o.set(name, value)?;
        self.target = o.target;
        self.wordlist = o.wordlist;
        self.timeout_ms = o.timeout_ms;
        self.concurrency = o.concurrency;
        self.filter_codes = o.filter_codes;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        WebPathScannerOptions {
            target: self.target.clone(),
            wordlist: self.wordlist.clone(),
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
            filter_codes: self.filter_codes.clone(),
        }
        .validate()?;
        parse_url(&self.target).map(|_| ())
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let (host, port, _tls) = parse_url(&self.target)?;
        let timeout = std::time::Duration::from_millis(if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            3000
        });
        let max_concurrency = if self.concurrency > 0 {
            self.concurrency
        } else {
            20
        };

        let paths: Vec<String> = if self.wordlist.is_empty() {
            DEFAULT_WORDLIST.iter().map(|s| s.to_string()).collect()
        } else {
            self.wordlist
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };

        let filter_codes: Vec<u16> = if self.filter_codes.is_empty() {
            vec![200, 301, 302, 401, 403]
        } else {
            self.filter_codes
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect()
        };

        let semaphore = Arc::new(Semaphore::new(max_concurrency));
        let mut handles = Vec::new();

        for path in &paths {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let path = path.clone();
            let host = host.clone();
            let filter_codes = filter_codes.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let addr = format!("{}:{}", host, port);
                let stream = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                    Ok(Ok(s)) => s,
                    _ => return None,
                };
                let request = format!(
                    "GET /{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: ICEBOX/1.0\r\nAccept: */*\r\n\r\n",
                    path, host
                );
                if tokio::time::timeout(timeout, stream.writable()).await.is_err() {
                    return None;
                }
                let _ = stream.try_write(request.as_bytes());
                let mut buf = vec![0u8; 4096];
                let n = match tokio::time::timeout(timeout, stream.readable()).await {
                    Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
                    _ => 0,
                };
                if n == 0 { return None; }
                let resp = String::from_utf8_lossy(&buf[..n.min(4000)]);
                let first_line = resp.lines().next().unwrap_or("");
                let status_code = first_line.split(' ').nth(1)
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(0);
                if status_code > 0 && (filter_codes.is_empty() || filter_codes.contains(&status_code)) {
                    let size_hint = resp.find("\r\n\r\n")
                        .map(|i| resp.len() - i - 4)
                        .unwrap_or(0);
                    Some((path, status_code, first_line.to_string(), size_hint))
                } else {
                    None
                }
            }));
        }

        let mut discovered: Vec<serde_json::Value> = Vec::new();
        for h in handles {
            if let Ok(Some((path, code, line, size))) = h.await {
                discovered.push(serde_json::json!({
                    "path": format!("/{path}"),
                    "status": code,
                    "reason": line,
                    "size": size,
                }));
            }
        }

        discovered.sort_by(|a, b| {
            let pa = a["path"].as_str().unwrap_or("");
            let pb = b["path"].as_str().unwrap_or("");
            pa.cmp(pb)
        });

        let finding = if discovered.is_empty() {
            "No interesting web paths discovered".to_string()
        } else {
            let paths_str: Vec<String> = discovered
                .iter()
                .map(|d| {
                    let p = d["path"].as_str().unwrap_or("");
                    let s = d["status"].as_u64().unwrap_or(0);
                    format!("{p} [{s}]")
                })
                .collect();
            format!(
                "Discovered {} path(s): {}",
                discovered.len(),
                paths_str.join(", ")
            )
        };

        Ok(ModuleResult {
            success: true,
            finding: Some(finding),
            evidence: discovered
                .iter()
                .map(|d| {
                    let p = d["path"].as_str().unwrap_or("");
                    let s = d["status"].as_u64().unwrap_or(0);
                    format!("http{s}{p}")
                })
                .collect(),
            data: serde_json::json!({
                "target": self.target,
                "paths": discovered,
                "count": discovered.len(),
            }),
            ..Default::default()
        })
    }
}

fn dns_encode_domain(domain: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for label in domain.split('.') {
        if !label.is_empty() {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0x00);
    buf
}

fn dns_build_axfr_query(domain: &str, id: u16) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x00]);
    msg.extend_from_slice(&[0x00, 0x01]);
    msg.extend_from_slice(&[0x00, 0x00]);
    msg.extend_from_slice(&[0x00, 0x00]);
    msg.extend_from_slice(&[0x00, 0x00]);
    msg.extend_from_slice(&dns_encode_domain(domain));
    msg.extend_from_slice(&[0x00, 0xFC]);
    msg.extend_from_slice(&[0x00, 0x01]);

    let len = msg.len() as u16;
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&len.to_be_bytes());
    pkt.extend_from_slice(&msg);
    pkt
}

fn dns_decode_name(data: &[u8], pos: &mut usize) -> Result<String, ModuleError> {
    let mut labels = Vec::new();
    loop {
        if *pos >= data.len() {
            return Err(ModuleError::Other("DNS name: unexpected EOF".into()));
        }
        let byte = data[*pos];
        if byte == 0x00 {
            *pos += 1;
            break;
        }
        if byte & 0xC0 == 0xC0 {
            let offset = ((byte as usize & 0x3F) << 8) | data[*pos + 1] as usize;
            *pos += 2;
            let mut p = offset;
            if let Ok(name) = dns_decode_name(data, &mut p) {
                labels.push(name);
            }
            break;
        }
        let len = byte as usize;
        *pos += 1;
        if *pos + len > data.len() {
            return Err(ModuleError::Other("DNS name: label too long".into()));
        }
        labels.push(String::from_utf8_lossy(&data[*pos..*pos + len]).to_string());
        *pos += len;
    }
    Ok(labels.join("."))
}

fn dns_parse_response(data: &[u8]) -> Result<Vec<serde_json::Value>, ModuleError> {
    if data.len() < 14 {
        return Err(ModuleError::Other("response too short".into()));
    }
    let _id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qr = (flags >> 15) & 1;
    let rcode = flags & 0x0F;
    if qr == 0 {
        return Err(ModuleError::Other("not a response".into()));
    }
    if rcode != 0 {
        let rcode_names = [
            "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
        ];
        let name = rcode_names.get(rcode as usize).unwrap_or(&"UNKNOWN");
        return Err(ModuleError::Other(format!(
            "DNS error: {name} (rcode={rcode})"
        )));
    }

    let _qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let _nscount = u16::from_be_bytes([data[8], data[9]]);
    let _arcount = u16::from_be_bytes([data[10], data[11]]);

    let mut pos = 12;
    dns_decode_name(data, &mut pos)?;
    pos += 4;

    let mut records = Vec::new();
    for _ in 0..ancount {
        let name = match dns_decode_name(data, &mut pos) {
            Ok(n) => n,
            Err(_) => "?".to_string(),
        };
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > data.len() {
            break;
        }

        let rdata = match rtype {
            1 => {
                if rdlength >= 4 {
                    Some(serde_json::Value::String(format!(
                        "{}.{}.{}.{}",
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3]
                    )))
                } else {
                    None
                }
            }
            28 => {
                if rdlength >= 16 {
                    let ip = std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(&data[pos..pos + 16]).unwrap_or([0u8; 16]),
                    );
                    Some(serde_json::Value::String(ip.to_string()))
                } else {
                    None
                }
            }
            5 => {
                let mut p = pos;
                dns_decode_name(data, &mut p)
                    .ok()
                    .map(serde_json::Value::String)
            }
            2 => {
                let mut p = pos;
                dns_decode_name(data, &mut p)
                    .ok()
                    .map(serde_json::Value::String)
            }
            15 => {
                let pref = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let mut p = pos + 2;
                let target = dns_decode_name(data, &mut p).unwrap_or_default();
                Some(serde_json::json!({"preference": pref, "target": target}))
            }
            6 => {
                let mut p = pos;
                let mname = dns_decode_name(data, &mut p).unwrap_or_default();
                let rname = dns_decode_name(data, &mut p).unwrap_or_default();
                if p + 20 <= data.len() {
                    let serial =
                        u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
                    Some(serde_json::json!({"mname": mname, "rname": rname, "serial": serial}))
                } else {
                    None
                }
            }
            16 => {
                if rdlength > 0 {
                    let txt_len = data[pos] as usize;
                    let txt = String::from_utf8_lossy(
                        &data[pos + 1..pos + 1 + txt_len.min(rdlength - 1)],
                    )
                    .to_string();
                    Some(serde_json::Value::String(txt))
                } else {
                    None
                }
            }
            33 => {
                let mut p = pos;
                if p + 6 <= data.len() {
                    let priority = u16::from_be_bytes([data[p], data[p + 1]]);
                    let weight = u16::from_be_bytes([data[p + 2], data[p + 3]]);
                    let port = u16::from_be_bytes([data[p + 4], data[p + 5]]);
                    p += 6;
                    let target = dns_decode_name(data, &mut p).unwrap_or_default();
                    Some(
                        serde_json::json!({"priority": priority, "weight": weight, "port": port, "target": target}),
                    )
                } else {
                    None
                }
            }
            _ => None,
        };

        let type_names = [
            "", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "WKS", "PTR",
            "HINFO", "MINFO", "MX", "TXT",
        ];
        let type_name = if (rtype as usize) < type_names.len() {
            type_names[rtype as usize]
        } else {
            "TYPE?"
        };

        records.push(serde_json::json!({
            "name": name,
            "type": type_name,
            "type_code": rtype,
            "ttl": ttl,
            "value": rdata,
        }));
        pos += rdlength;
    }

    Ok(records)
}

#[module(
    name = "dns_zone_transfer",
    kind = "Auxiliary",
    description = "Attempt DNS zone transfer (AXFR) to enumerate all DNS records for a domain",
    author = "ICEBOX"
)]
pub struct DnsZoneTransfer {
    #[option(required = true, help = "Domain to query (e.g. example.com)")]
    pub domain: String,
    #[option(help = "DNS server to query (IP, default: use configured resolver)")]
    pub server: String,
    #[option(help = "Timeout in milliseconds (default 10000)")]
    pub timeout_ms: u64,
}

#[async_trait]
impl Module for DnsZoneTransfer {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&DnsZoneTransferOptions {
            domain: self.domain.clone(),
            server: self.server.clone(),
            timeout_ms: self.timeout_ms,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = DnsZoneTransferOptions {
            domain: self.domain.clone(),
            server: self.server.clone(),
            timeout_ms: self.timeout_ms,
        };
        o.set(name, value)?;
        self.domain = o.domain;
        self.server = o.server;
        self.timeout_ms = o.timeout_ms;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        DnsZoneTransferOptions {
            domain: self.domain.clone(),
            server: self.server.clone(),
            timeout_ms: self.timeout_ms,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let domain = self.domain.trim().to_lowercase();
        let timeout = std::time::Duration::from_millis(if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            10000
        });

        let nameservers: Vec<&str> = if self.server.is_empty() {
            vec!["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        } else {
            vec![self.server.as_str()]
        };

        let mut all_records = Vec::new();
        let mut errors = Vec::new();

        for ns in &nameservers {
            let addr = format!("{ns}:53");
            let stream =
                match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        errors.push(format!("{ns}: connect error: {e}"));
                        continue;
                    }
                    Err(_) => {
                        errors.push(format!("{ns}: connect timeout"));
                        continue;
                    }
                };

            let query = dns_build_axfr_query(&domain, 0x1337);
            if tokio::time::timeout(timeout, stream.writable())
                .await
                .is_err()
            {
                errors.push(format!("{ns}: write timeout"));
                continue;
            }
            let _ = stream.try_write(&query);

            let mut buf = vec![0u8; 65536];
            let n = match tokio::time::timeout(timeout, stream.readable()).await {
                Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
                _ => {
                    errors.push(format!("{ns}: read timeout"));
                    continue;
                }
            };

            if n < 4 {
                errors.push(format!("{ns}: response too short ({n} bytes)"));
                continue;
            }

            let dns_msg = &buf[2..n];
            match dns_parse_response(dns_msg) {
                Ok(records) => {
                    if !records.is_empty() {
                        all_records.extend(records);
                        break;
                    }
                    errors.push(format!("{ns}: no records returned"));
                }
                Err(e) => {
                    errors.push(format!("{ns}: parse error: {e}"));
                }
            }
        }

        let evidence: Vec<String> = all_records
            .iter()
            .map(|r| {
                let name = r["name"].as_str().unwrap_or("");
                let rtype = r["type"].as_str().unwrap_or("?");
                let value = r.get("value").and_then(|v| v.as_str()).unwrap_or("");
                format!("dns/{name} {rtype} {value}")
            })
            .collect();

        let ns_used_str = all_records
            .first()
            .and_then(|_| nameservers.first())
            .unwrap_or(&"none");

        let finding = if all_records.is_empty() {
            format!(
                "DNS zone transfer failed for {domain}: {}",
                errors.join("; ")
            )
        } else {
            let count = all_records.len();
            let soa_count = all_records.iter().filter(|r| r["type"] == "SOA").count();
            format!("Zone transfer SUCCESS for {domain} via {ns_used_str}: {count} records ({soa_count} SOA)")
        };

        Ok(ModuleResult {
            success: !all_records.is_empty(),
            finding: Some(finding),
            evidence,
            data: serde_json::json!({
                "domain": domain,
                "nameserver": ns_used_str,
                "records": all_records,
                "record_count": all_records.len(),
                "errors": errors,
            }),
            ..Default::default()
        })
    }
}

fn whois_server_for(query: &str) -> &'static str {
    let q = query.trim().to_lowercase();
    if q.contains('.') {
        if q.ends_with(".edu") {
            return "whois.educause.edu";
        }
        if q.ends_with(".gov") {
            return "whois.nic.gov";
        }
        if q.ends_with(".mil") {
            return "whois.nic.mil";
        }
        if q.ends_with(".org") || q.ends_with(".ngo") || q.ends_with(".ong") {
            return "whois.publicinterestregistry.net";
        }
        if q.ends_with(".info") {
            return "whois.afilias.net";
        }
        if q.ends_with(".biz") {
            return "whois.nic.biz";
        }
        if q.ends_with(".io") {
            return "whois.nic.io";
        }
        if q.ends_with(".co") {
            return "whois.nic.co";
        }
        if q.ends_with(".int") {
            return "whois.iana.org";
        }
        "whois.verisign-grs.com"
    } else {
        "whois.arin.net"
    }
}

#[module(
    name = "whois_lookup",
    kind = "Auxiliary",
    description = "Perform whois lookup on a domain or IP address",
    author = "ICEBOX"
)]
pub struct WhoisLookup {
    #[option(required = true, help = "Domain or IP address to query")]
    pub query: String,
    #[option(help = "Whois server (default: auto-detected)")]
    pub server: String,
    #[option(help = "Timeout in milliseconds (default 15000)")]
    pub timeout_ms: u64,
}

#[async_trait]
impl Module for WhoisLookup {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&WhoisLookupOptions {
            query: self.query.clone(),
            server: self.server.clone(),
            timeout_ms: self.timeout_ms,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = WhoisLookupOptions {
            query: self.query.clone(),
            server: self.server.clone(),
            timeout_ms: self.timeout_ms,
        };
        o.set(name, value)?;
        self.query = o.query;
        self.server = o.server;
        self.timeout_ms = o.timeout_ms;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        WhoisLookupOptions {
            query: self.query.clone(),
            server: self.server.clone(),
            timeout_ms: self.timeout_ms,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let query = self.query.trim().to_string();
        let timeout = std::time::Duration::from_millis(if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            15000
        });
        let server = if self.server.is_empty() {
            whois_server_for(&query)
        } else {
            self.server.as_str()
        };

        let addr = format!("{server}:43");
        let stream =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(ModuleError::Other(format!("connect to {server}: {e}"))),
                Err(_) => return Err(ModuleError::Other(format!("connect to {server}: timeout"))),
            };

        let request = format!("{query}\r\n");
        match tokio::time::timeout(timeout, stream.writable()).await {
            Ok(Ok(_)) => {
                stream
                    .try_write(request.as_bytes())
                    .map_err(|e| ModuleError::Other(format!("write: {e}")))?;
            }
            _ => return Err(ModuleError::Other("write timeout".into())),
        }

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

        let raw_text = String::from_utf8_lossy(&all_data).to_string();
        let summary_lines: Vec<&str> = raw_text
            .lines()
            .filter(|l| {
                let l = l.trim().to_lowercase();
                l.starts_with("domain")
                    || l.starts_with("registrar")
                    || l.starts_with("creation")
                    || l.starts_with("expir")
                    || l.starts_with("name server")
                    || l.starts_with("nserver")
                    || l.starts_with("org")
                    || l.starts_with("netrange")
                    || l.starts_with("cidr")
                    || l.starts_with("orgname")
            })
            .collect();
        let summary = summary_lines.join("\n");

        Ok(ModuleResult {
            success: !raw_text.is_empty(),
            finding: Some(format!(
                "Whois lookup for {query} via {server}: {} lines",
                raw_text.lines().count()
            )),
            evidence: if summary.is_empty() {
                vec![format!("whois/{query} -> {} bytes", all_data.len())]
            } else {
                summary_lines.iter().map(|l| format!("whois/{l}")).collect()
            },
            data: serde_json::json!({
                "query": query,
                "server": server,
                "raw_length": all_data.len(),
                "summary": summary,
                "raw": if raw_text.len() > 10000 { format!("{}...", &raw_text[..10000]) } else { raw_text },
            }),
            ..Default::default()
        })
    }
}

const DEFAULT_SUBDOMAINS: &[&str] = &[
    "www",
    "mail",
    "admin",
    "ftp",
    "ssh",
    "api",
    "dev",
    "test",
    "blog",
    "shop",
    "portal",
    "remote",
    "vpn",
    "webmail",
    "dns",
    "ns1",
    "ns2",
    "smtp",
    "pop3",
    "imap",
    "owa",
    "cpanel",
    "whm",
    "phpmyadmin",
    "jenkins",
    "gitlab",
    "jira",
    "wiki",
    "docs",
    "status",
    "support",
    "chat",
    "demo",
    "stage",
    "staging",
    "backup",
    "monitor",
    "logs",
    "db",
    "data",
    "sql",
    "mysql",
    "redis",
    "mongo",
    "cdn",
    "assets",
    "static",
    "download",
    "upload",
    "app",
    "apps",
    "server",
    "crm",
    "erp",
    "intranet",
    "biz",
    "info",
    "partner",
    "partners",
    "client",
    "clients",
    "user",
    "users",
    "account",
    "accounts",
    "login",
    "signin",
    "auth",
    "sso",
    "identity",
    "api-v1",
    "api-v2",
    "v1",
    "v2",
    "graphql",
    "rest",
    "service",
    "services",
    "mq",
    "kafka",
    "rabbitmq",
    "elasticsearch",
    "kibana",
    "grafana",
    "prometheus",
    "nagios",
    "zabbix",
    "mx",
    "mail2",
    "mail1",
    "ns",
    "ns3",
    "ns4",
    "direct",
    "direct-connect",
    "web",
    "webmail2",
    "forum",
    "help",
    "helpdesk",
    "knowledgebase",
    "kb",
    "tickets",
    "git",
    "svn",
    "cloud",
    "office",
    "outlook",
    "exchange",
    "lync",
    "skype",
];

#[module(
    name = "subdomain_enum",
    kind = "Scanner",
    description = "Enumerate subdomains via DNS resolution",
    author = "ICEBOX"
)]
pub struct SubdomainEnum {
    #[option(required = true, help = "Domain to enumerate (e.g. example.com)")]
    pub domain: String,
    #[option(help = "Subdomain wordlist, comma-separated (default: built-in common subdomains)")]
    pub wordlist: String,
    #[option(help = "Timeout per lookup in milliseconds (default 3000)")]
    pub timeout_ms: u64,
    #[option(help = "Concurrent lookups (default 50)")]
    pub concurrency: usize,
}

#[async_trait]
impl Module for SubdomainEnum {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&SubdomainEnumOptions {
            domain: self.domain.clone(),
            wordlist: self.wordlist.clone(),
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = SubdomainEnumOptions {
            domain: self.domain.clone(),
            wordlist: self.wordlist.clone(),
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
        };
        o.set(name, value)?;
        self.domain = o.domain;
        self.wordlist = o.wordlist;
        self.timeout_ms = o.timeout_ms;
        self.concurrency = o.concurrency;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        SubdomainEnumOptions {
            domain: self.domain.clone(),
            wordlist: self.wordlist.clone(),
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let domain = self.domain.trim().to_lowercase();
        let timeout = std::time::Duration::from_millis(if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            3000
        });
        let max_concurrency = if self.concurrency > 0 {
            self.concurrency
        } else {
            50
        };

        let subdomains: Vec<String> = if self.wordlist.is_empty() {
            DEFAULT_SUBDOMAINS.iter().map(|s| s.to_string()).collect()
        } else {
            self.wordlist
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };

        let semaphore = Arc::new(Semaphore::new(max_concurrency));
        let mut handles = Vec::new();

        for sub in &subdomains {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let sub = sub.clone();
            let domain = domain.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let fqdn = format!("{sub}.{domain}");
                let result =
                    tokio::time::timeout(timeout, tokio::net::lookup_host((fqdn.clone(), 0))).await;
                match result {
                    Ok(Ok(addrs)) => {
                        let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                        if !ips.is_empty() {
                            Some((sub, fqdn, ips))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }));
        }

        let mut resolved: Vec<serde_json::Value> = Vec::new();
        for h in handles {
            if let Ok(Some((sub, fqdn, ips))) = h.await {
                resolved.push(serde_json::json!({
                    "subdomain": sub,
                    "fqdn": fqdn,
                    "ips": ips,
                }));
            }
        }

        resolved.sort_by(|a, b| {
            a["subdomain"]
                .as_str()
                .unwrap_or("")
                .cmp(b["subdomain"].as_str().unwrap_or(""))
        });

        let evidence: Vec<String> = resolved
            .iter()
            .map(|r| {
                let f = r["fqdn"].as_str().unwrap_or("");
                let ips = r["ips"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                format!("dns/{f} -> {ips}")
            })
            .collect();

        let finding = if resolved.is_empty() {
            "No subdomains found".to_string()
        } else {
            let list: Vec<String> = resolved
                .iter()
                .map(|r| {
                    let s = r["subdomain"].as_str().unwrap_or("");
                    let ips = r["ips"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_default();
                    format!("{s} ({ips})")
                })
                .collect();
            format!("Found {} subdomain(s): {}", resolved.len(), list.join(", "))
        };

        Ok(ModuleResult {
            success: true,
            finding: Some(finding),
            evidence,
            data: serde_json::json!({
                "domain": domain,
                "subdomains": resolved,
                "count": resolved.len(),
                "tried": subdomains.len(),
            }),
            ..Default::default()
        })
    }
}

fn ber_tag(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut buf = vec![tag];
    let lbytes = if contents.len() < 128 {
        vec![contents.len() as u8]
    } else if contents.len() <= 0xFF {
        vec![0x81, contents.len() as u8]
    } else {
        let bytes = (contents.len() as u16).to_be_bytes();
        vec![0x82, bytes[0], bytes[1]]
    };
    buf.extend_from_slice(&lbytes);
    buf.extend_from_slice(contents);
    buf
}

fn ber_integer(value: i32) -> Vec<u8> {
    let bytes = if value == 0 {
        vec![0x00]
    } else if value > 0 {
        if value <= 0x7F {
            vec![value as u8]
        } else {
            value.to_be_bytes().to_vec()
        }
    } else {
        value.to_be_bytes().to_vec()
    };
    ber_tag(0x02, &bytes)
}

fn ber_octet_string(s: &[u8]) -> Vec<u8> {
    ber_tag(0x04, s)
}

fn ber_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn ber_sequence(contents: &[u8]) -> Vec<u8> {
    ber_tag(0x30, contents)
}

fn ber_oid(components: &[u32]) -> Vec<u8> {
    let mut encoded = Vec::new();
    if components.len() < 2 {
        return ber_tag(0x06, &[]);
    }
    encoded.push((40 * components[0] + components[1]) as u8);
    for &c in &components[2..] {
        if c < 128 {
            encoded.push(c as u8);
        } else {
            let mut bytes = Vec::new();
            let mut v = c;
            while v > 0 {
                bytes.push((v & 0x7F) as u8);
                v >>= 7;
            }
            bytes.reverse();
            for (i, &b) in bytes.iter().enumerate() {
                if i < bytes.len() - 1 {
                    encoded.push(b | 0x80);
                } else {
                    encoded.push(b);
                }
            }
        }
    }
    ber_tag(0x06, &encoded)
}

fn ber_context_specific(tag: u8, contents: &[u8]) -> Vec<u8> {
    ber_tag(0xA0 | tag, contents)
}

fn snmp_build_get_request(community: &str, oid: &[u32], request_id: i32) -> Vec<u8> {
    let mut varbind_inner = Vec::new();
    varbind_inner.extend_from_slice(&ber_oid(oid));
    varbind_inner.extend_from_slice(&ber_null());
    let varbind = ber_sequence(&varbind_inner);

    let mut varbind_list_inner = Vec::new();
    varbind_list_inner.extend_from_slice(&varbind);
    let varbind_list = ber_sequence(&varbind_list_inner);

    let mut pdu_inner = Vec::new();
    pdu_inner.extend_from_slice(&ber_integer(request_id));
    pdu_inner.extend_from_slice(&ber_integer(0));
    pdu_inner.extend_from_slice(&ber_integer(0));
    pdu_inner.extend_from_slice(&varbind_list);
    let pdu = ber_context_specific(0, &pdu_inner);

    let mut msg_inner = Vec::new();
    msg_inner.extend_from_slice(&ber_integer(1));
    msg_inner.extend_from_slice(&ber_octet_string(community.as_bytes()));
    msg_inner.extend_from_slice(&pdu);
    ber_sequence(&msg_inner)
}

fn asn1_skip_tlv(data: &[u8], pos: &mut usize) -> Result<(), ModuleError> {
    if *pos >= data.len() {
        return Err(ModuleError::Other("ASN.1: unexpected EOF at tag".into()));
    }
    let _tag = data[*pos];
    *pos += 1;
    if *pos >= data.len() {
        return Err(ModuleError::Other("ASN.1: unexpected EOF at length".into()));
    }
    let len_byte = data[*pos];
    *pos += 1;
    let length: usize = if len_byte < 0x80 {
        len_byte as usize
    } else if len_byte == 0x81 {
        if *pos >= data.len() {
            return Err(ModuleError::Other("ASN.1: EOF in long length".into()));
        }
        let l = data[*pos] as usize;
        *pos += 1;
        l
    } else if len_byte == 0x82 {
        if *pos + 2 > data.len() {
            return Err(ModuleError::Other("ASN.1: EOF in long length".into()));
        }
        let l = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        l
    } else {
        return Err(ModuleError::Other(
            "ASN.1: unsupported length encoding".into(),
        ));
    };
    *pos += length;
    Ok(())
}

fn asn1_get_value(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, ModuleError> {
    if *pos >= data.len() {
        return Err(ModuleError::Other("ASN.1: EOF at tag".into()));
    }
    *pos += 1;
    if *pos >= data.len() {
        return Err(ModuleError::Other("ASN.1: EOF at length".into()));
    }
    let len_byte = data[*pos];
    *pos += 1;
    let length: usize = if len_byte < 0x80 {
        len_byte as usize
    } else if len_byte == 0x81 {
        if *pos >= data.len() {
            return Err(ModuleError::Other("ASN.1: EOF".into()));
        }
        let l = data[*pos] as usize;
        *pos += 1;
        l
    } else if len_byte == 0x82 {
        if *pos + 2 > data.len() {
            return Err(ModuleError::Other("ASN.1: EOF".into()));
        }
        let l = (data[*pos] as usize) << 8 | data[*pos + 1] as usize;
        *pos += 2;
        l
    } else {
        return Err(ModuleError::Other("ASN.1: unsupported length".into()));
    };
    if *pos + length > data.len() {
        return Err(ModuleError::Other("ASN.1: value exceeds data".into()));
    }
    let val = data[*pos..*pos + length].to_vec();
    *pos += length;
    Ok(val)
}

fn snmp_parse_response(data: &[u8]) -> Result<String, ModuleError> {
    let mut pos = 0;
    if pos >= data.len() || data[pos] != 0x30 {
        return Err(ModuleError::Other("not an ASN.1 SEQUENCE".into()));
    }
    let _outer_val = asn1_get_value(data, &mut pos)?;

    let mut p = 0;
    asn1_skip_tlv(data, &mut p)?;
    asn1_skip_tlv(data, &mut p)?;
    asn1_skip_tlv(data, &mut p)?;
    if p >= data.len() || data[p] != 0xA2 {
        return Err(ModuleError::Other("expected GetResponse PDU".into()));
    }
    asn1_get_value(data, &mut p)?;
    let mut pp = 0;
    asn1_skip_tlv(data, &mut pp)?;
    asn1_skip_tlv(data, &mut pp)?;
    asn1_skip_tlv(data, &mut pp)?;
    if pp >= data.len() || (data[pp] != 0xA2 && data[pp] != 0xA0) {
        return Err(ModuleError::Other("expected SNMP PDU".into()));
    }
    let pdu_val = asn1_get_value(data, &mut pp)?;
    let mut pdu_pos = 0;
    asn1_skip_tlv(&pdu_val, &mut pdu_pos)?;
    asn1_skip_tlv(&pdu_val, &mut pdu_pos)?;
    asn1_skip_tlv(&pdu_val, &mut pdu_pos)?;
    if pdu_pos >= pdu_val.len() || pdu_val[pdu_pos] != 0x30 {
        return Err(ModuleError::Other("expected var-bind-list".into()));
    }
    let vb_list = asn1_get_value(&pdu_val, &mut pdu_pos)?;
    let mut vb_pos = 0;
    if vb_pos >= vb_list.len() || vb_list[vb_pos] != 0x30 {
        return Err(ModuleError::Other("expected var-bind".into()));
    }
    let vb_val = asn1_get_value(&vb_list, &mut vb_pos)?;
    let mut vv = 0;
    asn1_skip_tlv(&vb_val, &mut vv)?;
    if vv >= vb_val.len() {
        return Err(ModuleError::Other("no value in var-bind".into()));
    }
    let value = asn1_get_value(&vb_val, &mut vv)?;
    if value
        .iter()
        .all(|&b| (0x20..=0x7E).contains(&b) || b == b' ')
    {
        Ok(String::from_utf8_lossy(&value).to_string())
    } else if !value.is_empty() {
        Ok(format!("0x{}", hex_encode(&value)))
    } else {
        Ok("(null/empty)".into())
    }
}

fn asn1_parse_for_text(data: &[u8]) -> Option<String> {
    for window in data.windows(4) {
        if window == [0x04, 0x81] || window == [0x04, 0x82] {
            break;
        }
    }
    let text = String::from_utf8_lossy(data);
    let mut candidates: Vec<String> = text
        .split(|c: char| !c.is_ascii_graphic() && c != ' ')
        .filter(|s| s.len() > 5 && s.is_ascii())
        .map(|s| s.trim().to_string())
        .collect();
    candidates.dedup();
    candidates.retain(|s| !s.contains('\0') && s.len() < 256);
    candidates.first().cloned()
}

#[module(
    name = "snmp_scanner",
    kind = "Scanner",
    description = "SNMP service scanner  -  enumerate community strings and system information",
    author = "ICEBOX"
)]
pub struct SnmpScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "SNMP port (default 161)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 3000)")]
    pub timeout_ms: u64,
    #[option(help = "Community strings, comma-separated (default: public,private)")]
    pub communities: String,
}

#[async_trait]
impl Module for SnmpScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&SnmpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            communities: self.communities.clone(),
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = SnmpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            communities: self.communities.clone(),
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.timeout_ms = o.timeout_ms;
        self.communities = o.communities;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        SnmpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            communities: self.communities.clone(),
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 161 };
        let timeout = std::time::Duration::from_millis(if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            3000
        });
        let addr = format!("{}:{}", self.host, port);

        let communities: Vec<&str> = if self.communities.is_empty() {
            vec![
                "public",
                "private",
                "community",
                "snmp",
                "manager",
                "admin",
                "read",
                "write",
            ]
        } else {
            self.communities
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect()
        };

        let sysdescr_oid: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
        let mut found_communities: Vec<(String, String)> = Vec::new();

        for &community in &communities {
            let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let request = snmp_build_get_request(community, sysdescr_oid, 1);
            if tokio::time::timeout(timeout, sock.send_to(&request, &addr))
                .await
                .is_err()
            {
                continue;
            }
            let mut buf = vec![0u8; 65536];
            let n = match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => n,
                _ => continue,
            };
            if n < 10 {
                continue;
            }

            let response = &buf[..n];
            match snmp_parse_response(response) {
                Ok(description) => {
                    found_communities.push((community.to_string(), description));
                }
                Err(_) => {
                    if let Some(text) = asn1_parse_for_text(response) {
                        found_communities.push((community.to_string(), text));
                    }
                }
            }
        }

        let evidence: Vec<String> = found_communities
            .iter()
            .map(|(c, desc)| format!("snmp/community:{c} -> {desc}"))
            .collect();

        let finding = if found_communities.is_empty() {
            format!("SNMP on udp/{port}: no working community string found")
        } else {
            let summaries: Vec<String> = found_communities
                .iter()
                .map(|(c, desc)| format!("{c}={desc}"))
                .collect();
            format!(
                "SNMP on udp/{port}: {} working community string(s): {}",
                found_communities.len(),
                summaries.join("; ")
            )
        };

        Ok(ModuleResult {
            success: !found_communities.is_empty(),
            finding: Some(finding),
            evidence,
            data: serde_json::json!({
                "host": self.host,
                "port": port,
                "found_communities": found_communities,
                "tried": communities,
            }),
            ..Default::default()
        })
    }
}

fn bson_encode_is_master() -> Vec<u8> {
    let mut doc = Vec::new();
    doc.push(0x10);
    doc.extend_from_slice(b"isMaster\x00");
    doc.extend_from_slice(&1i32.to_le_bytes());
    doc.push(0x00);
    let mut pkt = Vec::with_capacity(4 + doc.len());
    let len = (4 + doc.len()) as i32;
    pkt.extend_from_slice(&len.to_le_bytes());
    pkt.extend_from_slice(&doc);
    pkt
}

fn build_mongo_query(db_cmd: &str, query: &[u8]) -> Vec<u8> {
    let msg_len = 16 + 4 + db_cmd.len() as u32 + 1 + 4 + 4 + query.len() as u32;
    let mut pkt = Vec::with_capacity(msg_len as usize);
    pkt.extend_from_slice(&msg_len.to_le_bytes());
    pkt.extend_from_slice(&1i32.to_le_bytes());
    pkt.extend_from_slice(&0i32.to_le_bytes());
    pkt.extend_from_slice(&2004i32.to_le_bytes());
    pkt.extend_from_slice(&0i32.to_le_bytes());
    pkt.extend_from_slice(db_cmd.as_bytes());
    pkt.push(0x00);
    pkt.extend_from_slice(&0i32.to_le_bytes());
    pkt.extend_from_slice(&(-1i32).to_le_bytes());
    pkt.extend_from_slice(query);
    pkt
}

fn bson_find_string(doc: &[u8], field: &str) -> Option<String> {
    if doc.len() < 5 {
        return None;
    }
    let _total_len = i32::from_le_bytes([doc[0], doc[1], doc[2], doc[3]]) as usize;
    let mut pos = 4;
    while pos + 2 < doc.len() {
        let etype = doc[pos];
        pos += 1;
        let name_end = doc[pos..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&doc[pos..pos + name_end]).ok()?;
        pos += name_end + 1;
        if name == field {
            return match etype {
                0x02 => {
                    if pos + 4 > doc.len() {
                        return None;
                    }
                    let slen =
                        i32::from_le_bytes([doc[pos], doc[pos + 1], doc[pos + 2], doc[pos + 3]])
                            as usize;
                    if pos + 4 + slen <= doc.len() {
                        Some(String::from_utf8_lossy(&doc[pos + 4..pos + 4 + slen - 1]).to_string())
                    } else {
                        None
                    }
                }
                0x08 => {
                    if pos < doc.len() {
                        Some(if doc[pos] != 0 {
                            "true".into()
                        } else {
                            "false".into()
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            };
        }
        pos = match etype {
            0x01 => {
                if pos + 8 <= doc.len() {
                    pos + 8
                } else {
                    return None;
                }
            }
            0x02 => {
                if pos + 4 > doc.len() {
                    return None;
                }
                let slen = i32::from_le_bytes([doc[pos], doc[pos + 1], doc[pos + 2], doc[pos + 3]])
                    as usize;
                if pos + 4 + slen <= doc.len() {
                    pos + 4 + slen
                } else {
                    return None;
                }
            }
            0x03 | 0x04 => {
                if pos + 4 > doc.len() {
                    return None;
                }
                let dlen = i32::from_le_bytes([doc[pos], doc[pos + 1], doc[pos + 2], doc[pos + 3]])
                    as usize;
                if pos + dlen <= doc.len() {
                    pos + dlen
                } else {
                    return None;
                }
            }
            0x08 => pos + 1,
            0x09 | 0x12 => {
                if pos + 8 <= doc.len() {
                    pos + 8
                } else {
                    return None;
                }
            }
            0x10 if pos + 4 <= doc.len() => pos + 4,
            _ => {
                return None;
            }
        };
    }
    None
}

fn bson_find_int32(doc: &[u8], field: &str) -> Option<i32> {
    if doc.len() < 5 {
        return None;
    }
    let mut pos = 4;
    while pos + 2 < doc.len() {
        let etype = doc[pos];
        pos += 1;
        let name_end = doc[pos..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&doc[pos..pos + name_end]).ok()?;
        pos += name_end + 1;
        if name == field && etype == 0x10 && pos + 4 <= doc.len() {
            return Some(i32::from_le_bytes([
                doc[pos],
                doc[pos + 1],
                doc[pos + 2],
                doc[pos + 3],
            ]));
        }
        pos = match etype {
            0x01 => pos + 8,
            0x02 => {
                if pos + 4 > doc.len() {
                    return None;
                }
                pos + 4
                    + i32::from_le_bytes([doc[pos], doc[pos + 1], doc[pos + 2], doc[pos + 3]])
                        as usize
            }
            0x03 | 0x04 => {
                if pos + 4 > doc.len() {
                    return None;
                }
                pos + i32::from_le_bytes([doc[pos], doc[pos + 1], doc[pos + 2], doc[pos + 3]])
                    as usize
            }
            0x08 => pos + 1,
            0x09 | 0x12 => pos + 8,
            0x10 => pos + 4,
            _ => {
                return None;
            }
        };
    }
    None
}

fn mongo_body(response: &[u8]) -> Option<&[u8]> {
    if response.len() < 16 {
        return None;
    }
    let _msg_len = i32::from_le_bytes([response[0], response[1], response[2], response[3]]);
    let _req_id = i32::from_le_bytes([response[4], response[5], response[6], response[7]]);
    let _resp_to = i32::from_le_bytes([response[8], response[9], response[10], response[11]]);
    let op_code = i32::from_le_bytes([response[12], response[13], response[14], response[15]]);
    if op_code != 1 {
        return None;
    }
    if response.len() < 36 {
        return None;
    }
    let _flags = i32::from_le_bytes([response[16], response[17], response[18], response[19]]);
    let _cursor = i64::from_le_bytes([
        response[20],
        response[21],
        response[22],
        response[23],
        response[24],
        response[25],
        response[26],
        response[27],
    ]);
    let _start = i32::from_le_bytes([response[28], response[29], response[30], response[31]]);
    let _num = i32::from_le_bytes([response[32], response[33], response[34], response[35]]);
    if response.len() > 36 {
        Some(&response[36..])
    } else {
        None
    }
}

#[module(
    name = "mongo_scanner",
    kind = "Scanner",
    description = "MongoDB service scanner  -  version detection and no-auth access check",
    author = "ICEBOX"
)]
pub struct MongoScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "MongoDB port (default 27017)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
}

#[async_trait]
impl Module for MongoScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&MongoScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = MongoScannerOptions {
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
        MongoScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 27017 };
        let timeout_ms = if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        };
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let addr = format!("{}:{}", self.host, port);

        let stream =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(ModuleError::Other(format!("connection failed: {e}"))),
                Err(_) => return Err(ModuleError::Other("connection timed out".into())),
            };

        let query = bson_encode_is_master();
        let pkt = build_mongo_query("admin.$cmd", &query);
        if tokio::time::timeout(timeout, stream.writable())
            .await
            .is_err()
        {
            return Err(ModuleError::Other("write timeout".into()));
        }
        let _ = stream.try_write(&pkt);

        let mut buf = vec![0u8; 65536];
        let n = match tokio::time::timeout(timeout, stream.readable()).await {
            Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
            _ => 0,
        };

        if n < 36 {
            return Ok(ModuleResult {
                success: true,
                finding: Some(format!("MongoDB on tcp/{port}: no valid response")),
                data: serde_json::json!({"host": self.host, "port": port}),
                ..Default::default()
            });
        }

        let body = match mongo_body(&buf[..n]) {
            Some(b) => b,
            None => {
                return Ok(ModuleResult {
                    success: true,
                    finding: Some(format!("MongoDB on tcp/{port}: unparseable response")),
                    data: serde_json::json!({"host": self.host, "port": port, "hex": hex_encode(&buf[..n.min(128)])}),
                    ..Default::default()
                })
            }
        };

        let is_master = bson_find_string(body, "ismaster").unwrap_or_default();
        let version = bson_find_string(body, "version").unwrap_or_default();
        let ok = bson_find_int32(body, "ok").unwrap_or(0);
        let max_bson = bson_find_int32(body, "maxBsonObjectSize").unwrap_or(0);
        let wire_ver = bson_find_int32(body, "minWireVersion")
            .map(|v| format!("{v}"))
            .or_else(|| bson_find_int32(body, "maxWireVersion").map(|v| format!("{v}")))
            .unwrap_or_default();

        let mut findings = vec![];
        let mut evidence = vec![];

        if ok == 1 {
            findings.push("MongoDB accessible (no auth triggered)".into());
            evidence.push("mongo/no_auth".into());
        }
        if !version.is_empty() {
            findings.push(format!("version: {version}"));
            evidence.push(format!("mongo/version:{version}"));
        }
        if !is_master.is_empty() {
            findings.push(format!("ismaster: {is_master}"));
        }
        if max_bson > 0 {
            evidence.push(format!("mongo/maxBsonSize:{max_bson}"));
        }

        Ok(ModuleResult {
            success: true,
            finding: Some(format!("MongoDB on tcp/{port}: {}", findings.join("; "))),
            evidence,
            data: serde_json::json!({
                "host": self.host, "port": port,
                "version": version, "is_master": is_master,
                "ok": ok, "max_bson_size": max_bson,
                "wire_version": wire_ver,
            }),
            ..Default::default()
        })
    }
}

#[module(
    name = "es_scanner",
    kind = "Scanner",
    description = "Elasticsearch service scanner  -  cluster info, version, and open access detection",
    author = "ICEBOX"
)]
pub struct EsScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "Elasticsearch port (default 9200)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
    #[option(help = "Check cluster health in addition to root endpoint (default true)")]
    pub check_health: bool,
}

async fn http_get_line(stream: &tokio::net::TcpStream, timeout: std::time::Duration) -> Vec<u8> {
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
    all_data
}

fn http_extract_body(raw: &[u8]) -> Option<&[u8]> {
    let text = String::from_utf8_lossy(raw);
    if let Some(pos) = text.find("\r\n\r\n") {
        let body_start = pos + 4;
        Some(&raw[body_start..])
    } else if let Some(pos) = text.find("\n\n") {
        let body_start = pos + 2;
        Some(&raw[body_start..])
    } else {
        None
    }
}

async fn es_http_request(
    host: &str,
    port: u16,
    path: &str,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, ModuleError> {
    let addr = format!("{host}:{port}");
    let stream = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(ModuleError::Other(format!("connect: {e}"))),
        Err(_) => return Err(ModuleError::Other("connect timeout".into())),
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: ICEBOX/1.0\r\nAccept: application/json\r\n\r\n"
    );
    if tokio::time::timeout(timeout, stream.writable())
        .await
        .is_err()
    {
        return Err(ModuleError::Other("write timeout".into()));
    }
    let _ = stream.try_write(request.as_bytes());
    Ok(http_get_line(&stream, timeout).await)
}

fn es_extract_json_string(body: &[u8], field: &str) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let search = format!("\"{field}\":\"");
    if let Some(start) = text.find(&search) {
        let val_start = start + search.len();
        if let Some(end) = text[val_start..].find('\"') {
            return Some(text[val_start..val_start + end].to_string());
        }
    }
    None
}

#[async_trait]
impl Module for EsScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&EsScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_health: self.check_health,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = EsScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_health: self.check_health,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.timeout_ms = o.timeout_ms;
        self.check_health = o.check_health;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        EsScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_health: self.check_health,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 9200 };
        let timeout_ms = if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        };
        let timeout = std::time::Duration::from_millis(timeout_ms);

        let raw = es_http_request(&self.host, port, "/", timeout).await?;
        let body = http_extract_body(&raw).unwrap_or(&raw);
        let text = String::from_utf8_lossy(body);

        let mut findings = Vec::new();
        let mut evidence = Vec::new();

        let cluster_name = es_extract_json_string(body, "cluster_name");
        if let Some(ref cn) = cluster_name {
            findings.push(format!("cluster: {cn}"));
            evidence.push(format!("es/cluster:{cn}"));
        }

        let version = es_extract_json_string(body, "number");
        if let Some(ref v) = version {
            findings.push(format!("version: {v}"));
            evidence.push(format!("es/version:{v}"));
        }

        let tagline = es_extract_json_string(body, "tagline");
        if let Some(ref t) = tagline {
            evidence.push(format!("es/tagline:{t}"));
        }

        let mut health_status = String::new();
        if self.check_health {
            if let Ok(health_raw) =
                es_http_request(&self.host, port, "/_cluster/health", timeout).await
            {
                if let Some(health_body) = http_extract_body(&health_raw) {
                    if let Some(status) = es_extract_json_string(health_body, "status") {
                        health_status = status.clone();
                        findings.push(format!("health: {status}"));
                        evidence.push(format!("es/health:{status}"));
                    }
                }
            }
        }

        let finding = if findings.is_empty() {
            format!("ES on tcp/{port}: service detected (unrecognized response)")
        } else {
            format!("ES on tcp/{port}: {}", findings.join("; "))
        };

        Ok(ModuleResult {
            success: true,
            finding: Some(finding),
            evidence,
            data: serde_json::json!({
                "host": self.host, "port": port,
                "cluster_name": cluster_name,
                "version": version,
                "health_status": health_status,
                "raw": text.chars().take(2000).collect::<String>(),
            }),
            ..Default::default()
        })
    }
}

fn pg_startup_message(user: &str) -> Vec<u8> {
    let user_param = format!("\x00user\x00{user}\x00");
    let body = format!("\x00\x03\x00\x00{user_param}\x00");
    let len = (4 + body.len()) as u32;
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&len.to_le_bytes());
    pkt.extend_from_slice(body.as_bytes());
    pkt
}

fn pg_md5_auth(user: &str, password: &str, salt: &[u8]) -> String {
    let inner = md5::compute(format!("{password}{user}").as_bytes());
    let mut combined = format!("{inner:x}").into_bytes();
    combined.extend_from_slice(salt);
    let outer = md5::compute(&combined);
    format!("md5{outer:x}")
}

const PG_DEFAULT_CREDS: &[(&str, &str)] = &[
    ("postgres", "postgres"),
    ("postgres", "admin"),
    ("postgres", "password"),
    ("postgres", ""),
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "admin"),
    ("root", "password"),
];

#[module(
    name = "postgres_scanner",
    kind = "Scanner",
    description = "PostgreSQL service scanner  -  version detection and default credential check",
    author = "ICEBOX"
)]
pub struct PostgresScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "PostgreSQL port (default 5432)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
    #[option(help = "Check default credentials (default true)")]
    pub check_defaults: bool,
}

fn pg_auth_type_name(t: i32) -> &'static str {
    match t {
        0 => "OK",
        2 => "KerberosV5",
        3 => "CleartextPassword",
        5 => "MD5Password",
        6 => "SCMCredential",
        7 => "GSS",
        9 => "SSPI",
        10 => "SASL",
        11 => "SASLContinue",
        12 => "SASLFinal",
        _ => "Unknown",
    }
}

#[async_trait]
impl Module for PostgresScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&PostgresScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_defaults: self.check_defaults,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = PostgresScannerOptions {
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
        PostgresScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_defaults: self.check_defaults,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 5432 };
        let timeout_ms = if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        };
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let addr = format!("{}:{}", self.host, port);

        async fn pg_read_response(
            stream: &tokio::net::TcpStream,
            timeout: std::time::Duration,
        ) -> Result<Vec<u8>, ModuleError> {
            let mut buf = vec![0u8; 8192];
            let n = match tokio::time::timeout(timeout, stream.readable()).await {
                Ok(Ok(_)) => stream.try_read(&mut buf).unwrap_or(0),
                _ => return Err(ModuleError::Other("read timeout".into())),
            };
            Ok(buf[..n].to_vec())
        }

        let creds_to_try: Vec<(&str, &str)> = if self.check_defaults {
            PG_DEFAULT_CREDS.to_vec()
        } else {
            Vec::new()
        };

        let mut found_creds: Vec<(String, String)> = Vec::new();
        let mut auth_type = String::new();
        let mut server_version = String::new();

        for (user, pass) in &creds_to_try {
            let stream =
                match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                    Ok(Ok(s)) => s,
                    _ => continue,
                };
            let startup = pg_startup_message(user);
            if tokio::time::timeout(timeout, stream.writable())
                .await
                .is_err()
            {
                continue;
            }
            let _ = stream.try_write(&startup);

            let response = match pg_read_response(&stream, timeout).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if response.is_empty() || response[0] == b'E' {
                continue;
            }

            if response[0] == b'R' {
                if response.len() < 9 {
                    continue;
                }
                let auth_t =
                    i32::from_be_bytes([response[5], response[6], response[7], response[8]]);
                let auth_name = pg_auth_type_name(auth_t);
                if server_version.is_empty() {
                    auth_type = auth_name.to_string();
                }

                if auth_t == 0 {
                    found_creds.push((user.to_string(), pass.to_string()));
                    tokio::time::timeout(timeout, stream.readable()).await.ok();
                    let mut buf2 = vec![0u8; 4096];
                    if let Ok(Ok(_)) = tokio::time::timeout(timeout, stream.readable()).await {
                        let n = stream.try_read(&mut buf2).unwrap_or(0);
                        if n > 0 {
                            let text = String::from_utf8_lossy(&buf2[..n.min(4000)]);
                            for line in text.split('\x00') {
                                if line.starts_with("server_version") {
                                    server_version = line
                                        .trim_start_matches("server_version")
                                        .trim_start_matches('\x00')
                                        .to_string();
                                }
                            }
                        }
                    }
                } else if auth_t == 3 && creds_to_try.len() == 1 {
                    let pass_pkt = format!("p{}\x00", pass);
                    let len = (4 + pass_pkt.len()) as u32;
                    let mut auth_msg = Vec::new();
                    auth_msg.extend_from_slice(&len.to_le_bytes());
                    auth_msg.extend_from_slice(pass_pkt.as_bytes());
                    if tokio::time::timeout(timeout, stream.writable())
                        .await
                        .is_ok()
                    {
                        let _ = stream.try_write(&auth_msg);
                    }
                    let resp2 = pg_read_response(&stream, timeout).await.unwrap_or_default();
                    if resp2.len() > 5 && resp2[0] == b'R' {
                        let auth_t2 = i32::from_be_bytes([resp2[5], resp2[6], resp2[7], resp2[8]]);
                        if auth_t2 == 0 {
                            found_creds.push((user.to_string(), pass.to_string()));
                        }
                    }
                } else if auth_t == 5 && creds_to_try.len() == 1 {
                    let salt = &response[9..13];
                    let md5_hash = pg_md5_auth(user, pass, salt);
                    let pass_bytes = md5_hash.as_bytes();
                    let len = (4 + pass_bytes.len() + 1) as u32;
                    let mut auth_msg = Vec::new();
                    auth_msg.extend_from_slice(&len.to_le_bytes());
                    auth_msg.extend_from_slice(pass_bytes);
                    auth_msg.push(0x00);
                    if tokio::time::timeout(timeout, stream.writable())
                        .await
                        .is_ok()
                    {
                        let _ = stream.try_write(&auth_msg);
                    }
                    let resp2 = pg_read_response(&stream, timeout).await.unwrap_or_default();
                    if resp2.len() > 5 && resp2[0] == b'R' {
                        let auth_t2 = i32::from_be_bytes([resp2[5], resp2[6], resp2[7], resp2[8]]);
                        if auth_t2 == 0 {
                            found_creds.push((user.to_string(), pass.to_string()));
                        }
                    }
                }
            } else if response[0] == b'N' || response[0] == b'S' {
            }
        }

        let evidence: Vec<String> = found_creds
            .iter()
            .map(|(u, p)| format!("postgres/cred:{u}:{p}"))
            .collect();

        let finding = if !found_creds.is_empty() {
            let labels: Vec<String> = found_creds
                .iter()
                .map(|(u, p)| format!("{u}:{p}"))
                .collect();
            format!(
                "PostgreSQL on tcp/{port}: FOUND {} credential(s): {}",
                found_creds.len(),
                labels.join(", ")
            )
        } else {
            format!("PostgreSQL on tcp/{port}: detected (auth={auth_type}, version={server_version}), no valid creds found", )
        };

        Ok(ModuleResult {
            success: !found_creds.is_empty(),
            finding: Some(finding),
            evidence,
            data: serde_json::json!({
                "host": self.host, "port": port,
                "version": server_version,
                "auth_type": auth_type,
                "found_credentials": found_creds,
                "tried_count": creds_to_try.len(),
            }),
            ..Default::default()
        })
    }
}

#[module(
    name = "smtp_scanner",
    kind = "Scanner",
    description = "SMTP service scanner  -  banner grabbing, open relay check, and user enumeration",
    author = "ICEBOX"
)]
pub struct SmtpScanner {
    #[option(required = true, help = "Target IP or hostname")]
    pub host: String,
    #[option(help = "SMTP port (default 25)")]
    pub port: u16,
    #[option(help = "Timeout in milliseconds (default 5000)")]
    pub timeout_ms: u64,
    #[option(help = "Check open relay (default true)")]
    pub check_relay: bool,
    #[option(help = "Check VRFY user enumeration (default true)")]
    pub check_vrfy: bool,
}

async fn smtp_read(stream: &tokio::net::TcpStream, timeout: std::time::Duration) -> String {
    let mut all = Vec::new();
    let mut buf = vec![0u8; 4096];
    for _ in 0..3 {
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
        all.extend_from_slice(&buf[..n]);
        if all.len() > 8192 {
            break;
        }
    }
    String::from_utf8_lossy(&all).to_string()
}

async fn smtp_write(
    stream: &tokio::net::TcpStream,
    cmd: &str,
    timeout: std::time::Duration,
) -> Result<(), ModuleError> {
    match tokio::time::timeout(timeout, stream.writable()).await {
        Ok(Ok(_)) => stream
            .try_write(cmd.as_bytes())
            .map_err(|e| ModuleError::Other(format!("write: {e}")))
            .map(|_| ()),
        _ => Err(ModuleError::Other("write timeout".into())),
    }
}

#[async_trait]
impl Module for SmtpScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&SmtpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_relay: self.check_relay,
            check_vrfy: self.check_vrfy,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = SmtpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_relay: self.check_relay,
            check_vrfy: self.check_vrfy,
        };
        o.set(name, value)?;
        self.host = o.host;
        self.port = o.port;
        self.timeout_ms = o.timeout_ms;
        self.check_relay = o.check_relay;
        self.check_vrfy = o.check_vrfy;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        SmtpScannerOptions {
            host: self.host.clone(),
            port: self.port,
            timeout_ms: self.timeout_ms,
            check_relay: self.check_relay,
            check_vrfy: self.check_vrfy,
        }
        .validate()
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let port = if self.port > 0 { self.port } else { 25 };
        let timeout_ms = if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            5000
        };
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let addr = format!("{}:{}", self.host, port);

        let stream =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(ModuleError::Other(format!("connection failed: {e}"))),
                Err(_) => return Err(ModuleError::Other("connection timed out".into())),
            };

        let banner = smtp_read(&stream, timeout).await;
        let banner_line = banner.lines().next().unwrap_or("").trim().to_string();

        let mut findings = Vec::new();
        let mut evidence = Vec::new();
        findings.push(format!("banner: {banner_line}"));
        evidence.push(format!("smtp/banner:{banner_line}"));

        smtp_write(&stream, "EHLO icebox\r\n", timeout).await.ok();
        let ehlo_resp = smtp_read(&stream, timeout).await;
        let ehlo_lines: Vec<&str> = ehlo_resp.lines().collect();
        let ehlo_ok = ehlo_lines
            .first()
            .map(|l| l.starts_with("250"))
            .unwrap_or(false);

        if ehlo_ok {
            let caps: Vec<String> = ehlo_lines
                .iter()
                .filter_map(|l| {
                    let l = l.strip_prefix("250-").or_else(|| l.strip_prefix("250 "))?;
                    Some(l.trim().to_string())
                })
                .collect();
            if !caps.is_empty() {
                findings.push(format!("capabilities: {}", caps.join(", ")));
            }

            if caps.iter().any(|c| c.to_uppercase().contains("AUTH")) {
                evidence.push("smtp/auth_available".into());
            }

            if self.check_relay {
                smtp_write(&stream, "MAIL FROM:<test@icebox.local>\r\n", timeout)
                    .await
                    .ok();
                let mfrom = smtp_read(&stream, timeout).await;
                if mfrom.starts_with("250") {
                    smtp_write(&stream, "RCPT TO:<test@example.com>\r\n", timeout)
                        .await
                        .ok();
                    let rcpt = smtp_read(&stream, timeout).await;
                    if rcpt.starts_with("250") {
                        findings.push("open relay: YES (RCPT TO succeeded)".into());
                        evidence.push("smtp/open_relay".into());
                    } else {
                        findings.push("open relay: NO (relay denied)".into());
                    }
                }
            }

            if self.check_vrfy {
                smtp_write(&stream, "VRFY root\r\n", timeout).await.ok();
                let vrfy = smtp_read(&stream, timeout).await;
                if vrfy.starts_with("250") || vrfy.starts_with("252") {
                    findings.push("user enumeration via VRFY: possible".into());
                    evidence.push("smtp/vrfy_enabled".into());
                }

                smtp_write(&stream, "EXPN postmaster\r\n", timeout)
                    .await
                    .ok();
                let expn = smtp_read(&stream, timeout).await;
                if expn.starts_with("250") {
                    findings.push("user enumeration via EXPN: possible".into());
                    evidence.push("smtp/expn_enabled".into());
                }
            }
        } else {
            findings.push("EHLO not recognized".into());
        }

        let _ = smtp_write(&stream, "QUIT\r\n", timeout).await;

        Ok(ModuleResult {
            success: true,
            finding: Some(format!("SMTP on tcp/{port}: {}", findings.join("; "))),
            evidence,
            data: serde_json::json!({
                "host": self.host, "port": port,
                "banner": banner_line,
                "findings": findings,
            }),
            ..Default::default()
        })
    }
}
