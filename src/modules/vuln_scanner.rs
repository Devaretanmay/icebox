use crate::core::module::{Module, ModuleError, ModuleResult};
use async_trait::async_trait;
use icebox_macro::module;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

#[derive(Serialize)]
struct OsvQueryRequest {
    #[serde(rename = "package")]
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EpssResponse {
    data: Vec<EpssEntry>,
}

#[derive(Debug, Deserialize)]
struct EpssEntry {
    cve: String,
    #[serde(deserialize_with = "deserialize_epss_str")]
    epss: Option<f64>,
}

fn deserialize_epss_str<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum FloatOrString {
        F(f64),
        S(String),
    }
    match Option::<FloatOrString>::deserialize(deserializer)? {
        Some(FloatOrString::F(n)) => Ok(Some(n)),
        Some(FloatOrString::S(s)) => Ok(s.parse::<f64>().ok()),
        None => Ok(None),
    }
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct VulnerabilityFinding {
    cve: String,
    package: String,
    installed_version: String,
    fixed_version: Option<String>,
    summary: String,
    cvss_v31: Option<f64>,
    epss: Option<f64>,
    kev: bool,
    #[serde(default)]
    new_finding: bool,
    severity: String,
}

impl VulnerabilityFinding {
    fn severity_label(cvss: Option<f64>) -> String {
        match cvss {
            Some(s) if s >= 9.0 => "critical".into(),
            Some(s) if s >= 7.0 => "high".into(),
            Some(s) if s >= 4.0 => "medium".into(),
            Some(s) if s > 0.0 => "low".into(),
            _ => "unknown".into(),
        }
    }

    fn key(&self) -> String {
        format!("{}/{}", self.package, self.cve)
    }
}

const KEV_CVES: &[&str] = &[
    "CVE-2021-44228",
    "CVE-2021-45046",
    "CVE-2021-45105",
    "CVE-2022-22965",
    "CVE-2022-22963",
    "CVE-2021-41773",
    "CVE-2021-42013",
    "CVE-2022-0847",
    "CVE-2022-30190",
    "CVE-2023-34362",
    "CVE-2023-2868",
    "CVE-2023-35078",
    "CVE-2023-3519",
    "CVE-2023-4966",
    "CVE-2023-46604",
    "CVE-2023-6345",
    "CVE-2023-7024",
    "CVE-2024-3094",
    "CVE-2024-1709",
    "CVE-2024-23897",
];

fn is_kev(cve_id: &str) -> bool {
    let upper = cve_id.to_uppercase();
    KEV_CVES
        .iter()
        .any(|k| upper == *k || upper.contains(k.trim_start_matches("CVE-")))
}

struct ScanCycleResult {
    cycle: usize,
    findings: Vec<VulnerabilityFinding>,
    new_cves: Vec<VulnerabilityFinding>,
    errors: Vec<String>,
    elapsed_secs: u64,
}

#[module(
    name = "vuln_scanner",
    kind = "Analysis",
    description = "Dependency vulnerability scanner with optional --watch mode - parses Cargo.toml, queries OSV.dev API for CVEs, enriches with EPSS and KEV data",
    author = "ICEBOX"
)]
pub struct VulnScanner {
    #[option(
        required = true,
        help = "Path to project directory containing Cargo.toml"
    )]
    pub project_dir: String,
    #[option(help = "Timeout per API call in milliseconds (default 15000)")]
    pub timeout_ms: u64,
    #[option(
        help = "Enable watch mode: re-check dependencies periodically (true/false, default: false)"
    )]
    pub watch: bool,
    #[option(help = "Interval between watch-mode scans in seconds (default: 3600)")]
    pub watch_interval_secs: u64,
    #[option(
        help = "Number of watch-mode scans to run (default: 3, 0 = infinite, use with caution)"
    )]
    pub watch_scans: usize,
    #[option(help = "Alert on new CVEs only (suppress full re-list, default: false)")]
    pub alert_on_new_only: bool,
}

#[async_trait]
impl Module for VulnScanner {
    fn options_json(&self) -> serde_json::Value {
        serde_json::to_value(&VulnScannerOptions {
            project_dir: self.project_dir.clone(),
            timeout_ms: self.timeout_ms,
            watch: self.watch,
            watch_interval_secs: self.watch_interval_secs,
            watch_scans: self.watch_scans,
            alert_on_new_only: self.alert_on_new_only,
        })
        .unwrap_or(serde_json::Value::Null)
    }

    fn set_option(&mut self, name: &str, value: &str) -> Result<(), ModuleError> {
        let mut o = VulnScannerOptions {
            project_dir: self.project_dir.clone(),
            timeout_ms: self.timeout_ms,
            watch: self.watch,
            watch_interval_secs: self.watch_interval_secs,
            watch_scans: self.watch_scans,
            alert_on_new_only: self.alert_on_new_only,
        };
        o.set(name, value)?;
        self.project_dir = o.project_dir;
        self.timeout_ms = o.timeout_ms;
        self.watch = o.watch;
        self.watch_interval_secs = o.watch_interval_secs;
        self.watch_scans = o.watch_scans;
        self.alert_on_new_only = o.alert_on_new_only;
        Ok(())
    }

    fn validate(&self) -> Result<(), ModuleError> {
        VulnScannerOptions {
            project_dir: self.project_dir.clone(),
            timeout_ms: self.timeout_ms,
            watch: self.watch,
            watch_interval_secs: self.watch_interval_secs,
            watch_scans: self.watch_scans,
            alert_on_new_only: self.alert_on_new_only,
        }
        .validate()?;
        let path = std::path::Path::new(&self.project_dir);
        if !path.exists() {
            return Err(ModuleError::Other(format!(
                "project directory does not exist: {}",
                self.project_dir
            )));
        }
        let cargo_toml = path.join("Cargo.toml");
        if !cargo_toml.exists() {
            return Err(ModuleError::Other(format!(
                "Cargo.toml not found in: {}",
                self.project_dir
            )));
        }
        Ok(())
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        let timeout = Duration::from_millis(if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            15000
        });
        let project_dir = self.project_dir.trim().to_string();
        let watch = self.watch;
        let interval = Duration::from_secs(if self.watch_interval_secs > 0 {
            self.watch_interval_secs
        } else {
            3600
        });
        let max_scans = if watch && self.watch_scans == 0 {
            usize::MAX
        } else if watch {
            self.watch_scans.max(1)
        } else {
            1
        };
        let alert_on_new = self.alert_on_new_only;

        let packages = match fetch_cargo_metadata(&project_dir).await {
            Ok(p) => p,
            Err(e) => {
                return Ok(ModuleResult {
                    success: false,
                    finding: None,
                    evidence: vec![],
                    error: Some(e.to_string()),
                    data: serde_json::Value::Null,
                    session_id: None,
                });
            }
        };
        if packages.is_empty() {
            return Ok(ModuleResult {
                success: true,
                finding: Some("No registry dependencies found in Cargo.toml".into()),
                evidence: vec![],
                data: json!({"project": project_dir, "dependencies": 0}),
                ..Default::default()
            });
        }
        let dep_count = packages.len();

        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("ICEBOX-vuln-scanner/1.0")
            .build()
            .map_err(|e| ModuleError::Other(format!("HTTP client: {e}")))?;

        let mut all_cves_seen: HashSet<String> = HashSet::new();
        let mut cycles: Vec<ScanCycleResult> = Vec::new();
        let mut global_new_cves: Vec<VulnerabilityFinding> = Vec::new();

        for cycle in 0..max_scans {
            if cycle > 0 && cycle < max_scans {
                tokio::time::sleep(interval).await;
            }

            let cycle_start = std::time::Instant::now();
            let mut cycle_errors: Vec<String> = Vec::new();

            let mut cycle_findings: Vec<VulnerabilityFinding> = Vec::new();
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(5));
            let mut handles = Vec::new();

            for pkg in &packages {
                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let name = pkg.name.clone();
                let version = pkg.version.clone();
                let client = client.clone();

                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    query_osv(&client, &name, &version, timeout).await
                }));
            }

            for h in handles {
                match h.await {
                    Ok(Ok(mut vulns)) => cycle_findings.append(&mut vulns),
                    Ok(Err(e)) => cycle_errors.push(e),
                    Err(e) => cycle_errors.push(format!("task join: {e}")),
                }
            }

            let cve_ids: Vec<String> = cycle_findings.iter().map(|f| f.cve.clone()).collect();
            if !cve_ids.is_empty() {
                match query_epss(&client, &cve_ids, timeout).await {
                    Ok(epss_map) => {
                        for finding in &mut cycle_findings {
                            if let Some(epss) = epss_map.get(&finding.cve) {
                                finding.epss = Some(*epss);
                            }
                        }
                    }
                    Err(e) => cycle_errors.push(format!("EPSS enrichment failed: {e}")),
                }
            }

            for finding in &mut cycle_findings {
                if is_kev(&finding.cve) {
                    finding.kev = true;
                }
            }

            let mut cycle_new: Vec<VulnerabilityFinding> = Vec::new();
            for finding in &mut cycle_findings {
                let key = finding.key();
                if !all_cves_seen.contains(&key) {
                    finding.new_finding = true;
                    cycle_new.push(finding.clone());
                    global_new_cves.push(finding.clone());
                }
                all_cves_seen.insert(key);
            }

            let elapsed = cycle_start.elapsed().as_secs();

            cycles.push(ScanCycleResult {
                cycle,
                findings: cycle_findings,
                new_cves: cycle_new,
                errors: cycle_errors,
                elapsed_secs: elapsed,
            });

            if !watch {
                break;
            }
        }

        let mut all_findings_deduped: Vec<VulnerabilityFinding> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for cycle in &cycles {
            for finding in &cycle.findings {
                let key = finding.key();
                if !seen.contains(&key) {
                    let mut f = finding.clone();
                    if global_new_cves.iter().any(|n| n.key() == key) {
                        f.new_finding = true;
                    }
                    all_findings_deduped.push(f);
                    seen.insert(key);
                }
            }
        }

        let evidence: Vec<String> = if alert_on_new && !global_new_cves.is_empty() {
            global_new_cves
                .iter()
                .map(|f| format_new_evidence(f, true))
                .collect()
        } else {
            all_findings_deduped
                .iter()
                .map(|f| format_new_evidence(f, f.new_finding))
                .collect()
        };

        let structured_evidence: Vec<serde_json::Value> = all_findings_deduped
            .iter()
            .map(|f| {
                json!({
                    "cve": f.cve,
                    "package": f.package,
                    "installed": f.installed_version,
                    "fixed": f.fixed_version,
                    "cvss_v31": f.cvss_v31,
                    "epss": f.epss,
                    "kev": f.kev,
                    "new_finding": f.new_finding,
                    "severity": f.severity,
                    "summary": f.summary,
                })
            })
            .collect();

        let cycles_data: Vec<serde_json::Value> = cycles
            .iter()
            .map(|c| {
                json!({
                    "cycle": c.cycle,
                    "elapsed_secs": c.elapsed_secs,
                    "vulns": c.findings.len(),
                    "new_cves_this_cycle": c.new_cves.len(),
                    "errors": c.errors,
                })
            })
            .collect();

        let critical_count = all_findings_deduped
            .iter()
            .filter(|f| f.severity == "critical")
            .count();
        let high_count = all_findings_deduped
            .iter()
            .filter(|f| f.severity == "high")
            .count();
        let kev_count = all_findings_deduped.iter().filter(|f| f.kev).count();
        let new_count = global_new_cves.len();
        let total_cycles = cycles.len();

        let finding_summary = if all_findings_deduped.is_empty() {
            format!("Scanned {dep_count} dependencies, 0 known vulnerabilities found")
        } else if watch && new_count > 0 {
            let new_detail: Vec<String> = global_new_cves
                .iter()
                .map(|f| format!("{} {} ({})", f.package, f.cve, f.severity))
                .collect();
            format!(
                "[WATCH] {} scan cycles | {} total CVEs ({} critical, {} high, {} KEV) | {} NEW since last scan: {}",
                total_cycles,
                all_findings_deduped.len(),
                critical_count,
                high_count,
                kev_count,
                new_count,
                new_detail.join("; "),
            )
        } else {
            format!(
                "Scanned {dep_count} dependencies, found {} vulnerabilities ({} critical, {} high, {} KEV) | {} scan cycles",
                all_findings_deduped.len(),
                critical_count,
                high_count,
                kev_count,
                total_cycles,
            )
        };

        Ok(ModuleResult {
            success: true,
            finding: Some(finding_summary),
            evidence,
            data: json!({
                "project": project_dir,
                "dependencies": dep_count,
                "watch_enabled": watch,
                "scan_cycles": total_cycles,
                "new_cves_discovered": new_count,
                "new_cves": global_new_cves.iter().map(|f| json!({
                    "cve": f.cve,
                    "package": f.package,
                    "installed": f.installed_version,
                    "fixed": f.fixed_version,
                    "cvss_v31": f.cvss_v31,
                    "epss": f.epss,
                    "kev": f.kev,
                    "severity": f.severity,
                    "summary": f.summary,
                })).collect::<Vec<_>>(),
                "findings": structured_evidence,
                "summary": {
                    "total": all_findings_deduped.len(),
                    "critical": critical_count,
                    "high": high_count,
                    "medium": all_findings_deduped.iter().filter(|f| f.severity == "medium").count(),
                    "low": all_findings_deduped.iter().filter(|f| f.severity == "low").count(),
                    "kev": kev_count,
                    "new": new_count,
                },
                "cycles": cycles_data,
            }),
            ..Default::default()
        })
    }
}

fn format_new_evidence(finding: &VulnerabilityFinding, is_new: bool) -> String {
    let new_flag = if is_new { " [NEW]" } else { "" };
    let kev_flag = if finding.kev { " [KEV]" } else { "" };
    let cvss_str = finding
        .cvss_v31
        .map(|s| format!(" cvss={s:.1}"))
        .unwrap_or_default();
    let epss_str = finding
        .epss
        .map(|s| format!(" epss={s:.4}"))
        .unwrap_or_default();
    format!(
        "vuln/{}/{}{}{}{}{}",
        finding.package, finding.cve, cvss_str, epss_str, kev_flag, new_flag,
    )
}

async fn fetch_cargo_metadata(project_dir: &str) -> Result<Vec<CargoPackage>, ModuleError> {
    let output = tokio::process::Command::new("cargo")
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .current_dir(project_dir)
        .output()
        .await
        .map_err(|e| ModuleError::Other(format!("cargo metadata failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ModuleError::Other(format!(
            "cargo metadata error: {stderr}"
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let meta: CargoMetadata = serde_json::from_str(&stdout)
        .map_err(|e| ModuleError::Other(format!("failed to parse cargo metadata: {e}")))?;

    let packages: Vec<CargoPackage> = meta
        .packages
        .into_iter()
        .filter(|p| {
            p.source
                .as_deref()
                .is_some_and(|s| s.starts_with("registry+"))
        })
        .collect();

    Ok(packages)
}

async fn query_osv(
    client: &reqwest::Client,
    name: &str,
    version: &str,
    timeout: Duration,
) -> Result<Vec<VulnerabilityFinding>, String> {
    let url = "https://api.osv.dev/v1/query";
    let body = OsvQueryRequest {
        package: OsvPackage {
            name: name.to_string(),
            ecosystem: "crates.io".into(),
        },
        version: version.to_string(),
    };

    let resp = client
        .post(url)
        .json(&body)
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| format!("OSV query for {name}@{version}: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!(
            "OSV query for {name}@{version}: HTTP {}",
            resp.status()
        ));
    }

    let osv_resp: OsvQueryResponse = resp
        .json()
        .await
        .map_err(|e| format!("OSV parse error for {name}@{version}: {e}"))?;

    let mut findings = Vec::new();

    for vuln in &osv_resp.vulns {
        let cvss = vuln.severity.iter().find_map(|s| {
            if s.severity_type == "CVSS_V3" || s.severity_type == "CVSS" {
                s.score.parse::<f64>().ok()
            } else {
                None
            }
        });

        let fixed_version = vuln.affected.iter().find_map(|a| {
            a.ranges.iter().find_map(|r| {
                if r.range_type == "SEMVER" || r.range_type == "ECOSYSTEM" {
                    r.events.iter().find_map(|e| e.fixed.clone())
                } else {
                    None
                }
            })
        });

        let cve_id = vuln
            .aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .cloned()
            .unwrap_or_else(|| vuln.id.clone());

        let summary = if vuln.summary.is_empty() {
            vuln.details.chars().take(200).collect::<String>()
        } else {
            vuln.summary.clone()
        };

        let severity = VulnerabilityFinding::severity_label(cvss);

        findings.push(VulnerabilityFinding {
            cve: cve_id,
            package: name.to_string(),
            installed_version: version.to_string(),
            fixed_version,
            summary,
            cvss_v31: cvss,
            epss: None,
            kev: false,
            new_finding: false,
            severity,
        });
    }

    Ok(findings)
}

async fn query_epss(
    client: &reqwest::Client,
    cve_ids: &[String],
    timeout: Duration,
) -> Result<HashMap<String, f64>, String> {
    if cve_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let cve_param = cve_ids.join(",");
    let url = format!("https://api.first.org/data/v1/epss?cve={cve_param}");

    let resp = client
        .get(&url)
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| format!("EPSS query: {e}"))?;

    if !resp.status().is_success() {
        return Ok(HashMap::new());
    }

    let mut epss_map = HashMap::new();
    if let Ok(epss_resp) = resp.json::<EpssResponse>().await {
        for entry in epss_resp.data {
            if let Some(score) = entry.epss {
                epss_map.insert(entry.cve, score);
            }
        }
    }

    Ok(epss_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kev_detection() {
        assert!(is_kev("CVE-2021-44228"));
        assert!(is_kev("cve-2021-44228"));
        assert!(is_kev("CVE-2022-22965"));
        assert!(!is_kev("CVE-2024-99999"));
    }

    #[test]
    fn test_severity_label() {
        assert_eq!(VulnerabilityFinding::severity_label(Some(9.5)), "critical");
        assert_eq!(VulnerabilityFinding::severity_label(Some(7.5)), "high");
        assert_eq!(VulnerabilityFinding::severity_label(Some(5.0)), "medium");
        assert_eq!(VulnerabilityFinding::severity_label(Some(2.0)), "low");
        assert_eq!(VulnerabilityFinding::severity_label(None), "unknown");
    }

    #[test]
    fn test_finding_key_and_new_flag() {
        let f1 = VulnerabilityFinding {
            cve: "CVE-2024-27303".into(),
            package: "tokio".into(),
            installed_version: "1.0.0".into(),
            fixed_version: Some("1.35.1".into()),
            summary: "test".into(),
            cvss_v31: Some(7.5),
            epss: Some(0.05),
            kev: false,
            new_finding: true,
            severity: "high".into(),
        };
        assert_eq!(f1.key(), "tokio/CVE-2024-27303");
        assert!(f1.new_finding);
    }

    #[test]
    fn test_format_new_evidence() {
        let finding = VulnerabilityFinding {
            cve: "CVE-2024-27303".into(),
            package: "tokio".into(),
            installed_version: "1.0.0".into(),
            fixed_version: Some("1.35.1".into()),
            summary: "test".into(),
            cvss_v31: Some(7.5),
            epss: Some(0.05),
            kev: false,
            new_finding: true,
            severity: "high".into(),
        };
        let ev = format_new_evidence(&finding, true);
        assert!(
            ev.contains("[NEW]"),
            "new evidence should have [NEW] tag: {ev}"
        );
        assert!(ev.contains("cvss=7.5"));
        assert!(ev.contains("epss=0.0500"));

        let ev2 = format_new_evidence(&finding, false);
        assert!(!ev2.contains("[NEW]"), "non-new should not have [NEW] tag");
    }

    #[test]
    fn test_format_new_evidence_with_kev() {
        let finding = VulnerabilityFinding {
            cve: "CVE-2021-44228".into(),
            package: "log4j".into(),
            installed_version: "2.0.0".into(),
            fixed_version: Some("2.17.1".into()),
            summary: "RCE in Log4j".into(),
            cvss_v31: Some(10.0),
            epss: Some(0.95),
            kev: true,
            new_finding: true,
            severity: "critical".into(),
        };
        let ev = format_new_evidence(&finding, true);
        assert!(ev.contains("[NEW]"));
        assert!(ev.contains("[KEV]"));
        assert!(ev.contains("cvss=10.0"));
        assert!(ev.contains("epss=0.9500"));
        assert!(ev.starts_with("vuln/"));
    }

    #[test]
    fn test_delta_detection_basic() {
        let mut seen: HashSet<String> = HashSet::new();

        let c0_findings = vec![
            VulnerabilityFinding {
                cve: "CVE-2024-001".into(),
                package: "crate_a".into(),
                installed_version: "1.0".into(),
                fixed_version: None,
                summary: "".into(),
                cvss_v31: Some(5.0),
                epss: None,
                kev: false,
                new_finding: false,
                severity: "medium".into(),
            },
            VulnerabilityFinding {
                cve: "CVE-2024-002".into(),
                package: "crate_b".into(),
                installed_version: "1.0".into(),
                fixed_version: None,
                summary: "".into(),
                cvss_v31: Some(3.0),
                epss: None,
                kev: false,
                new_finding: false,
                severity: "low".into(),
            },
        ];

        for f in &c0_findings {
            seen.insert(f.key());
        }
        assert_eq!(seen.len(), 2, "cycle 0 should register 2 CVEs");

        let c1_findings = vec![
            VulnerabilityFinding {
                cve: "CVE-2024-001".into(),
                package: "crate_a".into(),
                installed_version: "1.0".into(),
                fixed_version: None,
                summary: "".into(),
                cvss_v31: Some(5.0),
                epss: None,
                kev: false,
                new_finding: false,
                severity: "medium".into(),
            },
            VulnerabilityFinding {
                cve: "CVE-2024-002".into(),
                package: "crate_b".into(),
                installed_version: "1.0".into(),
                fixed_version: None,
                summary: "".into(),
                cvss_v31: Some(3.0),
                epss: None,
                kev: false,
                new_finding: false,
                severity: "low".into(),
            },
            VulnerabilityFinding {
                cve: "CVE-2024-003".into(),
                package: "crate_c".into(),
                installed_version: "1.0".into(),
                fixed_version: None,
                summary: "".into(),
                cvss_v31: Some(9.0),
                epss: None,
                kev: false,
                new_finding: true,
                severity: "critical".into(),
            },
        ];

        let mut new_cves: Vec<VulnerabilityFinding> = Vec::new();
        for mut f in c1_findings {
            let key = f.key();
            if !seen.contains(&key) {
                f.new_finding = true;
                new_cves.push(f.clone());
            }
            seen.insert(key);
        }

        assert_eq!(new_cves.len(), 1, "only one new CVE in cycle 1");
        assert_eq!(new_cves[0].cve, "CVE-2024-003");
        assert_eq!(new_cves[0].package, "crate_c");
        assert!(new_cves[0].new_finding);

        let c2_findings: Vec<VulnerabilityFinding> = vec![VulnerabilityFinding {
            cve: "CVE-2024-003".into(),
            package: "crate_c".into(),
            ..Default::default()
        }];
        let before = seen.len();
        for f in &c2_findings {
            seen.insert(f.key());
        }
        assert_eq!(seen.len(), before, "no new CVEs in cycle 2");
    }

    #[tokio::test]
    async fn test_osv_query_real() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("ICEBOX-test/1.0")
            .build()
            .expect("HTTP client");

        let findings = query_osv(&client, "tokio", "1.0.0", Duration::from_secs(10))
            .await
            .expect("OSV query must succeed");

        assert!(!findings.is_empty(), "tokio 1.0.0 should have known CVEs");
        let first = &findings[0];
        assert!(
            first.cve.starts_with("CVE-") || first.cve.starts_with("GHSA-"),
            "first finding: {}",
            first.cve
        );
        assert_eq!(first.package, "tokio");
        assert_eq!(first.installed_version, "1.0.0");
    }

    #[tokio::test]
    async fn test_osv_query_no_vulns() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("ICEBOX-test/1.0")
            .build()
            .expect("HTTP client");

        let findings = query_osv(
            &client,
            "zzzz_invalid_crate_000",
            "0.1.0",
            Duration::from_secs(10),
        )
        .await
        .expect("OSV query must succeed");

        assert!(
            findings.is_empty(),
            "non-existent crate should have no CVEs"
        );
    }

    #[test]
    fn test_finding_json_has_cvss_fields() {
        let finding = VulnerabilityFinding {
            cve: "CVE-2024-27303".into(),
            package: "tokio".into(),
            installed_version: "1.0.0".into(),
            fixed_version: Some("1.35.1".into()),
            summary: "Resource exhaustion in tokio.epoll".into(),
            cvss_v31: Some(7.5),
            epss: Some(0.05),
            kev: false,
            new_finding: true,
            severity: "high".into(),
        };

        let json_val = serde_json::to_value(&finding).expect("must serialize");
        assert_eq!(json_val["cve"], "CVE-2024-27303");
        assert_eq!(json_val["cvss_v31"], 7.5);
        assert!((json_val["epss"].as_f64().unwrap() - 0.05).abs() < 0.001);
        assert_eq!(json_val["kev"], false);
        assert_eq!(json_val["new_finding"], true);
        assert_eq!(json_val["severity"], "high");
    }

    #[tokio::test]
    async fn test_epss_query_real() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("ICEBOX-test/1.0")
            .build()
            .expect("HTTP client");

        let cves = vec!["CVE-2021-44228".to_string()];
        let epss_map = query_epss(&client, &cves, Duration::from_secs(10))
            .await
            .expect("EPSS query must succeed");

        assert!(
            epss_map.contains_key("CVE-2021-44228"),
            "Log4Shell should have EPSS data"
        );
        if let Some(score) = epss_map.get("CVE-2021-44228") {
            assert!(*score > 0.0, "EPSS score should be > 0");
            assert!(*score <= 1.0, "EPSS score should be <= 1.0");
        }
    }
}
