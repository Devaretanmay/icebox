use serde::de::{Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::module::{Capability, Intent, ModuleKind};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    None = 0,
    #[default]
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::None => "none",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    pub fn from_kind(kind: ModuleKind) -> RiskLevel {
        match kind {
            ModuleKind::Scanner | ModuleKind::Auxiliary | ModuleKind::Analysis => RiskLevel::Low,
            ModuleKind::Exploit | ModuleKind::Post | ModuleKind::Transform => RiskLevel::Medium,
            ModuleKind::Payload | ModuleKind::Listener | ModuleKind::Encoder => RiskLevel::High,
            ModuleKind::Backdoor => RiskLevel::Critical,
        }
    }
}

impl std::str::FromStr for RiskLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "none" => RiskLevel::None,
            "low" => RiskLevel::Low,
            "medium" => RiskLevel::Medium,
            "high" => RiskLevel::High,
            "critical" => RiskLevel::Critical,
            other => return Err(format!("unknown risk level: {other}")),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CvssScore {
    pub cvss_v31: Option<f64>,
    pub cvss_v40: Option<f64>,
    pub epss: Option<f64>,
    pub kev: bool,
}

impl<'de> Deserialize<'de> for CvssScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            CvssV31,
            CvssV40,
            Epss,
            Kev,
        }

        struct CvssVisitor;

        impl<'de> Visitor<'de> for CvssVisitor {
            type Value = CvssScore;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a CVSS score (number) or an object {cvss_v31, cvss_v40, epss, kev}")
            }

            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Ok(CvssScore {
                    cvss_v31: Some(v),
                    cvss_v40: None,
                    epss: None,
                    kev: false,
                })
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(CvssScore {
                    cvss_v31: Some(v as f64),
                    cvss_v40: None,
                    epss: None,
                    kev: false,
                })
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(CvssScore {
                    cvss_v31: Some(v as f64),
                    cvss_v40: None,
                    epss: None,
                    kev: false,
                })
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut cvss_v31 = None;
                let mut cvss_v40 = None;
                let mut epss = None;
                let mut kev = false;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::CvssV31 => cvss_v31 = map.next_value()?,
                        Field::CvssV40 => cvss_v40 = map.next_value()?,
                        Field::Epss => epss = map.next_value()?,
                        Field::Kev => kev = map.next_value()?,
                    }
                }
                Ok(CvssScore {
                    cvss_v31,
                    cvss_v40,
                    epss,
                    kev,
                })
            }
        }

        deserializer.deserialize_any(CvssVisitor)
    }
}

impl CvssScore {
    pub fn effective_score(&self) -> f64 {
        self.cvss_v40.or(self.cvss_v31).unwrap_or(0.0)
    }

    pub fn severity(&self) -> RiskLevel {
        let s = self.effective_score();
        if s >= 9.0 {
            RiskLevel::Critical
        } else if s >= 7.0 {
            RiskLevel::High
        } else if s >= 4.0 {
            RiskLevel::Medium
        } else if s > 0.0 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        }
    }

    pub fn weighted_risk(&self) -> f64 {
        let base = self.effective_score();
        let epss_boost = self.epss.unwrap_or(0.0) * 2.0;
        let kev_boost = if self.kev { 3.0 } else { 0.0 };
        (base + epss_boost + kev_boost).min(10.0)
    }

    pub fn from_score(score: f64) -> Self {
        CvssScore {
            cvss_v31: Some(score),
            cvss_v40: None,
            epss: None,
            kev: false,
        }
    }

    pub fn kev(score: f64) -> Self {
        CvssScore {
            cvss_v31: Some(score),
            cvss_v40: None,
            epss: None,
            kev: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Charter {
    pub accepted: bool,
    pub engagement: String,
    pub rules_of_engagement: Vec<String>,
}

impl Charter {
    pub fn accept(engagement: impl Into<String>, roe: Vec<String>) -> Self {
        Charter {
            accepted: true,
            engagement: engagement.into(),
            rules_of_engagement: roe,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScopeManager {
    pub allow: Vec<String>,
}

impl ScopeManager {
    pub fn new(allow: Vec<String>) -> Self {
        ScopeManager { allow }
    }

    pub fn is_in_scope(&self, target: &str) -> bool {
        let target = target.trim();
        let target_ips = resolve_ips(target);
        for raw in &self.allow {
            let entry = raw.trim();
            if entry.is_empty() {
                continue;
            }
            if entry == target {
                return true;
            }
            if let Some(prefix) = entry.strip_suffix('*') {
                if target.starts_with(prefix) {
                    return true;
                }
            }
            if entry.contains('/') && ipv4_in_cidr(target, entry) {
                return true;
            }
            for tip in &target_ips {
                if entry == tip {
                    return true;
                }
                if entry.contains('/') && ipv4_in_cidr(tip, entry) {
                    return true;
                }
            }
            if !is_literal_or_pattern(entry) {
                for eip in resolve_ips(entry) {
                    if eip == target {
                        return true;
                    }
                    for tip in &target_ips {
                        if eip == *tip {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

fn resolve_ips(host: &str) -> Vec<String> {
    if host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok() {
        return vec![host.to_string()];
    }
    let mut ips = Vec::new();
    if let Ok(addrs) = format!("{host}:0").to_socket_addrs() {
        for a in addrs {
            ips.push(a.ip().to_string());
        }
    }
    ips
}

fn is_literal_or_pattern(entry: &str) -> bool {
    if entry.contains('/') || entry.ends_with('*') {
        return true;
    }
    entry.parse::<Ipv4Addr>().is_ok() || entry.parse::<Ipv6Addr>().is_ok()
}

fn ipv4_in_cidr(target: &str, cidr: &str) -> bool {
    let network = match ipnet::Ipv4Net::from_str(cidr) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let target_ip = match Ipv4Addr::from_str(target) {
        Ok(a) => a,
        Err(_) => return false,
    };
    network.contains(&target_ip)
}

pub const DESTRUCTIVE_KEYWORDS: &[&str] = &[
    "wipe",
    "format",
    "destroy",
    "delete",
    "drop table",
    "shutdown",
    "reboot",
    "kill",
    "ransom",
    "brick",
    "overwrite",
    "bruteforce",
];

pub fn is_destructive(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    DESTRUCTIVE_KEYWORDS.iter().any(|k| lower.contains(k))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyContext {
    Cli,
    Rest,
    #[default]
    Autonomous,
}

impl PolicyContext {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyContext::Cli => "cli",
            PolicyContext::Rest => "rest",
            PolicyContext::Autonomous => "autonomous",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyRequest {
    pub target: String,
    pub capabilities: Vec<Capability>,
    pub impact: RiskLevel,
    pub destructive: bool,
    pub charter_accepted: bool,
    pub in_scope: bool,
    pub approved: bool,
    pub context: PolicyContext,
    pub cvss: Option<CvssScore>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    RequireApproval(String),
    Deny(String),
}

impl PolicyDecision {
    pub fn reason(&self) -> Option<&str> {
        match self {
            PolicyDecision::Allow => None,
            PolicyDecision::RequireApproval(r) | PolicyDecision::Deny(r) => Some(r),
        }
    }
}

pub trait PolicyEngine {
    fn evaluate(&self, req: &PolicyRequest) -> PolicyDecision;
}

#[derive(Debug, Clone, Copy)]
pub struct DefaultPolicy {
    pub max_risk: RiskLevel,
    pub context: PolicyContext,
}

impl PolicyEngine for DefaultPolicy {
    fn evaluate(&self, req: &PolicyRequest) -> PolicyDecision {
        if !req.charter_accepted {
            return PolicyDecision::Deny(
                "charter not accepted - run `charter accept` first".into(),
            );
        }
        if !req.in_scope {
            return PolicyDecision::Deny(format!("target out of scope: {}", req.target));
        }
        if req.impact > self.max_risk {
            return PolicyDecision::Deny(format!(
                "risk level {} exceeds maximum allowed {}",
                req.impact.as_str(),
                self.max_risk.as_str()
            ));
        }
        if (req.destructive || req.impact >= RiskLevel::High) && !req.approved {
            return PolicyDecision::RequireApproval(
                "destructive / high-risk action requires explicit approval".into(),
            );
        }
        PolicyDecision::Allow
    }
}

#[derive(Debug, Clone)]
pub struct Preflight {
    pub target: String,
    pub charter_accepted: bool,
    pub in_scope: bool,
    pub risk: RiskLevel,
    pub destructive: bool,
    pub approved: bool,
    pub capabilities: Vec<Capability>,
    pub intents: Vec<Intent>,
    pub context: PolicyContext,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PreflightError {
    #[error("destructive / high-risk action requires explicit approval")]
    ApprovalRequired,
    #[error("{0}")]
    Denied(String),
}

impl Preflight {
    pub fn to_request(&self) -> PolicyRequest {
        PolicyRequest {
            target: self.target.clone(),
            capabilities: self.capabilities.clone(),
            impact: self.risk,
            destructive: self.destructive,
            charter_accepted: self.charter_accepted,
            in_scope: self.in_scope,
            approved: self.approved,
            context: self.context,
            cvss: None,
        }
    }

    pub fn check(&self, policy: &dyn PolicyEngine) -> Result<(), PreflightError> {
        match policy.evaluate(&self.to_request()) {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::RequireApproval(_) => Err(PreflightError::ApprovalRequired),
            PolicyDecision::Deny(reason) => Err(PreflightError::Denied(reason)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub at: u64,
    pub target: String,
    pub module: String,
    pub capabilities: Vec<Capability>,
    pub intents: Vec<Intent>,
    pub impact: RiskLevel,
    pub context: PolicyContext,
    pub decision: PolicyDecision,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRule {
    DenyCapability(Capability),
    AllowCapability(Capability),
    MaxRisk(RiskLevel),
    RequireApproval {
        capability: Capability,
        target_pattern: String,
    },
    DenyIfCvssAbove(f64),
    RequireApprovalIf {
        cvss_above: Option<f64>,
        epss_above: Option<f64>,
        kev: bool,
    },
}

pub fn target_matches(target: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if let Some(prefix) = pattern.strip_suffix('*') {
        target.starts_with(prefix)
    } else {
        target == pattern
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub rules: Vec<PolicyRule>,
    pub version: u64,
}

impl Default for PolicySet {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            version: 1,
        }
    }
}

impl PolicySet {
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.version += 1;
    }

    pub fn remove_rule(&mut self, index: usize) -> Option<PolicyRule> {
        if index >= self.rules.len() {
            return None;
        }
        self.version += 1;
        Some(self.rules.remove(index))
    }

    pub fn set_rules(&mut self, rules: Vec<PolicyRule>) {
        self.rules = rules;
        self.version += 1;
    }

    pub fn max_risk(&self, default: RiskLevel) -> RiskLevel {
        self.rules.iter().fold(default, |acc, r| match r {
            PolicyRule::MaxRisk(m) => acc.min(*m),
            _ => acc,
        })
    }

    pub fn denied(&self, caps: &[Capability]) -> Option<Capability> {
        self.rules.iter().find_map(|r| match r {
            PolicyRule::DenyCapability(c) if caps.contains(c) => Some(*c),
            _ => None,
        })
    }

    pub fn allows(&self, caps: &[Capability]) -> bool {
        self.rules
            .iter()
            .any(|r| matches!(r, PolicyRule::AllowCapability(c) if caps.contains(c)))
    }

    pub fn deny_cvss_threshold(&self) -> Option<f64> {
        self.rules
            .iter()
            .filter_map(|r| match r {
                PolicyRule::DenyIfCvssAbove(t) => Some(*t),
                _ => None,
            })
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    pub fn has_cvss_rules(&self) -> bool {
        self.rules.iter().any(|r| {
            matches!(
                r,
                PolicyRule::DenyIfCvssAbove(_) | PolicyRule::RequireApprovalIf { .. }
            )
        })
    }
}

#[derive(Debug, Clone)]
pub struct ConfigPolicy {
    pub max_risk: RiskLevel,
    pub context: PolicyContext,
    pub rules: PolicySet,
}

impl PolicyEngine for ConfigPolicy {
    fn evaluate(&self, req: &PolicyRequest) -> PolicyDecision {
        if let Some(c) = self.rules.denied(&req.capabilities) {
            return PolicyDecision::Deny(format!("capability {} denied by policy", c.as_str()));
        }
        for r in &self.rules.rules {
            if let PolicyRule::RequireApproval {
                capability,
                target_pattern,
            } = r
            {
                if req.capabilities.contains(capability)
                    && target_matches(&req.target, target_pattern)
                {
                    return PolicyDecision::RequireApproval(format!(
                        "capability {} on {} requires approval",
                        capability.as_str(),
                        req.target
                    ));
                }
            }
        }
        if let Some(ref cvss) = req.cvss {
            let score = cvss.effective_score();
            for r in &self.rules.rules {
                if let PolicyRule::DenyIfCvssAbove(threshold) = r {
                    if score > *threshold {
                        return PolicyDecision::Deny(format!(
                            "CVSS score {:.1} exceeds deny threshold {:.1}",
                            score, threshold
                        ));
                    }
                }
            }
        }
        if let Some(ref cvss) = req.cvss {
            for r in &self.rules.rules {
                if let PolicyRule::RequireApprovalIf {
                    cvss_above,
                    epss_above,
                    kev,
                } = r
                {
                    let cvss_triggers = cvss_above
                        .map(|t| cvss.effective_score() > t)
                        .unwrap_or(false);
                    let epss_triggers = epss_above
                        .and_then(|t| cvss.epss.map(|e| e > t))
                        .unwrap_or(false);
                    let kev_triggers = *kev && cvss.kev;
                    if cvss_triggers || epss_triggers || kev_triggers {
                        return PolicyDecision::RequireApproval(format!(
                            "CVSS risk (score={:.1}, epss={:?}, kev={}) exceeds policy threshold",
                            cvss.effective_score(),
                            cvss.epss,
                            cvss.kev
                        ));
                    }
                }
            }
        }
        let mut d = DefaultPolicy {
            max_risk: self.rules.max_risk(self.max_risk),
            context: self.context,
        }
        .evaluate(req);
        if matches!(d, PolicyDecision::RequireApproval(_)) && self.rules.allows(&req.capabilities) {
            d = PolicyDecision::Allow;
        }
        d
    }
}

pub fn make_config_policy(
    max_risk: RiskLevel,
    context: PolicyContext,
    rules: &PolicySet,
) -> ConfigPolicy {
    ConfigPolicy {
        max_risk,
        context,
        rules: rules.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceProvenance {
    pub job_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub at: u64,
    pub module: String,
    pub target: String,
    pub content: String,
    pub kind: Option<String>,
    pub confidence: f64,
    pub normalized: Option<Value>,
    pub provenance: EvidenceProvenance,
}

impl Evidence {
    pub fn cvss(&self) -> Option<CvssScore> {
        if let Some(ref norm) = self.normalized {
            if let Ok(score) = serde_json::from_value::<CvssScore>(norm.clone()) {
                if score.effective_score() > 0.0 {
                    return Some(score);
                }
            }
        }
        DefaultRiskEvaluator::parse_one(&self.content)
    }

    pub fn new(module: &str, target: &str, content: &str, job_id: Option<u64>, seq: usize) -> Self {
        let (kind, confidence, normalized) = normalize_evidence(content, module);
        let at = now_secs();
        Evidence {
            id: format!("{at}-{seq}"),
            at,
            module: module.to_string(),
            target: target.to_string(),
            content: content.to_string(),
            kind,
            confidence,
            normalized,
            provenance: EvidenceProvenance { job_id },
        }
    }
}

pub trait RiskEvaluator {
    fn evaluate(&self, evidence: &[Evidence]) -> Option<CvssScore>;
    fn evaluate_raw(&self, contents: &[String], kind: &Option<String>) -> Option<CvssScore>;

    fn cvss_to_risk_level(score: f64) -> RiskLevel {
        if score >= 9.0 {
            RiskLevel::Critical
        } else if score >= 7.0 {
            RiskLevel::High
        } else if score >= 4.0 {
            RiskLevel::Medium
        } else if score > 0.0 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DefaultRiskEvaluator;

impl DefaultRiskEvaluator {
    pub fn parse_one(content: &str) -> Option<CvssScore> {
        let val: serde_json::Value = serde_json::from_str(content).ok()?;
        let obj = val.as_object()?;

        let cvss_v31 = obj
            .get("cvss_v31")
            .or_else(|| obj.get("cvss"))
            .or_else(|| obj.get("score"))
            .and_then(|v| v.as_f64());
        let cvss_v40 = obj
            .get("cvss_v40")
            .or_else(|| obj.get("cvss_v4"))
            .and_then(|v| v.as_f64());
        let epss = obj.get("epss").and_then(|v| v.as_f64());
        let kev = obj
            .get("kev")
            .or_else(|| obj.get("cisa_kev"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if cvss_v31.is_some() || cvss_v40.is_some() {
            Some(CvssScore {
                cvss_v31,
                cvss_v40,
                epss,
                kev,
            })
        } else {
            None
        }
    }
}

impl RiskEvaluator for DefaultRiskEvaluator {
    fn evaluate(&self, evidence: &[Evidence]) -> Option<CvssScore> {
        let mut best: Option<CvssScore> = None;
        for e in evidence {
            if let Some(score) = Self::parse_one(&e.content) {
                best = Self::pick_best(best, score);
            }
            if let Some(ref norm) = e.normalized {
                if let Ok(score) = serde_json::from_value::<CvssScore>(norm.clone()) {
                    best = Self::pick_best(best, score);
                }
            }
        }
        best
    }

    fn evaluate_raw(&self, contents: &[String], _kind: &Option<String>) -> Option<CvssScore> {
        contents
            .iter()
            .filter_map(|c| Self::parse_one(c))
            .max_by(|a, b| {
                a.weighted_risk()
                    .partial_cmp(&b.weighted_risk())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }
}

impl DefaultRiskEvaluator {
    fn pick_best(best: Option<CvssScore>, candidate: CvssScore) -> Option<CvssScore> {
        match best {
            None => Some(candidate),
            Some(ref current) if candidate.weighted_risk() > current.weighted_risk() => {
                Some(candidate)
            }
            _ => best,
        }
    }
}

pub fn normalize_evidence(content: &str, _module: &str) -> (Option<String>, f64, Option<Value>) {
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(content) {
        return (
            infer_kind(map.keys().map(|k| k.as_str())),
            0.9,
            Some(Value::Object(map)),
        );
    }
    let lower = content.to_lowercase();
    let (kind, confidence) = if lower.contains("credential")
        || lower.contains("password")
        || lower.contains("hash")
        || lower.contains("login")
    {
        (Some("credential".into()), 0.7)
    } else if lower.contains("cve") || lower.contains("vuln") || lower.contains("exploit") {
        (Some("vulnerability".into()), 0.7)
    } else if lower.contains("open") || lower.contains("listening") || lower.contains("port") {
        (Some("port".into()), 0.65)
    } else if lower.contains("service") || lower.contains("banner") {
        (Some("service".into()), 0.6)
    } else if lower.contains("error") || lower.contains("fail") {
        (Some("error".into()), 0.3)
    } else {
        (None, 0.5)
    };
    (kind, confidence, None)
}

fn infer_kind<'a>(keys: impl Iterator<Item = &'a str>) -> Option<String> {
    let lower: Vec<String> = keys.map(|k| k.to_lowercase()).collect();
    if lower.iter().any(|k| {
        k.contains("credential")
            || k.contains("password")
            || k.contains("user")
            || k.contains("hash")
    }) {
        Some("credential".into())
    } else if lower
        .iter()
        .any(|k| k.contains("cve") || k.contains("vuln"))
    {
        Some("vulnerability".into())
    } else if lower
        .iter()
        .any(|k| k.contains("port") || k.contains("service"))
    {
        Some("service".into())
    } else {
        Some("finding".into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningTrace {
    pub at: u64,
    pub phase: String,
    pub context_len: usize,
    pub summary: String,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryKind {
    Fact,
    Decision,
    Failure,
}

impl MemoryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryKind::Fact => "fact",
            MemoryKind::Decision => "decision",
            MemoryKind::Failure => "failure",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub at: u64,
    pub kind: MemoryKind,
    pub text: String,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
