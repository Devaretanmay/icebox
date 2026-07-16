use std::collections::HashMap;
use tracing::info;

use crate::core::framework::SharedFramework;
use crate::core::job::Job;
use crate::core::safety::{
    make_config_policy, now_secs, MemoryKind, PolicyContext, ReasoningTrace, RiskLevel,
};
use crate::core::session::{Session, SessionId, SessionKind};

use crate::ai::ollama::OllamaClient;

// -- Phase machine --

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Scan,
    Analyze,
    Plan,
    Execute,
    Report,
    Done,
}

impl Phase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Scan => "scan",
            Phase::Analyze => "analyze",
            Phase::Plan => "plan",
            Phase::Execute => "execute",
            Phase::Report => "report",
            Phase::Done => "done",
        }
    }
}

// -- Action types --

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Action {
    pub module: String,
    #[serde(default)]
    pub options: HashMap<String, String>,
    pub target: String,
    pub priority: u32,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PlanOutput {
    actions: Vec<Action>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanFinding {
    pub module: String,
    pub finding: Option<String>,
    pub evidence: Vec<String>,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalysisOutput {
    pub summary: String,
    pub vulnerabilities: Vec<String>,
    pub recommended_modules: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportOutput {
    pub title: String,
    pub summary: String,
    pub findings: Vec<String>,
    pub actions_taken: Vec<String>,
    pub recommendations: Vec<String>,
}

// -- Planner trait --

#[async_trait::async_trait]
pub trait Planner: Send + Sync {
    async fn analyze(&self, context: &str) -> anyhow::Result<AnalysisOutput>;
    async fn plan(&self, context: &str) -> anyhow::Result<Vec<Action>>;
    async fn summarize(&self, context: &str) -> anyhow::Result<ReportOutput>;
}

// -- Plan approval (human-in-the-loop gating) --

/// Decides whether the agent is allowed to execute a generated plan.
pub trait PlanApprover: Send + Sync {
    fn approve(&self, actions: &[Action]) -> bool;
}

/// Auto-approve every plan (used in auto-approved mode).
pub struct AlwaysApprove;
impl PlanApprover for AlwaysApprove {
    fn approve(&self, _actions: &[Action]) -> bool {
        true
    }
}

/// Reject every plan; campaign stops before Execute so the operator can inspect.
pub struct DenyPlan;
impl PlanApprover for DenyPlan {
    fn approve(&self, _actions: &[Action]) -> bool {
        false
    }
}

pub struct InteractiveApprover;
impl PlanApprover for InteractiveApprover {
    fn approve(&self, actions: &[Action]) -> bool {
        if actions.is_empty() {
            println!("agent: plan is empty  -  nothing to execute.");
            return false;
        }
        println!("\n=== PROPOSED PLAN ({} action(s)) ===", actions.len());
        let mut sorted = actions.to_vec();
        sorted.sort_by_key(|a| std::cmp::Reverse(a.priority));
        for (i, a) in sorted.iter().enumerate() {
            let opts: Vec<String> = a.options.iter().map(|(k, v)| format!("{k}={v}")).collect();
            println!(
                "  {}. [prio {}] {} -> {} | {} | opts: [{}]",
                i + 1,
                a.priority,
                a.module,
                a.target,
                a.reason,
                opts.join(", ")
            );
        }
        print!("Execute this plan? [y/N]: ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_ok() {
            let trimmed = line.trim().to_lowercase();
            return matches!(trimmed.as_str(), "y" | "yes");
        }
        false
    }
}

/// Build a compact catalog of all registered modules for the LLM system prompt.
pub fn build_module_catalog() -> String {
    let entries = crate::modules::discover();
    let mut lines = Vec::new();
    for e in entries {
        let info = (e.info)();
        let loaded = match crate::modules::load(&info.name) {
            Some(l) => l,
            None => continue,
        };
        let opt_desc = match loaded.module.options_json() {
            serde_json::Value::Object(map) if !map.is_empty() => map
                .iter()
                .map(|(k, v)| {
                    let t = if v.is_u64() || v.is_i64() {
                        "int"
                    } else if v.is_boolean() {
                        "bool"
                    } else {
                        "str"
                    };
                    format!("{k}:{t}")
                })
                .collect::<Vec<_>>()
                .join(", "),
            _ => String::new(),
        };
        lines.push(format!(
            "- {} [{}]: {}. options: [{}]",
            info.name,
            info.kind.as_str(),
            info.description,
            opt_desc
        ));
    }
    lines.join("\n")
}

// -- LLM Planner --

pub struct LlmPlanner {
    llm: OllamaClient,
    catalog: String,
}

impl LlmPlanner {
    /// Build a planner with a precomputed module catalog for the system prompt.
    pub fn new_with_catalog(model: impl Into<String>, catalog: String) -> Self {
        LlmPlanner {
            llm: OllamaClient::new(model.into()),
            catalog,
        }
    }

    pub fn new(model: impl Into<String>) -> Self {
        Self::new_with_catalog(model, build_module_catalog())
    }

    fn system_prompt(&self) -> String {
        format!(
            "{}\n\nAVAILABLE MODULES (use exact names, set options by the key names below):\n{}\n",
            SYSTEM_PROMPT, self.catalog
        )
    }
    fn analysis_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "vulnerabilities": {"type": "array", "items": {"type": "string"}},
                "recommended_modules": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["summary", "vulnerabilities", "recommended_modules"]
        })
    }

    fn plan_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "actions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "module": {"type": "string"},
                            "options": {"type": "object"},
                            "target": {"type": "string"},
                            "priority": {"type": "integer"},
                            "reason": {"type": "string"}
                        },
                        "required": ["module", "target", "priority", "reason"]
                    }
                }
            },
            "required": ["actions"]
        })
    }

    fn report_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "summary": {"type": "string"},
                "findings": {"type": "array", "items": {"type": "string"}},
                "actions_taken": {"type": "array", "items": {"type": "string"}},
                "recommendations": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["title", "summary", "findings", "actions_taken", "recommendations"]
        })
    }
}

const SYSTEM_PROMPT: &str = r#"You are ICEBOX, an autonomous network security assessment agent.
You MUST analyze the real scan data provided in SCAN RESULTS. Do NOT fabricate data.

Rules:
1. Only target IPs/hosts the operator explicitly provides as in-scope.
2. Never recommend destructive actions (wipe, format, destroy, delete, shutdown).
3. Base ALL analysis and plans on the SCAN RESULTS section. If it says "NONE", report no data.
4. Always output valid JSON matching the requested schema.
5. Be concise and technical. Use exact module names from the scan list.
"#;

const ANALYSIS_PROMPT: &str = r#"Given the scan results above, analyze the target for potential vulnerabilities.
Output your analysis as JSON with:
- summary: brief finding
- vulnerabilities: list of potential vulnerabilities
- recommended_modules: which modules to run next
"#;

const PLAN_PROMPT: &str = r#"Based on the analysis, produce a prioritized plan of actions.
Each action runs a module against the target.
Output a JSON object with an "actions" array.
Each action has: module (name from registry), options (key-value), target (IP/host), priority (1-100), reason.
"#;

const REPORT_PROMPT: &str = r#"Summarize the complete assessment. Output JSON with:
- title: campaign title
- summary: key outcomes
- findings: list of findings
- actions_taken: what was run
- recommendations: next steps
"#;

#[async_trait::async_trait]
impl Planner for LlmPlanner {
    async fn analyze(&self, context: &str) -> anyhow::Result<AnalysisOutput> {
        let prompt = format!("{}\n\n{}", ANALYSIS_PROMPT, context);
        let reply = self
            .llm
            .prompt(
                &self.system_prompt(),
                &prompt,
                Some(Self::analysis_schema()),
            )
            .await?;
        let cleaned = clean_json(&reply);
        match serde_json::from_str::<AnalysisOutput>(&cleaned) {
            Ok(a) => Ok(a),
            Err(_) => {
                let raw = self
                    .llm
                    .prompt(&self.system_prompt(), &prompt, None)
                    .await?;
                let cleaned = clean_json(&raw);
                Ok(serde_json::from_str::<AnalysisOutput>(&cleaned)?)
            }
        }
    }

    async fn plan(&self, context: &str) -> anyhow::Result<Vec<Action>> {
        let prompt = format!("{}\n\n{}", PLAN_PROMPT, context);
        let reply = self
            .llm
            .prompt(&self.system_prompt(), &prompt, Some(Self::plan_schema()))
            .await?;
        let cleaned = clean_json(&reply);
        match serde_json::from_str::<PlanOutput>(&cleaned) {
            Ok(plan) => Ok(plan.actions),
            Err(_) => {
                // Fallback: ask without the JSON schema and extract the object.
                let raw = self
                    .llm
                    .prompt(&self.system_prompt(), &prompt, None)
                    .await?;
                let cleaned = clean_json(&raw);
                let plan: PlanOutput = serde_json::from_str(&cleaned)?;
                Ok(plan.actions)
            }
        }
    }

    async fn summarize(&self, context: &str) -> anyhow::Result<ReportOutput> {
        let prompt = format!("{}\n\n{}", REPORT_PROMPT, context);
        let reply = self
            .llm
            .prompt(&self.system_prompt(), &prompt, Some(Self::report_schema()))
            .await?;
        let cleaned = clean_json(&reply);
        match serde_json::from_str::<ReportOutput>(&cleaned) {
            Ok(r) => Ok(r),
            Err(_) => {
                let raw = self
                    .llm
                    .prompt(&self.system_prompt(), &prompt, None)
                    .await?;
                let cleaned = clean_json(&raw);
                Ok(serde_json::from_str::<ReportOutput>(&cleaned)?)
            }
        }
    }
}

// -- Agent --

pub struct Agent {
    planner: Box<dyn Planner>,
    fw: SharedFramework,
    phase: Phase,
    target: String,
    max_risk: RiskLevel,
    approved: bool,
    plan_approver: Option<Box<dyn PlanApprover>>,
    max_iterations: usize,
    max_context_chars: usize,
    job_ids: Vec<crate::core::job::JobId>,
    session_ids: Vec<SessionId>,
    logs: Vec<String>,
    scan_results: Vec<ScanFinding>,
    executed_results: Vec<ScanFinding>,
}

impl Agent {
    pub fn new(
        planner: Box<dyn Planner>,
        fw: SharedFramework,
        target: impl Into<String>,
        max_risk: RiskLevel,
    ) -> Self {
        Agent {
            planner,
            fw,
            phase: Phase::Idle,
            target: target.into(),
            max_risk,
            approved: false,
            plan_approver: None,
            max_iterations: 3,
            max_context_chars: 8000,
            job_ids: Vec::new(),
            session_ids: Vec::new(),
            logs: Vec::new(),
            scan_results: Vec::new(),
            executed_results: Vec::new(),
        }
    }

    pub fn set_approved(&mut self, v: bool) {
        self.approved = v;
    }

    pub fn set_plan_approver(&mut self, approver: Box<dyn PlanApprover>) {
        self.plan_approver = Some(approver);
    }

    /// Run the agent loop: Scan -> [Analyze -> Plan -> Execute]* -> Report.
    pub async fn run(&mut self) -> anyhow::Result<CampaignResult> {
        info!("agent: starting campaign against {}", self.target);
        self.phase = Phase::Scan;
        self.run_scan().await?;

        let mut iteration = 0usize;
        loop {
            self.phase = Phase::Analyze;
            self.run_analyze().await?;

            self.phase = Phase::Plan;
            let actions = self.run_plan().await?;

            // Plan gating (human-in-the-loop)
            let proceed = match &self.plan_approver {
                Some(approver) => approver.approve(&actions),
                None => true,
            };
            if !proceed {
                self.logs
                    .push("plan rejected by operator; stopping campaign".into());
                break;
            }
            if actions.is_empty() {
                self.logs
                    .push("plan: no actions generated; stopping".into());
                break;
            }

            self.phase = Phase::Execute;
            let before = self.scan_results.len() + self.executed_results.len();
            self.run_execute(actions).await?;
            let produced = (self.scan_results.len() + self.executed_results.len()) - before;

            iteration += 1;
            if iteration >= self.max_iterations {
                self.logs
                    .push(format!("reached max iterations ({})", self.max_iterations));
                break;
            }
            if produced == 0 {
                self.logs
                    .push("no new results this iteration; stopping".into());
                break;
            }
            self.logs.push(format!(
                "iteration {iteration} produced {produced} new result(s); re-analyzing"
            ));
        }

        self.phase = Phase::Report;
        let report = self.run_report().await?;

        self.phase = Phase::Done;
        Ok(CampaignResult {
            summary: report.summary.clone(),
            actions_taken: report.actions_taken.clone(),
            sessions_opened: self.session_ids.clone(),
            job_ids: self.job_ids.clone(),
            report: serde_json::to_string_pretty(&report).unwrap_or_default(),
        })
    }

    async fn run_scan(&mut self) -> anyhow::Result<()> {
        let entries = crate::modules::discover();
        let names: Vec<String> = entries.iter().map(|e| (e.info)().name.clone()).collect();

        let scanners: Vec<_> = entries
            .into_iter()
            .filter(|e| {
                let kind = (e.info)().kind;
                matches!(
                    kind,
                    crate::core::module::ModuleKind::Scanner
                        | crate::core::module::ModuleKind::Auxiliary
                )
            })
            .collect();

        if scanners.is_empty() {
            self.logs.push(format!(
                "scan: no scanner modules, available: {}",
                names.join(", ")
            ));
            return Ok(());
        }

        for entry in scanners {
            let info = (entry.info)();
            let mut loaded = crate::modules::load(&info.name).unwrap();
            if info.name == "tcp_port_scanner" {
                let _ = loaded.module.set_option("host", &self.target);
                let _ = loaded.module.set_option("ports", "1-1024");
            }
            if info.name == "http_probe" {
                let _ = loaded.module.set_option("host", &self.target);
                let _ = loaded.module.set_option("ports", "80,443,8080,8443,3000");
            }
            if info.name == "dns_resolver" {
                let _ = loaded.module.set_option("hostname", &self.target);
            }
            if info.name == "service_fingerprinter" {
                let _ = loaded.module.set_option("host", &self.target);
                let _ = loaded
                    .module
                    .set_option("ports", "22,80,443,3306,5432,6379,8080,8443");
            }
            let mut fw = self.fw.lock().await;
            let pf = fw.executor.preflight(
                &loaded,
                &self.target,
                None,
                self.approved,
                PolicyContext::Autonomous,
            );
            let policy = make_config_policy(
                self.max_risk,
                PolicyContext::Autonomous,
                &fw.executor.policy_set,
            );
            if pf.check(&policy).is_err() {
                self.logs
                    .push(format!("scan: {} preflight blocked, skipping", info.name));
                continue;
            }
            let job = Job::new(&info.name, &self.target);
            let jid = job.id;
            fw.jobs.register(job);
            self.job_ids.push(jid);
            match fw
                .executor
                .execute(
                    &loaded,
                    &self.target,
                    None,
                    self.approved,
                    PolicyContext::Autonomous,
                    Some(jid.as_u64()),
                    false,
                )
                .await
            {
                Ok(r) => {
                    fw.jobs.complete(jid, r.clone());
                    self.logs.push(format!("scan: {} completed", info.name));
                    self.scan_results.push(ScanFinding {
                        module: info.name.clone(),
                        finding: r.finding.clone(),
                        evidence: r.evidence.clone(),
                        data: r.data.clone(),
                    });
                }
                Err(e) => {
                    fw.jobs.cancel(jid);
                    self.logs.push(format!("scan: {} error: {e}", info.name));
                }
            }
        }
        Ok(())
    }

    async fn run_analyze(&mut self) -> anyhow::Result<()> {
        let context = self.build_context().await;
        let analysis = self.planner.analyze(&context).await?;
        self.logs.push(format!(
            "analysis: {}  -  vulns: {}",
            analysis.summary,
            analysis.vulnerabilities.join(", ")
        ));
        let mut fw = self.fw.lock().await;
        fw.executor.remember(
            MemoryKind::Decision,
            format!("analysis: {}", analysis.summary),
        );
        fw.executor.record_trace(ReasoningTrace {
            at: now_secs(),
            phase: "analyze".into(),
            context_len: context.len(),
            summary: analysis.summary.clone(),
            actions: analysis.vulnerabilities.clone(),
        });
        Ok(())
    }

    async fn run_plan(&mut self) -> anyhow::Result<Vec<Action>> {
        let context = self.build_context().await;
        let actions = self.planner.plan(&context).await?;
        self.logs
            .push(format!("plan: {} actions generated", actions.len()));
        let mut fw = self.fw.lock().await;
        fw.executor.record_trace(ReasoningTrace {
            at: now_secs(),
            phase: "plan".into(),
            context_len: context.len(),
            summary: format!("{} actions generated", actions.len()),
            actions: actions.iter().map(|a| a.module.clone()).collect(),
        });
        Ok(actions)
    }

    async fn run_execute(&mut self, actions: Vec<Action>) -> anyhow::Result<()> {
        for action in actions {
            let Some(loaded) = crate::modules::load(&action.module) else {
                self.logs
                    .push(format!("execute: module {} not found", action.module));
                continue;
            };
            self.logs.push(format!(
                "execute: {} -> {} ({})",
                action.module, action.target, action.reason
            ));

            // Apply options to loaded module.
            let mut loaded_mut = loaded;
            for (k, v) in &action.options {
                let _ = loaded_mut.module.set_option(k, v);
            }

            let mut fw = self.fw.lock().await;
            let pf = fw.executor.preflight(
                &loaded_mut,
                &self.target,
                None,
                self.approved,
                PolicyContext::Autonomous,
            );
            let policy = make_config_policy(
                self.max_risk,
                PolicyContext::Autonomous,
                &fw.executor.policy_set,
            );
            if let Err(e) = pf.check(&policy) {
                self.logs.push(format!("execute: preflight blocked: {e}"));
                continue;
            }

            let job = Job::new(&action.module, &self.target);
            let jid = job.id;
            fw.jobs.register(job);
            self.job_ids.push(jid);

            match fw
                .executor
                .execute(
                    &loaded_mut,
                    &self.target,
                    None,
                    self.approved,
                    PolicyContext::Autonomous,
                    Some(jid.as_u64()),
                    false,
                )
                .await
            {
                Ok(r) => {
                    fw.jobs.complete(jid, r.clone());
                    self.executed_results.push(ScanFinding {
                        module: action.module.clone(),
                        finding: r.finding.clone(),
                        evidence: r.evidence.clone(),
                        data: r.data.clone(),
                    });
                    let outcome = r
                        .finding
                        .clone()
                        .unwrap_or_else(|| "no finding".to_string());
                    fw.executor.remember(
                        MemoryKind::Decision,
                        format!("executed {}: {}", action.module, outcome),
                    );
                    if let Some(ref sid) = r.session_id {
                        let kind = if sid.starts_with("session:") {
                            SessionKind::Shell
                        } else {
                            SessionKind::Unknown
                        };
                        let sid2 =
                            fw.sessions
                                .register(Session::new(kind, &self.target, &action.module));
                        self.session_ids.push(sid2);
                    }
                }
                Err(e) => {
                    fw.jobs.cancel(jid);
                    fw.executor.remember(
                        MemoryKind::Failure,
                        format!("{} failed: {e}", action.module),
                    );
                    self.logs
                        .push(format!("execute: {} error: {e}", action.module));
                }
            }
        }
        let modules: Vec<String> = self
            .executed_results
            .iter()
            .map(|r| r.module.clone())
            .collect();
        let mut fw = self.fw.lock().await;
        fw.executor.record_trace(ReasoningTrace {
            at: now_secs(),
            phase: "execute".into(),
            context_len: 0,
            summary: format!("executed {} action(s)", modules.len()),
            actions: modules,
        });
        Ok(())
    }

    async fn run_report(&mut self) -> anyhow::Result<ReportOutput> {
        let context = self.build_context().await;
        let report = self.planner.summarize(&context).await?;
        let mut fw = self.fw.lock().await;
        fw.executor.record_trace(ReasoningTrace {
            at: now_secs(),
            phase: "report".into(),
            context_len: context.len(),
            summary: report.summary.clone(),
            actions: report.recommendations.clone(),
        });
        Ok(report)
    }

    async fn build_context(&self) -> String {
        let mut ctx = format!(
            "Target: {}\nPhase: {}\n\n",
            self.target,
            self.phase.as_str()
        );

        // Structured scan results — only real data about the target.
        if self.scan_results.is_empty() {
            ctx.push_str("Initial Scan Results: NONE\n");
        } else {
            ctx.push_str("=== INITIAL SCAN RESULTS (real data about the target) ===\n");
            for sr in &self.scan_results {
                ctx.push_str(&format!(
                    "  module: {}\n  finding: {}\n  evidence: {:?}\n  data: {}\n\n",
                    sr.module,
                    sr.finding.as_deref().unwrap_or("(none)"),
                    sr.evidence,
                    sr.data
                ));
            }
        }

        if !self.executed_results.is_empty() {
            ctx.push_str("=== EXECUTED ACTIONS (results from prior plan steps) ===\n");
            for sr in &self.executed_results {
                ctx.push_str(&format!(
                    "  module: {}\n  finding: {}\n  evidence: {:?}\n  data: {}\n\n",
                    sr.module,
                    sr.finding.as_deref().unwrap_or("(none)"),
                    sr.evidence,
                    sr.data
                ));
            }
        }

        let fw = self.fw.lock().await;
        let jobs: Vec<String> = fw
            .jobs
            .list_recent(20)
            .iter()
            .map(|j| {
                format!(
                    "job {}: {} {} -> {}",
                    j.id,
                    j.module_name,
                    j.target,
                    j.status.as_str()
                )
            })
            .collect();
        ctx.push_str(&format!("Jobs:\n{}\n", jobs.join("\n")));

        let sessions: Vec<String> = fw
            .sessions
            .list()
            .iter()
            .map(|s| format!("session {}: {} {}", s.id, s.kind.as_str(), s.target))
            .collect();
        ctx.push_str(&format!("Sessions:\n{}\n", sessions.join("\n")));

        let memories: Vec<String> = fw
            .executor
            .recent_memories(20)
            .iter()
            .map(|m| format!("[{}] {}", m.kind.as_str(), m.text))
            .collect();
        if !memories.is_empty() {
            ctx.push_str(&format!(
                "Memory (planner learnings):\n{}\n",
                memories.join("\n")
            ));
        }

        if !self.logs.is_empty() {
            let recent: Vec<String> = self.logs.iter().rev().take(40).rev().cloned().collect();
            ctx.push_str(&format!("Logs (last 40):\n{}\n", recent.join("\n")));
        }

        // Truncate context to cap — keep header and tail, drop bulky middle.
        if ctx.len() > self.max_context_chars {
            if let Some(pos) = ctx.find("\n\n=== EXECUTED") {
                let prefix = &ctx[..pos];
                let suffix = &ctx[pos..];
                let kept = if suffix.len() > self.max_context_chars {
                    let start = suffix.len() - self.max_context_chars + 500;
                    format!("\n\n[... context truncated ...]\n{}", &suffix[start..])
                } else {
                    suffix.to_string()
                };
                return format!("{prefix}{kept}");
            }
            let start = ctx.len().saturating_sub(self.max_context_chars);
            format!("[... context truncated ...]\n{}", &ctx[start..])
        } else {
            ctx
        }
    }
}

#[derive(Debug, Clone)]
pub struct CampaignResult {
    pub summary: String,
    pub actions_taken: Vec<String>,
    pub sessions_opened: Vec<SessionId>,
    pub job_ids: Vec<crate::core::job::JobId>,
    pub report: String,
}

/// Strip markdown code fences from LLM output that wraps JSON.
fn clean_json(raw: &str) -> String {
    let raw = raw.trim();
    if let Some(s) = raw.strip_prefix("```json") {
        if let Some(end) = s.rfind("```") {
            return s[..end].trim().to_string();
        }
    }
    if let Some(s) = raw.strip_prefix("```") {
        if let Some(end) = s.rfind("```") {
            return s[..end].trim().to_string();
        }
    }
    raw.to_string()
}
