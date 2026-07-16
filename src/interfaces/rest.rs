//! REST API surface for the ICEBOX Framework.

use std::net::SocketAddr;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

use crate::ai::agent::{Agent, LlmPlanner};
use crate::ai::Orchestrator;
use crate::core::framework::SharedFramework;
use crate::core::governance::{
    audit_to_csv, role_allows, ApprovalRequest, ApprovalStatus, PolicyPack, Role,
};
use crate::core::job::Job;
use crate::core::safety::{
    Charter, DecisionRecord, Evidence, MemoryEntry, PolicyContext, PolicyDecision, PolicyEngine,
    PolicyRule, PolicySet, Preflight, ReasoningTrace, RiskLevel,
};
use crate::core::session::{Session, SessionId, SessionKind};
use crate::core::workspace::WorkspaceSnapshot;

#[derive(Serialize)]
struct ModuleItem {
    name: String,
    kind: String,
    description: String,
}

#[derive(Serialize)]
struct ModuleDetail {
    name: String,
    kind: String,
    description: String,
    author: String,
    options: serde_json::Value,
    target: Option<String>,
    in_scope: Option<bool>,
    charter_accepted: bool,
}

#[derive(Deserialize)]
struct SetPayload {
    key: String,
    value: String,
}

#[derive(Deserialize, Default)]
struct RunPayload {
    target: String,
    #[serde(default)]
    approved: bool,
    #[serde(default)]
    sandbox: bool,
    #[serde(default)]
    options: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Serialize)]
struct RunResponse {
    job_id: u64,
    session_id: Option<String>,
    success: bool,
    data: serde_json::Value,
    preflight: Option<PreflightReport>,
    error: Option<String>,
}

#[derive(Serialize)]
struct PreflightReport {
    in_scope: bool,
    charter_accepted: bool,
    risk: String,
    destructive: bool,
    approved: bool,
    passed: bool,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct CharterPayload {
    engagement: String,
}

#[derive(Serialize)]
struct CharterStatus {
    accepted: bool,
    engagement: String,
}

#[derive(Deserialize)]
struct ScopePayload {
    target: String,
}

#[derive(Serialize)]
struct SessionItem {
    id: u64,
    kind: String,
    target: String,
    module: String,
    elapsed_secs: u64,
}

#[derive(Deserialize)]
struct AgentRunPayload {
    target: String,
    model: Option<String>,
    #[serde(default)]
    approve: bool,
}

#[derive(Deserialize)]
struct OrchestratePayload {
    targets: Vec<String>,
    model: Option<String>,
    #[serde(default)]
    approve: bool,
}

#[derive(Serialize)]
struct AgentRunResponse {
    summary: String,
    actions_taken: Vec<String>,
    sessions_opened: Vec<u64>,
    job_ids: Vec<u64>,
    report: String,
}

#[derive(Serialize)]
struct JobItem {
    id: u64,
    module: String,
    target: String,
    status: String,
    elapsed_secs: u64,
}

#[derive(Deserialize)]
struct PolicyQuery {
    module: Option<String>,
    target: Option<String>,
}

#[derive(Deserialize)]
struct AuditQuery {
    n: Option<usize>,
    format: Option<String>,
}

#[derive(Deserialize)]
struct EvidenceQuery {
    n: Option<usize>,
    #[serde(default)]
    min_confidence: Option<f64>,
    kind: Option<String>,
}

pub async fn serve(fw: SharedFramework, addr: SocketAddr) -> anyhow::Result<()> {
    // Each route delegates to a handler; CORS is permissive because the API is
    // meant for local tooling and the agent, not public network exposure.
    let app = Router::new()
        .route("/api/v1/modules", get(list_modules))
        .route("/api/v1/modules/{name}", get(get_module))
        .route("/api/v1/modules/{name}/set", post(set_option))
        .route("/api/v1/modules/{name}/run", post(run_module))
        .route("/api/v1/sessions", get(list_sessions))
        .route("/api/v1/sessions/{id}/close", post(close_session))
        .route("/api/v1/jobs", get(list_jobs))
        .route("/api/v1/agent/run", post(run_agent))
        .route("/api/v1/orchestrate", post(run_orchestrate))
        .route("/api/v1/charter", get(get_charter).post(accept_charter))
        .route("/api/v1/scope", get(get_scope).post(add_scope))
        .route("/api/v1/policy", get(evaluate_policy))
        .route(
            "/api/v1/policy/rules",
            get(list_policy_rules)
                .post(add_policy_rule)
                .put(replace_policy_rules),
        )
        .route("/api/v1/policy/rules/{index}", delete(delete_policy_rule))
        .route("/api/v1/workspace/save", post(save_workspace))
        .route("/api/v1/workspace/load", post(load_workspace))
        .route("/api/v1/audit", get(list_audit))
        .route("/api/v1/audit/export", get(export_audit))
        .route(
            "/api/v1/policy/packs",
            get(list_policy_packs).post(add_policy_pack),
        )
        .route("/api/v1/policy/pack/{name}/apply", post(apply_policy_pack))
        .route(
            "/api/v1/approvals",
            get(list_approvals).post(request_approval),
        )
        .route("/api/v1/approvals/{id}/approve", post(approve_approval))
        .route("/api/v1/approvals/{id}/deny", post(deny_approval))
        .route("/api/v1/role", get(get_role).post(set_role))
        .route("/api/v1/evidence", get(list_evidence))
        .route("/api/v1/traces", get(list_traces))
        .route("/api/v1/memory", get(list_memory))
        .layer(CorsLayer::permissive())
        .with_state(fw);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("REST API listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

fn to_preflight_report(pf: &Preflight, policy: &dyn PolicyEngine) -> PreflightReport {
    let check = pf.check(policy);
    PreflightReport {
        in_scope: pf.in_scope,
        charter_accepted: pf.charter_accepted,
        risk: pf.risk.as_str().into(),
        destructive: pf.destructive,
        approved: pf.approved,
        passed: check.is_ok(),
        reason: check.err().map(|e| e.to_string()),
    }
}

async fn list_modules(State(_fw): State<SharedFramework>) -> Json<Vec<ModuleItem>> {
    let items = crate::modules::discover()
        .into_iter()
        .map(|e| {
            let i = (e.info)();
            ModuleItem {
                name: i.name,
                kind: i.kind.as_str().into(),
                description: i.description,
            }
        })
        .collect();
    Json(items)
}

async fn get_module(
    State(fw): State<SharedFramework>,
    Path(name): Path<String>,
) -> Json<Option<ModuleDetail>> {
    let fw = fw.lock().await;
    let loaded = match crate::modules::load(&name) {
        Some(l) => l,
        None => return Json(None),
    };
    let pf = fw
        .executor
        .preflight(&loaded, "", None, false, PolicyContext::Rest);
    Json(Some(ModuleDetail {
        name: loaded.info.name.clone(),
        kind: loaded.info.kind.as_str().into(),
        description: loaded.info.description.clone(),
        author: loaded.info.author.clone(),
        options: loaded.module.options_json(),
        target: None,
        in_scope: None,
        charter_accepted: pf.charter_accepted,
    }))
}

async fn set_option(
    State(_fw): State<SharedFramework>,
    Path(name): Path<String>,
    Json(payload): Json<SetPayload>,
) -> Json<Result<String, String>> {
    let Some(mut loaded) = crate::modules::load(&name) else {
        return Json(Err("module not found".into()));
    };
    match loaded.module.set_option(&payload.key, &payload.value) {
        Ok(_) => Json(Ok(format!("{}={}", payload.key, payload.value))),
        Err(e) => Json(Err(e.to_string())),
    }
}

async fn run_module(
    State(fw): State<SharedFramework>,
    Path(name): Path<String>,
    Json(payload): Json<RunPayload>,
) -> Json<RunResponse> {
    let Some(mut loaded) = crate::modules::load(&name) else {
        return Json(RunResponse {
            job_id: 0,
            session_id: None,
            success: false,
            data: serde_json::Value::Null,
            preflight: None,
            error: Some("module not found".into()),
        });
    };

    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Operator) {
        return Json(RunResponse {
            job_id: 0,
            session_id: None,
            success: false,
            data: serde_json::Value::Null,
            preflight: None,
            error: Some("forbidden: operator role required".into()),
        });
    }
    for (k, v) in &payload.options {
        let s = match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let _ = loaded.module.set_option(k, &s);
    }
    let pf = fw.executor.preflight(
        &loaded,
        &payload.target,
        None,
        payload.approved,
        PolicyContext::Rest,
    );
    let policy = fw.executor.policy(PolicyContext::Rest);
    let report = to_preflight_report(&pf, &policy);
    if let Err(ref e) = pf.check(&policy) {
        return Json(RunResponse {
            job_id: 0,
            session_id: None,
            success: false,
            data: serde_json::Value::Null,
            preflight: Some(report),
            error: Some(e.to_string()),
        });
    }

    let job = Job::new(&loaded.info.name, &payload.target);
    let job_id = job.id;
    fw.jobs.register(job);

    let result = fw
        .executor
        .execute(
            &loaded,
            &payload.target,
            None,
            payload.approved,
            PolicyContext::Rest,
            Some(job_id.as_u64()),
            payload.sandbox,
        )
        .await;

    match result {
        Ok(r) => {
            fw.jobs.complete(job_id, r.clone());
            let mut sid = None;
            if let Some(ref s) = r.session_id {
                let kind = if s.starts_with("session:") {
                    SessionKind::Shell
                } else {
                    SessionKind::Unknown
                };
                let new_sid =
                    fw.sessions
                        .register(Session::new(kind, &payload.target, &loaded.info.name));
                sid = Some(new_sid.to_string());
            }
            Json(RunResponse {
                job_id: job_id.as_u64(),
                session_id: sid,
                success: r.success,
                data: r.data.clone(),
                preflight: Some(report),
                error: None,
            })
        }
        Err(e) => {
            fw.jobs.cancel(job_id);
            Json(RunResponse {
                job_id: job_id.as_u64(),
                session_id: None,
                success: false,
                data: serde_json::Value::Null,
                preflight: Some(report),
                error: Some(e.to_string()),
            })
        }
    }
}

async fn run_agent(
    State(fw): State<SharedFramework>,
    Json(payload): Json<AgentRunPayload>,
) -> Json<AgentRunResponse> {
    let model = payload.model.unwrap_or_else(|| "llama3.2".into());
    if !role_allows(fw.lock().await.operator_role, Role::Operator) {
        return Json(AgentRunResponse {
            summary: "forbidden: operator role required".into(),
            actions_taken: vec![],
            sessions_opened: vec![],
            job_ids: vec![],
            report: String::new(),
        });
    }
    let planner = Box::new(LlmPlanner::new(&model));
    let mut agent = Agent::new(planner, fw, payload.target.clone(), RiskLevel::High);
    agent.set_approved(true);
    // When approve=false the plan is gated through AlwaysApprove=false so the
    // campaign stops before Execute; when true, plans auto-execute.
    if payload.approve {
        agent.set_plan_approver(Box::new(crate::ai::agent::AlwaysApprove));
    } else {
        agent.set_plan_approver(Box::new(crate::ai::agent::DenyPlan));
    }
    match agent.run().await {
        Ok(cr) => Json(AgentRunResponse {
            summary: cr.summary,
            actions_taken: cr.actions_taken,
            sessions_opened: cr.sessions_opened.iter().map(|s| s.as_u64()).collect(),
            job_ids: cr.job_ids.iter().map(|j| j.as_u64()).collect(),
            report: cr.report,
        }),
        Err(e) => Json(AgentRunResponse {
            summary: format!("error: {e}"),
            actions_taken: vec![],
            sessions_opened: vec![],
            job_ids: vec![],
            report: String::new(),
        }),
    }
}

async fn run_orchestrate(
    State(fw): State<SharedFramework>,
    Json(payload): Json<OrchestratePayload>,
) -> Json<crate::ai::CampaignReport> {
    let model = payload.model.unwrap_or_else(|| "llama3.2".into());
    if !role_allows(fw.lock().await.operator_role, Role::Operator) {
        return Json(crate::ai::CampaignReport {
            targets: payload.targets.clone(),
            summaries: vec!["forbidden: operator role required".into()],
            ok: 0,
            failed: 0,
            total_jobs: 0,
            total_sessions: 0,
            total_decisions: 0,
            total_evidence: 0,
            total_traces: 0,
        });
    }
    let mut orch = Orchestrator::new(fw, RiskLevel::High);
    orch.set_approved(payload.approve);
    Json(
        orch.run(&payload.targets, move || {
            Box::new(LlmPlanner::new(model.clone()))
        })
        .await,
    )
}

async fn list_sessions(State(fw): State<SharedFramework>) -> Json<Vec<SessionItem>> {
    let fw = fw.lock().await;
    Json(
        fw.sessions
            .list()
            .into_iter()
            .map(|s| SessionItem {
                id: s.id.as_u64(),
                kind: s.kind.as_str().into(),
                target: s.target.clone(),
                module: s.module_name.clone(),
                elapsed_secs: s.elapsed().as_secs(),
            })
            .collect(),
    )
}

async fn close_session(State(fw): State<SharedFramework>, Path(id): Path<u64>) -> Json<bool> {
    let mut fw = fw.lock().await;
    Json(fw.sessions.close(SessionId(id)))
}

async fn list_jobs(State(fw): State<SharedFramework>) -> Json<Vec<JobItem>> {
    let fw = fw.lock().await;
    Json(
        fw.jobs
            .list_recent(50)
            .into_iter()
            .map(|j| JobItem {
                id: j.id.as_u64(),
                module: j.module_name.clone(),
                target: j.target.clone(),
                status: j.status.as_str().into(),
                elapsed_secs: j.elapsed().as_secs(),
            })
            .collect(),
    )
}

async fn get_charter(State(fw): State<SharedFramework>) -> Json<CharterStatus> {
    let fw = fw.lock().await;
    Json(CharterStatus {
        accepted: fw.executor.charter.accepted,
        engagement: fw.executor.charter.engagement.clone(),
    })
}

async fn accept_charter(
    State(fw): State<SharedFramework>,
    Json(payload): Json<CharterPayload>,
) -> Json<String> {
    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Operator) {
        return Json("forbidden: operator role required".into());
    }
    fw.executor.charter = Charter::accept(payload.engagement.clone(), vec![]);
    Json("accepted".into())
}

async fn get_scope(State(fw): State<SharedFramework>) -> Json<Vec<String>> {
    let fw = fw.lock().await;
    Json(fw.executor.scope.allow.clone())
}

async fn add_scope(
    State(fw): State<SharedFramework>,
    Json(payload): Json<ScopePayload>,
) -> Json<String> {
    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Operator) {
        return Json("forbidden: operator role required".into());
    }
    fw.executor.scope.allow.push(payload.target);
    Json("added".into())
}

async fn evaluate_policy(
    State(fw): State<SharedFramework>,
    Query(params): Query<PolicyQuery>,
) -> Json<serde_json::Value> {
    let fw = fw.lock().await;
    // No module -> return the active policy set itself.
    let module = params.module.clone().unwrap_or_default();
    if module.is_empty() {
        return Json(
            serde_json::to_value(&fw.executor.policy_set).unwrap_or(serde_json::Value::Null),
        );
    }
    let Some(loaded) = crate::modules::load(&module) else {
        return Json(serde_json::json!({
            "module": module,
            "target": params.target.unwrap_or_default(),
            "decision": "deny",
            "reason": "module not found",
            "in_scope": false,
            "charter_accepted": fw.executor.charter.accepted,
        }));
    };
    let target = params.target.unwrap_or_default();
    let pf = fw
        .executor
        .preflight(&loaded, &target, None, false, PolicyContext::Rest);
    let policy = fw.executor.policy(PolicyContext::Rest);
    let decision = policy.evaluate(&pf.to_request());
    Json(serde_json::json!({
        "module": loaded.info.name,
        "target": target,
        "capabilities": pf.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        "intents": pf.capabilities.iter().map(|c| c.intent().as_str()).collect::<Vec<_>>(),
        "impact": pf.risk.as_str(),
        "decision": match &decision {
            PolicyDecision::Allow => "allow",
            PolicyDecision::RequireApproval(_) => "require_approval",
            PolicyDecision::Deny(_) => "deny",
        },
        "reason": decision.reason().map(|s| s.to_string()),
        "in_scope": pf.in_scope,
        "charter_accepted": pf.charter_accepted,
    }))
}

async fn list_audit(
    State(fw): State<SharedFramework>,
    Query(params): Query<AuditQuery>,
) -> Json<Vec<DecisionRecord>> {
    let fw = fw.lock().await;
    Json(fw.executor.recent_decisions(params.n.unwrap_or(20)))
}

async fn list_evidence(
    State(fw): State<SharedFramework>,
    Query(params): Query<EvidenceQuery>,
) -> Json<Vec<Evidence>> {
    let fw = fw.lock().await;
    let mut ev: Vec<Evidence> = fw.executor.recent_evidence(params.n.unwrap_or(200));
    if let Some(min) = params.min_confidence {
        ev.retain(|e| e.confidence >= min);
    }
    if let Some(kind) = &params.kind {
        ev.retain(|e| e.kind.as_deref() == Some(kind.as_str()));
    }
    Json(ev)
}

async fn list_policy_rules(State(fw): State<SharedFramework>) -> Json<PolicySet> {
    let fw = fw.lock().await;
    Json(fw.executor.policy_set.clone())
}

async fn add_policy_rule(
    State(fw): State<SharedFramework>,
    Json(rule): Json<PolicyRule>,
) -> Json<PolicySet> {
    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Operator) {
        return Json(fw.executor.policy_set.clone());
    }
    fw.executor.policy_set.add_rule(rule);
    Json(fw.executor.policy_set.clone())
}

async fn replace_policy_rules(
    State(fw): State<SharedFramework>,
    Json(rules): Json<Vec<PolicyRule>>,
) -> Json<PolicySet> {
    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Operator) {
        return Json(fw.executor.policy_set.clone());
    }
    fw.executor.policy_set.set_rules(rules);
    Json(fw.executor.policy_set.clone())
}

async fn delete_policy_rule(
    State(fw): State<SharedFramework>,
    Path(index): Path<usize>,
) -> Result<Json<PolicySet>, StatusCode> {
    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Operator) {
        return Err(StatusCode::FORBIDDEN);
    }
    match fw.executor.policy_set.remove_rule(index) {
        Some(_) => Ok(Json(fw.executor.policy_set.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
struct WorkspacePath {
    path: String,
}

async fn save_workspace(
    State(fw): State<SharedFramework>,
    Json(p): Json<WorkspacePath>,
) -> Result<Json<String>, StatusCode> {
    let fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Operator) {
        return Err(StatusCode::FORBIDDEN);
    }
    let snap = WorkspaceSnapshot::from_framework(&fw);
    snap.save_to_file(&p.path).map_err(|e| {
        eprintln!("workspace save error: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(format!("saved to {}", p.path)))
}

async fn load_workspace(
    State(fw): State<SharedFramework>,
    Json(p): Json<WorkspacePath>,
) -> Result<Json<String>, StatusCode> {
    let snap = WorkspaceSnapshot::load_from_file(&p.path).map_err(|e| {
        eprintln!("workspace load error: {e}");
        StatusCode::BAD_REQUEST
    })?;
    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Operator) {
        return Err(StatusCode::FORBIDDEN);
    }
    snap.apply_to_framework(&mut fw);
    Ok(Json(format!("loaded from {}", p.path)))
}

async fn export_audit(
    State(fw): State<SharedFramework>,
    Query(params): Query<AuditQuery>,
) -> Response {
    let fw = fw.lock().await;
    let records = fw.executor.recent_decisions(params.n.unwrap_or(200));
    if params.format.as_deref() == Some("csv") {
        ([(header::CONTENT_TYPE, "text/csv")], audit_to_csv(&records)).into_response()
    } else {
        Json(records).into_response()
    }
}

async fn list_policy_packs(State(fw): State<SharedFramework>) -> Json<Vec<PolicyPack>> {
    let fw = fw.lock().await;
    Json(fw.policy_packs.values().cloned().collect())
}

async fn add_policy_pack(
    State(fw): State<SharedFramework>,
    Json(pack): Json<PolicyPack>,
) -> Result<Json<PolicyPack>, StatusCode> {
    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }
    fw.policy_packs.insert(pack.name.clone(), pack.clone());
    Ok(Json(pack))
}

async fn apply_policy_pack(
    State(fw): State<SharedFramework>,
    Path(name): Path<String>,
) -> Result<Json<PolicySet>, StatusCode> {
    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }
    let pack = match fw.policy_packs.get(&name) {
        Some(p) => p.clone(),
        None => return Err(StatusCode::NOT_FOUND),
    };
    fw.executor.policy_set.set_rules(pack.rules.clone());
    Ok(Json(fw.executor.policy_set.clone()))
}

async fn list_approvals(State(fw): State<SharedFramework>) -> Json<Vec<ApprovalRequest>> {
    let fw = fw.lock().await;
    Json(fw.approval_queue.list())
}

#[derive(Deserialize)]
struct ApprovalRequestInput {
    module: String,
    target: String,
    reason: String,
    #[serde(default)]
    options: std::collections::HashMap<String, String>,
}

async fn request_approval(
    State(fw): State<SharedFramework>,
    Json(input): Json<ApprovalRequestInput>,
) -> Json<ApprovalRequest> {
    let mut fw = fw.lock().await;
    let id = fw
        .approval_queue
        .request(input.module, input.target, input.reason, input.options);
    Json(fw.approval_queue.get(id).cloned().unwrap())
}

async fn approve_approval(
    State(fw): State<SharedFramework>,
    Path(id): Path<u64>,
) -> Result<Json<String>, StatusCode> {
    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Operator) {
        return Err(StatusCode::FORBIDDEN);
    }
    let req = match fw.approval_queue.get(id) {
        Some(r) if r.status == ApprovalStatus::Pending => r.clone(),
        _ => return Err(StatusCode::NOT_FOUND),
    };
    fw.approval_queue.approve(id);
    let mut loaded = match crate::modules::load(&req.module) {
        Some(l) => l,
        None => return Err(StatusCode::BAD_REQUEST),
    };
    for (k, v) in &req.options {
        let _ = loaded.module.set_option(k, v);
    }
    match fw
        .executor
        .execute(
            &loaded,
            &req.target,
            None,
            true,
            PolicyContext::Rest,
            None,
            false,
        )
        .await
    {
        Ok(_) => Ok(Json(format!("request {id} approved and executed"))),
        Err(e) => Ok(Json(format!(
            "request {id} approved but execution failed: {e}"
        ))),
    }
}

async fn deny_approval(
    State(fw): State<SharedFramework>,
    Path(id): Path<u64>,
) -> Result<Json<String>, StatusCode> {
    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Operator) {
        return Err(StatusCode::FORBIDDEN);
    }
    if fw.approval_queue.deny(id) {
        Ok(Json(format!("request {id} denied")))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn get_role(State(fw): State<SharedFramework>) -> Json<Role> {
    let fw = fw.lock().await;
    Json(fw.operator_role)
}

#[derive(Deserialize)]
struct RolePayload {
    role: Role,
}

async fn set_role(
    State(fw): State<SharedFramework>,
    Json(payload): Json<RolePayload>,
) -> Result<Json<Role>, StatusCode> {
    let mut fw = fw.lock().await;
    if !role_allows(fw.operator_role, Role::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }
    fw.operator_role = payload.role;
    Ok(Json(fw.operator_role))
}

async fn list_traces(State(fw): State<SharedFramework>) -> Json<Vec<ReasoningTrace>> {
    let fw = fw.lock().await;
    Json(fw.executor.recent_traces(50))
}

async fn list_memory(State(fw): State<SharedFramework>) -> Json<Vec<MemoryEntry>> {
    let fw = fw.lock().await;
    Json(fw.executor.recent_memories(50))
}
