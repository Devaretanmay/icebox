use std::sync::Arc;
use tokio::sync::Mutex;

const COLOR_ORANGE: &str = "\x1b[38;2;232;84;42m";
const COLOR_TEAL: &str = "\x1b[38;2;46;140;147m";
const COLOR_SLATE: &str = "\x1b[38;2;74;92;104m";
const COLOR_RESET: &str = "\x1b[0m";

use icebox::core::executor::ModuleExecutor;
use icebox::core::framework::{new_shared_framework, Framework, SharedFramework};
use icebox::core::governance::{audit_to_csv, role_allows, PolicyPack, Role};
use icebox::core::job::Job;
use icebox::core::module::LoadedModule;
use icebox::core::safety::{
    Charter, PolicyContext, PolicyDecision, PolicyEngine, PolicyRule, RiskLevel, ScopeManager,
};
use icebox::core::session::{Session, SessionId, SessionKind};
use icebox::core::Capability;

struct CliState {
    fw: SharedFramework,
    loaded: Option<LoadedModule>,
    target: Option<String>,
}

async fn run_worker(args: &[String]) -> anyhow::Result<()> {
    if !std::path::Path::new("/.dockerenv").exists() {
        eprintln!("fatal: worker must be run inside the ICEBOX sandbox");
        std::process::exit(1);
    }
    let mut name = None;
    let mut target = String::new();
    let mut options = serde_json::Value::Null;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--module" => name = it.next().cloned(),
            "--target" => target = it.next().cloned().unwrap_or_default(),
            "--options" => {
                options = it
                    .next()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(serde_json::Value::Null)
            }
            _ => {}
        }
    }
    let Some(name) = name else {
        eprintln!("worker: --module required");
        std::process::exit(2);
    };
    let Some(mut loaded) = icebox::modules::load(&name) else {
        eprintln!("worker: module not found: {name}");
        std::process::exit(2);
    };
    if let Some(obj) = options.as_object() {
        for (k, v) in obj {
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let _ = loaded.module.set_option(k, &s);
        }
    }
    if !target.is_empty() {
        let _ = loaded.module.set_option("target", &target);
    }
    match loaded.module.run().await {
        Ok(r) => {
            println!("{}", serde_json::to_string(&r).unwrap_or_default());
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("worker: run error: {e}");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("icebox {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("ICEBOX - governance kernel for security tooling");
        println!();
        println!("USAGE:");
        println!("  icebox            Start interactive REPL + REST API (http://127.0.0.1:8443)");
        println!("  icebox --api     Start the REST API only");
        println!("  icebox --no-auth Start without REST authentication (local dev only)");
        println!("  icebox --auth-token <t>  Use explicit REST auth token");
        println!("  icebox --version  Print version and exit");
        println!("  icebox --help     Show this help and exit");
        return Ok(());
    }
    if let Some(pos) = args.iter().position(|a| a == "worker") {
        return run_worker(&args[pos + 1..]).await;
    }
    let api_only = args.iter().any(|a| a == "--api");
    let no_auth = args.iter().any(|a| a == "--no-auth");
    let auth_token = args
        .iter()
        .position(|a| a == "--auth-token")
        .and_then(|i| args.get(i + 1).cloned());
    let auth = icebox::interfaces::rest::resolve_auth(no_auth, auth_token);
    let fw = new_shared_framework(ModuleExecutor::new(
        Charter::default(),
        ScopeManager::default(),
        RiskLevel::Critical,
    ));
    let state = Arc::new(Mutex::new(CliState {
        fw: fw.clone(),
        loaded: None,
        target: None,
    }));

    let fw_api = fw.clone();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8443));
    let api_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("API rt");
        rt.block_on(async { icebox::interfaces::rest::serve(fw_api, addr, auth).await })
    });
    if no_auth {
        eprintln!("REST API http://{addr}/api/v1  (AUTH DISABLED --no-auth)");
    } else {
        eprintln!("REST API http://{addr}/api/v1  (Bearer token in ~/.icebox/auth.token)");
    }

    if api_only {
        std::thread::sleep(std::time::Duration::from_millis(200));
        api_handle.join().map_err(|_| anyhow::anyhow!("API thread panicked"))??;
        return Ok(());
    }

    let mut buf = String::new();
    loop {
        buf.clear();
        eprint!("{COLOR_SLATE}icebox>{COLOR_RESET} ");
        if std::io::stdin().read_line(&mut buf)? == 0 {
            break;
        }
        let t = buf.trim();
        if t.is_empty() {
            continue;
        }
        let p: Vec<&str> = t.split_whitespace().collect();
        let c = p[0].to_ascii_lowercase();
        let a = &p[1..];
        let mut s = state.lock().await;
        let fw_arc = s.fw.clone();
        if matches!(
            c.as_str(),
            "agent" | "save" | "load" | "validate" | "role" | "pack" | "approve" | "campaign"
                | "proxy" | "tier"
        ) {
            drop(s);
            match c.as_str() {
                "agent" => cmd_agent(a, fw_arc.clone()).await,
                "campaign" => cmd_campaign(a, fw_arc.clone()).await,
                "save" => cmd_save(a, fw_arc.clone()).await,
                "load" => cmd_load(a, fw_arc.clone()).await,
                "validate" => cmd_validate(a, fw_arc.clone()).await,
                "role" => cmd_role(a, fw_arc.clone()).await,
                "pack" => cmd_pack(a, fw_arc.clone()).await,
                "approve" => cmd_approve(a, fw_arc.clone()).await,
                "proxy" => cmd_proxy(a, fw_arc.clone()).await,
                "tier" => cmd_tier(a, fw_arc.clone()).await,
                _ => unreachable!(),
            }
        } else {
            let mut fw = fw_arc.lock().await;
            let fw: &mut Framework = &mut fw;
            match c.as_str() {
                "help" | "?" => println!("Commands: help list use info set show charter scope run sessions jobs agent campaign validate save load policy audit evidence traces memory role pack approve proxy tier\nREST API on http://127.0.0.1:8443/api/v1"),
                "exit" | "quit" => std::process::exit(0),
                "list" => cmd_list().await,
                "use" => cmd_use(a, &mut s, fw).await,
                "info" => cmd_info(&s),
                "set" => cmd_set(a, &mut s),
                "show" => cmd_show(a, &s),
                "charter" => cmd_charter(a, fw),
                "scope" => cmd_scope(a, fw),
                "sessions" => cmd_sessions(a, fw),
                "jobs" => cmd_jobs(a, fw),
                "run" => cmd_run(a, &mut s, fw).await,
                "policy" => cmd_policy(a, &s, fw).await,
                "audit" => cmd_audit(a, fw),
                "evidence" => cmd_evidence(a, fw),
                "traces" => cmd_traces(a, fw),
                "memory" => cmd_memory(a, fw),
                _ => println!("unknown: {c}"),
            }
        }
    }
    Ok(())
}

async fn cmd_list() {
    for e in icebox::modules::discover() {
        let i = (e.info)();
        println!("  {}  [{}]  {}", i.name, i.kind.as_str(), i.description);
    }
}

async fn cmd_use(a: &[&str], s: &mut CliState, fw: &Framework) {
    let n = a.join(" ");
    if n.is_empty() {
        println!("usage: use <name>");
        return;
    }
    match icebox::modules::load(&n) {
        Some(l) => {
            let pf = fw.executor.preflight(
                &l,
                &s.target.clone().unwrap_or_default(),
                None,
                false,
                PolicyContext::Cli,
            ).await;
            let scope_note = match &s.target {
                Some(_) => format!("in-scope: {}", pf.in_scope),
                None => "in-scope: n/a (set a target with `run <target>`)".to_string(),
            };
            println!("loaded {} ({})", l.info.name, scope_note);
            s.loaded = Some(l);
        }
        None => println!("not found: {n}"),
    }
}

fn cmd_info(s: &CliState) {
    let Some(ref l) = s.loaded else {
        println!("no module");
        return;
    };
    println!("name: {}", l.info.name);
    println!("kind: {}", l.info.kind.as_str());
    println!("desc: {}", l.info.description);
    if !l.info.author.is_empty() {
        println!("author: {}", l.info.author);
    }
    println!("options: {}", l.module.options_json());
}

fn cmd_set(a: &[&str], s: &mut CliState) {
    let Some(l) = &mut s.loaded else {
        println!("no module");
        return;
    };
    if a.len() < 2 {
        println!("usage: set <key> <val>");
        return;
    }
    match l.module.set_option(a[0], &a[1..].join(" ")) {
        Ok(_) => println!("{} = {}", a[0], a[1..].join(" ")),
        Err(e) => println!("error: {e}"),
    }
}

fn cmd_show(a: &[&str], s: &CliState) {
    if a.first().copied() != Some("options") {
        println!("usage: show options");
        return;
    }
    match &s.loaded {
        None => println!("no module"),
        Some(l) => println!("{}", l.module.options_json()),
    }
}

fn cmd_charter(a: &[&str], fw: &mut Framework) {
    match a.first().copied().unwrap_or("") {
        "accept" => {
            if a.len() < 2 {
                println!("usage: charter accept <name>");
                return;
            }
            if !role_allows(fw.operator_role, Role::Operator) {
                println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
                return;
            }
            fw.executor.charter = Charter::accept(a[1..].join(" "), vec!["authorized".into()]);
            println!("{COLOR_TEAL}accepted: {}{COLOR_RESET}", a[1..].join(" "));
        }
        "status" => println!(
            "{COLOR_TEAL}accepted: {}{COLOR_RESET}",
            fw.executor.charter.accepted
        ),
        _ => println!("usage: charter accept|status"),
    }
}

fn cmd_scope(a: &[&str], fw: &mut Framework) {
    match a.first().copied().unwrap_or("") {
        "add" => {
            let t = a[1..].join(" ");
            if t.is_empty() {
                println!("usage: scope add <tgt>");
                return;
            }
            if !role_allows(fw.operator_role, Role::Operator) {
                println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
                return;
            }
            fw.executor.scope.allow.push(t.clone());
            println!("added: {t}");
        }
        "show" => {
            for t in &fw.executor.scope.allow {
                println!("  {t}");
            }
        }
        _ => println!("usage: scope add|show"),
    }
}

fn cmd_sessions(a: &[&str], fw: &mut Framework) {
    if a.first().copied() == Some("close") {
        if !role_allows(fw.operator_role, Role::Operator) {
            println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
            return;
        }
        let id = a.get(1).and_then(|x| x.parse::<u64>().ok()).map(SessionId);
        if let Some(id) = id {
            if fw.sessions.close(id) {
                println!("session {id} closed");
                return;
            }
        }
        println!("not found");
        return;
    }
    for s in fw.sessions.list() {
        println!(
            "  {}  {}  {}  ({:.0?})",
            s.id,
            s.kind.as_str(),
            s.target,
            s.elapsed()
        );
    }
}

fn cmd_jobs(a: &[&str], fw: &Framework) {
    let n = a.first().and_then(|x| x.parse().ok()).unwrap_or(10);
    for j in fw.jobs.list_recent(n) {
        println!(
            "  {}  {}  {}  {}  ({:.0?})",
            j.id,
            j.module_name,
            j.target,
            j.status.as_str(),
            j.elapsed()
        );
    }
}

async fn cmd_save(a: &[&str], fw: SharedFramework) {
    if !role_allows(fw.lock().await.operator_role, Role::Operator) {
        println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
        return;
    }
    let path = if a.is_empty() {
        "workspace.json".to_string()
    } else {
        a.join(" ")
    };
    let snap = {
        let fw_guard = fw.lock().await;
        icebox::core::workspace::WorkspaceSnapshot::from_framework(&fw_guard)
    };
    match snap.save_to_file(&path) {
        Ok(_) => println!("saved to {path}"),
        Err(e) => println!("save error: {e}"),
    }
}

async fn cmd_load(a: &[&str], fw: SharedFramework) {
    if !role_allows(fw.lock().await.operator_role, Role::Operator) {
        println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
        return;
    }
    let path = if a.is_empty() {
        "workspace.json".to_string()
    } else {
        a.join(" ")
    };
    match icebox::core::workspace::WorkspaceSnapshot::load_from_file(&path) {
        Ok(snap) => {
            let mut fw = fw.lock().await;
            snap.apply_to_framework(&mut fw);
            println!("loaded from {path}");
        }
        Err(e) => println!("load error: {e}"),
    }
}

async fn cmd_agent(a: &[&str], fw: SharedFramework) {
    if !role_allows(fw.lock().await.operator_role, Role::Operator) {
        println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
        return;
    }
    if a.first().copied() != Some("run") {
        println!("usage: agent run [--model <name>] <target>");
        return;
    }
    let (model, target) = if a.get(1).copied() == Some("--model") {
        (
            a.get(2).unwrap_or(&"llama3.2").to_string(),
            a[3..].join(" "),
        )
    } else {
        ("llama3.2".to_string(), a[1..].join(" "))
    };
    if target.is_empty() {
        println!("usage: agent run [--model <name>] <target>");
        return;
    }
    println!("agent: starting campaign against {target} (model: {model})");
    let planner = Box::new(icebox::ai::agent::LlmPlanner::new(model));
    let mut agent = icebox::ai::agent::Agent::new(planner, fw, target, RiskLevel::High);
    agent.set_plan_approver(Box::new(icebox::ai::agent::InteractiveApprover));
    match agent.run().await {
        Ok(cr) => {
            println!("\n=== Campaign Complete ===");
            println!("Summary: {}", cr.summary);
            println!("Actions taken: {}", cr.actions_taken.join(", "));
            println!("Jobs: {:?}", cr.job_ids);
            println!("Sessions: {:?}", cr.sessions_opened);
            println!("\nReport:\n{}", cr.report);
        }
        Err(e) => println!("agent error: {e}"),
    }
}

async fn cmd_campaign(a: &[&str], fw: SharedFramework) {
    if !role_allows(fw.lock().await.operator_role, Role::Operator) {
        println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
        return;
    }
    let approved = a.last().copied() == Some("approve");
    let targets: Vec<String> = a
        .iter()
        .take(if approved { a.len() - 1 } else { a.len() })
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect();
    if targets.is_empty() {
        println!("usage: campaign <target1> [target2 ...] [approve]");
        return;
    }
    println!(
        "campaign: {} target(s) (approved: {approved})",
        targets.len()
    );
    let orch = icebox::ai::Orchestrator::new(fw, RiskLevel::High);
    let report = orch
        .run(&targets, || {
            Box::new(icebox::ai::agent::LlmPlanner::new("llama3.2"))
        })
        .await;
    println!("ok: {}  failed: {}", report.ok, report.failed);
    for (t, s) in report.targets.iter().zip(report.summaries.iter()) {
        println!("  - {t}: {s}");
    }
    println!(
        "aggregate: jobs={} sessions={} decisions={} evidence={} traces={}",
        report.total_jobs,
        report.total_sessions,
        report.total_decisions,
        report.total_evidence,
        report.total_traces
    );
}

async fn cmd_validate(a: &[&str], fw: SharedFramework) {
    if !role_allows(fw.lock().await.operator_role, Role::Operator) {
        println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
        return;
    }
    match a.first().copied() {
        Some("diff") => {
            let (pa, pb) = (a.get(1).copied(), a.get(2).copied());
            let (Some(pa), Some(pb)) = (pa, pb) else {
                println!("usage: validate diff <a.json> <b.json>");
                return;
            };
            let ra: icebox::ai::ValidationReport = match load_report(pa) {
                Some(r) => r,
                None => return,
            };
            let rb: icebox::ai::ValidationReport = match load_report(pb) {
                Some(r) => r,
                None => return,
            };
            let d = icebox::ai::diff(&ra, &rb);
            println!(
                "policy: {} -> {} | jobs {:+}", d.policy_version_a, d.policy_version_b, d.jobs_delta
            );
            println!(
                "deltas: evidence {:+} decisions {:+} traces {:+} (targets: {})",
                d.evidence_delta, d.decisions_delta, d.traces_delta, d.target_count
            );
        }
        Some("run") | None => {
            let mut targets: Vec<String> = Vec::new();
            let mut workspace: Option<String> = None;
            let mut out: Option<String> = None;
            let mut model = "llama3.2".to_string();
            let rest = if a.first().copied() == Some("run") { &a[1..] } else { a };
            let mut it = rest.iter();
            while let Some(&arg) = it.next() {
                match arg {
                    "--targets" => {
                        targets = it
                            .next()
                            .unwrap_or(&"")
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                    "--workspace" => workspace = Some(it.next().unwrap_or(&"").to_string()),
                    "--out" => out = Some(it.next().unwrap_or(&"").to_string()),
                    "--model" => model = it.next().unwrap_or(&"llama3.2").to_string(),
                    _ => {}
                }
            }
            if let Some(path) = &workspace {
                match icebox::core::workspace::WorkspaceSnapshot::load_from_file(path) {
                    Ok(snap) => {
                        let mut g = fw.lock().await;
                        snap.apply_to_framework(&mut g);
                        println!("validate: loaded workspace {path}");
                    }
                    Err(e) => {
                        println!("validate: workspace load error: {e}");
                        return;
                    }
                }
            }
            if targets.is_empty() {
                let g = fw.lock().await;
                targets = g.executor.scope.allow.clone();
            }
            if targets.is_empty() {
                println!("validate: no targets - pass --targets t1,t2 or set scope");
                return;
            }
            println!("validate: {} target(s) (model: {model})", targets.len());
            let model_for_closure = model.clone();
            let report = icebox::ai::run_validation(
                fw.clone(),
                &targets,
                RiskLevel::High,
                move || Box::new(icebox::ai::agent::LlmPlanner::new(model_for_closure.clone())),
            )
            .await;
            println!(
                "validate: ok={} failed={} (policy v{}, ran_at {})",
                report.campaign.ok, report.campaign.failed, report.policy_version, report.ran_at
            );
            println!(
                "totals: jobs={} sessions={} decisions={} evidence={} traces={}",
                report.campaign.total_jobs,
                report.campaign.total_sessions,
                report.campaign.total_decisions,
                report.campaign.total_evidence,
                report.campaign.total_traces
            );
            if let Some(path) = &out {
                match std::fs::write(path, serde_json::to_string_pretty(&report).unwrap_or_default()) {
                    Ok(_) => println!("validate: report saved to {path}"),
                    Err(e) => println!("validate: save error: {e}"),
                }
            }
        }
        Some(_) => println!(
            "usage: validate run [--targets t1,t2] [--workspace w.json] [--out report.json] [--model m] | validate diff <a.json> <b.json>"
        ),
    }
}

fn load_report(path: &str) -> Option<icebox::ai::ValidationReport> {
    match std::fs::read_to_string(path) {
        Ok(s) => match serde_json::from_str::<icebox::ai::ValidationReport>(&s) {
            Ok(r) => Some(r),
            Err(e) => {
                println!("validate: parse error {path}: {e}");
                None
            }
        },
        Err(e) => {
            println!("validate: read error {path}: {e}");
            None
        }
    }
}

async fn cmd_run(a: &[&str], s: &mut CliState, fw: &mut Framework) {
    if !role_allows(fw.operator_role, Role::Operator) {
        println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
        return;
    }
    let Some(ref mut l) = s.loaded else {
        println!("no module");
        return;
    };
    let mut approved = false;
    let mut sandbox = false;
    let mut engine = None;
    let mut tp = a;
    while let Some(first) = tp.first().copied() {
        if first == "--approve" {
            approved = true;
            tp = &tp[1..];
        } else if first == "--sandbox" {
            sandbox = true;
            tp = &tp[1..];
        } else if first == "--engine" {
            if let Some(e) = tp.get(1) {
                engine = match e.to_lowercase().as_str() {
                    "docker" => Some(icebox::core::sandbox::SandboxEngineType::Docker),
                    "firecracker" => {
                        println!(
                            "{COLOR_ORANGE}Firecracker is not supported for module execution; use docker{COLOR_RESET}"
                        );
                        return;
                    }
                    _ => {
                        println!("unknown engine: {e}");
                        return;
                    }
                };
                tp = &tp[2..];
            } else {
                println!("--engine requires a value");
                return;
            }
        } else {
            break;
        }
    }
    let target = if !tp.is_empty() {
        Some(tp.join(" "))
    } else {
        s.target.clone()
    };
    let Some(target) = target else {
        println!("target required");
        return;
    };
    s.target = Some(target.clone());

    let pf = fw
        .executor
        .preflight(l, &target, None, approved, PolicyContext::Cli).await;
    if let Err(e) = pf.check(&fw.executor.policy(PolicyContext::Cli)) {
        println!("{COLOR_ORANGE}BLOCKED: {e}{COLOR_RESET}");
        if pf.risk >= RiskLevel::High {
            println!("try: run --approve {target}");
        }
        return;
    }
    if sandbox {
        println!(
            "{COLOR_TEAL}[SANDBOX] isolation enabled - preflight still enforced{COLOR_RESET}"
        );
    } else {
        println!("preflight passed");
    }

    let job = Job::new(&l.info.name, &target);
    let jid = job.id;
    fw.jobs.register(job);
    match fw
        .executor
        .execute(
            l,
            &target,
            None,
            approved,
            PolicyContext::Cli,
            Some(jid.as_u64()),
            sandbox,
            engine,
        )
        .await
    {
        Ok(r) => {
            fw.jobs.complete(jid, r.clone());
            println!("job {jid} completed");
            if let Some(ref sid) = r.session_id {
                let kind = if sid.starts_with("session:") {
                    SessionKind::Shell
                } else {
                    SessionKind::Unknown
                };
                let sid2 = fw
                    .sessions
                    .register(Session::new(kind, &target, &l.info.name));
                println!("session {sid2} opened");
            }
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
        }
        Err(e) => {
            fw.jobs.cancel(jid);
            println!("error: {e}");
        }
    }
}

async fn cmd_policy(a: &[&str], s: &CliState, fw: &mut Framework) {
    match a.first().copied() {
        Some("rules") => {
            println!("policy version: {}", fw.executor.policy_set.version);
            if fw.executor.policy_set.rules.is_empty() {
                println!("no policy rules (default policy active)");
            } else {
                for (i, r) in fw.executor.policy_set.rules.iter().enumerate() {
                    println!("  [{}] {}", i, policy_rule_str(r));
                }
            }
            return;
        }
        Some("rule") if a.get(1).copied() == Some("add") => {
            cmd_policy_add(&a[2..], fw);
            return;
        }
        Some("rule") if a.get(1).copied() == Some("remove") => {
            cmd_policy_remove(&a[2..], fw);
            return;
        }
        _ => {}
    }
    let module = a.first().copied().unwrap_or("").to_string();
    if module.is_empty() {
        println!("usage: policy <module> [target] | policy rules | policy rule add <deny|allow|maxrisk> <capability|level> | policy rule remove <index>");
        return;
    }
    let target = a
        .get(1)
        .copied()
        .map(|t| t.to_string())
        .or_else(|| s.target.clone())
        .unwrap_or_default();
    let Some(loaded) = icebox::modules::load(&module) else {
        println!("not found: {module}");
        return;
    };
    let pf = fw
        .executor
        .preflight(&loaded, &target, None, false, PolicyContext::Cli).await;
    let policy = fw.executor.policy(PolicyContext::Cli);
    let decision = policy.evaluate(&pf.to_request());
    println!("module: {}", loaded.info.name);
    println!("target: {target}");
    println!("capabilities:");
    for c in &loaded.info.capabilities {
        println!("  - {}", c.as_str());
    }
    let intents: Vec<&str> = loaded
        .info
        .effective_intents()
        .iter()
        .map(|i| i.as_str())
        .collect();
    println!(
        "intent: {}  (declared: {})",
        intents.join(", "),
        loaded.info.intent.map(|i| i.as_str()).unwrap_or("derived")
    );
    println!(
        "impact: {}  (declared: {})",
        loaded.info.effective_impact().as_str(),
        loaded.info.impact.map(|i| i.as_str()).unwrap_or("derived")
    );
    let verdict = match &decision {
        PolicyDecision::Allow => "ALLOW",
        PolicyDecision::RequireApproval(_) => "REQUIRE_APPROVAL",
        PolicyDecision::Deny(_) => "DENY",
    };
    println!("decision: {verdict}");
    if let Some(r) = decision.reason() {
        println!("reason: {r}");
    }
}

fn cmd_policy_add(rest: &[&str], fw: &mut Framework) {
    if !role_allows(fw.operator_role, Role::Operator) {
        println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
        return;
    }
    let Some(kind) = rest.first().copied() else {
        println!(
            "usage: policy rule add <deny|allow|maxrisk|deny-cvss|require-approval-if> <args>"
        );
        return;
    };
    let val = rest.get(1).copied().unwrap_or("");
    let rule = match kind {
        "deny" => match val.parse::<Capability>() {
            Ok(c) => PolicyRule::DenyCapability(c),
            Err(e) => {
                println!("error: {e}");
                return;
            }
        },
        "allow" => match val.parse::<Capability>() {
            Ok(c) => PolicyRule::AllowCapability(c),
            Err(e) => {
                println!("error: {e}");
                return;
            }
        },
        "maxrisk" => match val.parse::<RiskLevel>() {
            Ok(r) => PolicyRule::MaxRisk(r),
            Err(e) => {
                println!("error: {e}");
                return;
            }
        },
        "deny-cvss" => match val.parse::<f64>() {
            Ok(t) => PolicyRule::DenyIfCvssAbove(t),
            Err(_) => {
                println!("error: expected float threshold, got '{val}'");
                return;
            }
        },
        "require-approval-if" => {
            let mut cvss_above: Option<f64> = None;
            let mut epss_above: Option<f64> = None;
            let mut kev = false;
            let mut i = 1;
            while i < rest.len() {
                match rest[i] {
                    "--cvss" => {
                        if let Some(v) = rest.get(i + 1).and_then(|s| s.parse::<f64>().ok()) {
                            cvss_above = Some(v);
                            i += 2;
                            continue;
                        }
                    }
                    "--epss" => {
                        if let Some(v) = rest.get(i + 1).and_then(|s| s.parse::<f64>().ok()) {
                            epss_above = Some(v);
                            i += 2;
                            continue;
                        }
                    }
                    "--kev" => {
                        kev = true;
                        i += 1;
                        continue;
                    }
                    _ => {}
                }
                i += 1;
            }
            PolicyRule::RequireApprovalIf {
                cvss_above,
                epss_above,
                kev,
            }
        }
        other => {
            println!(
                "unknown rule kind: {other} (use deny|allow|maxrisk|deny-cvss|require-approval-if)"
            );
            return;
        }
    };
    fw.executor.policy_set.add_rule(rule.clone());
    println!(
        "added rule: {} (policy version now {})",
        policy_rule_str(&rule),
        fw.executor.policy_set.version
    );
}

fn cmd_policy_remove(rest: &[&str], fw: &mut Framework) {
    if !role_allows(fw.operator_role, Role::Operator) {
        println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
        return;
    }
    let Some(idx) = rest.first().and_then(|s| s.parse::<usize>().ok()) else {
        println!("usage: policy rule remove <index>");
        return;
    };
    match fw.executor.policy_set.remove_rule(idx) {
        Some(r) => println!(
            "removed [{}]: {} (policy version now {})",
            idx,
            policy_rule_str(&r),
            fw.executor.policy_set.version
        ),
        None => println!("no rule at index {idx}"),
    }
}

fn policy_rule_str(r: &PolicyRule) -> String {
    match r {
        PolicyRule::DenyCapability(c) => format!("deny capability {}", c.as_str()),
        PolicyRule::AllowCapability(c) => format!("allow (pre-approve) capability {}", c.as_str()),
        PolicyRule::MaxRisk(l) => format!("max risk {}", l.as_str()),
        PolicyRule::RequireApproval {
            capability,
            target_pattern,
        } => {
            format!(
                "require approval for capability {} on targets matching {}",
                capability.as_str(),
                target_pattern
            )
        }
        PolicyRule::DenyIfCvssAbove(t) => format!("deny if CVSS above {t}"),
        PolicyRule::RequireApprovalIf {
            cvss_above,
            epss_above,
            kev,
        } => {
            let mut parts = Vec::new();
            if let Some(c) = cvss_above {
                parts.push(format!("cvss>{c}"));
            }
            if let Some(e) = epss_above {
                parts.push(format!("epss>{e}"));
            }
            if *kev {
                parts.push("kev=true".into());
            }
            format!("require approval if [{}]", parts.join(", "))
        }
        PolicyRule::DenyPayload(p) => format!("deny payload matching '{p}'"),
    }
}

fn cmd_audit(a: &[&str], fw: &Framework) {
    if a.first().copied() == Some("export") {
        let mut format = "json".to_string();
        let mut out: Option<String> = None;
        let mut it = a.iter().skip(1);
        while let Some(&x) = it.next() {
            match x {
                "--format" => format = it.next().copied().unwrap_or("json").to_string(),
                "--out" => out = Some(it.next().copied().unwrap_or("").to_string()),
                _ => {}
            }
        }
        let recs = fw.executor.recent_decisions(10000);
        let body = if format == "csv" {
            audit_to_csv(&recs)
        } else {
            serde_json::to_string_pretty(&recs).unwrap_or_default()
        };
        match &out {
            Some(p) => match std::fs::write(p, &body) {
                Ok(_) => println!("audit exported to {p} ({format})"),
                Err(e) => println!("export error: {e}"),
            },
            None => println!("{body}"),
        }
        return;
    }
    let n: usize = a.first().and_then(|x| x.parse().ok()).unwrap_or(20);
    let recs = fw.executor.recent_decisions(n);
    if recs.is_empty() {
        println!("no decisions recorded yet");
        return;
    }
    for d in recs {
        let verdict = match &d.decision {
            PolicyDecision::Allow => "allow",
            PolicyDecision::RequireApproval(_) => "require_approval",
            PolicyDecision::Deny(_) => "deny",
        };
        println!(
            "[{}] {} -> {} : {} (impact={}, ctx={})",
            d.at,
            d.module,
            d.target,
            verdict,
            d.impact.as_str(),
            d.context.as_str()
        );
    }
}

fn cmd_evidence(a: &[&str], fw: &Framework) {
    let n: usize = a.first().and_then(|x| x.parse().ok()).unwrap_or(20);
    let ev = fw.executor.recent_evidence(n);
    if ev.is_empty() {
        println!("no evidence captured yet");
        return;
    }
    for e in ev {
        println!(
            "[{}] module={} target={} kind={:?} confidence={:.2} job={:?}",
            e.id, e.module, e.target, e.kind, e.confidence, e.provenance.job_id
        );
        if let Some(n) = &e.normalized {
            println!("    normalized: {}", n);
        }
        println!("    {}", e.content);
    }
}

fn cmd_traces(a: &[&str], fw: &Framework) {
    let n: usize = a.first().and_then(|x| x.parse().ok()).unwrap_or(20);
    let traces = fw.executor.recent_traces(n);
    if traces.is_empty() {
        println!("no reasoning traces yet (run an agent campaign)");
        return;
    }
    for t in traces {
        println!(
            "[{}] phase={} ctx={} : {} | actions={:?}",
            t.at, t.phase, t.context_len, t.summary, t.actions
        );
    }
}

fn cmd_memory(a: &[&str], fw: &Framework) {
    let n: usize = a.first().and_then(|x| x.parse().ok()).unwrap_or(20);
    let mem = fw.executor.recent_memories(n);
    if mem.is_empty() {
        println!("no memories yet (run an agent campaign)");
        return;
    }
    for m in mem {
        println!("[{}] {} : {}", m.at, m.kind.as_str(), m.text);
    }
}

async fn cmd_role(a: &[&str], fw: SharedFramework) {
    if a.first().copied() == Some("--set") {
        let Some(r) = a.get(1).and_then(|s| s.parse::<Role>().ok()) else {
            println!("usage: role --set <viewer|operator|admin>");
            return;
        };
        let mut g = fw.lock().await;
        if !role_allows(g.operator_role, Role::Admin) {
            println!("{COLOR_ORANGE}forbidden: admin role required to change role{COLOR_RESET}");
            return;
        }
        g.operator_role = r;
        println!("role set: {}", r.as_str());
        return;
    }
    let g = fw.lock().await;
    println!("role: {}", g.operator_role.as_str());
}

async fn cmd_pack(a: &[&str], fw: SharedFramework) {
    match a.first().copied() {
        Some("list") => {
            let g = fw.lock().await;
            if g.policy_packs.is_empty() {
                println!("no policy packs");
                return;
            }
            for p in g.policy_packs.values() {
                println!("  {} ({} rules, v{})", p.name, p.rules.len(), p.version);
            }
        }
        Some("add") => {
            if a.len() < 3 {
                println!("usage: pack add <name> <capability> [capability ...]");
                return;
            }
            let name = a[1].to_string();
            let mut rules = Vec::new();
            for cap in &a[2..] {
                match cap.parse::<Capability>() {
                    Ok(c) => rules.push(PolicyRule::AllowCapability(c)),
                    Err(e) => {
                        println!("bad capability {cap}: {e}");
                        return;
                    }
                }
            }
            let pack = PolicyPack::new(name.clone(), rules.clone());
            let mut g = fw.lock().await;
            if !role_allows(g.operator_role, Role::Admin) {
                println!("{COLOR_ORANGE}forbidden: admin role required to add packs{COLOR_RESET}");
                return;
            }
            g.policy_packs.insert(name.clone(), pack);
            println!("pack added: {name} ({} rules)", rules.len());
        }
        Some("apply") => {
            let Some(name) = a.get(1).map(|s| s.to_string()) else {
                println!("usage: pack apply <name>");
                return;
            };
            let mut g = fw.lock().await;
            if !role_allows(g.operator_role, Role::Admin) {
                println!(
                    "{COLOR_ORANGE}forbidden: admin role required to apply packs{COLOR_RESET}"
                );
                return;
            }
            let pack = match g.policy_packs.get(&name) {
                Some(p) => p.clone(),
                None => {
                    println!("pack not found: {name}");
                    return;
                }
            };
            g.executor.policy_set.set_rules(pack.rules.clone());
            println!(
                "pack applied: {name} (policy now v{})",
                g.executor.policy_set.version
            );
        }
        _ => println!("usage: pack list | pack add <name> <capability>... | pack apply <name>"),
    }
}

async fn cmd_approve(a: &[&str], fw: SharedFramework) {
    match a.first().copied() {
        Some("list") => {
            let g = fw.lock().await;
            if g.approval_queue.list().is_empty() {
                println!("no approval requests");
                return;
            }
            for r in g.approval_queue.list() {
                println!(
                    "  #{}  {} -> {}  [{}]  {}",
                    r.id, r.module, r.target, r.status.as_str(), r.reason
                );
            }
        }
        Some("request") => {
            let Some(module) = a.get(1).map(|s| s.to_string()) else {
                println!("usage: approve request <module> <target> [--reason text] [--set key val]...");
                return;
            };
            let Some(target) = a.get(2).map(|s| s.to_string()) else {
                println!("usage: approve request <module> <target> [--reason text] [--set key val]...");
                return;
            };
            let reason = a
                .iter()
                .position(|&x| x == "--reason")
                .and_then(|i| a.get(i + 1))
                .copied()
                .map(|s| s.to_string())
                .unwrap_or_default();
            let mut options: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            let mut i = 0;
            while i < a.len() {
                if a[i] == "--set" {
                    if let (Some(k), Some(v)) = (a.get(i + 1), a.get(i + 2)) {
                        options.insert((*k).to_string(), (*v).to_string());
                        i += 3;
                        continue;
                    }
                }
                i += 1;
            }
            let mut g = fw.lock().await;
            let id = g.approval_queue.request(module.clone(), target.clone(), reason.clone(), options);
            println!("approval requested: #{id} ({module} -> {target})");
        }
        Some("approve") => {
            let Some(id) = a.get(1).and_then(|x| x.parse::<u64>().ok()) else {
                println!("usage: approve approve <id>");
                return;
            };
            let mut g = fw.lock().await;
            if !role_allows(g.operator_role, Role::Operator) {
                println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
                return;
            }
            let req = match g.approval_queue.get(id) {
                Some(r) => r.clone(),
                None => {
                    println!("not found: #{id}");
                    return;
                }
            };
            g.approval_queue.approve(id);
            let mut loaded = match icebox::modules::load(&req.module) {
                Some(l) => l,
                None => {
                    println!("module not found: {}", req.module);
                    return;
                }
            };
            for (k, v) in &req.options {
                let _ = loaded.module.set_option(k, v);
            }
            match g.executor.execute(&mut loaded, &req.target, None, true, PolicyContext::Cli, None, false, None).await {
                Ok(_) => println!("approved + executed: #{id}"),
                Err(e) => println!("approved but execute failed: {e}"),
            }
        }
        Some("deny") => {
            let Some(id) = a.get(1).and_then(|x| x.parse::<u64>().ok()) else {
                println!("usage: approve deny <id>");
                return;
            };
            let mut g = fw.lock().await;
            if !role_allows(g.operator_role, Role::Operator) {
                println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
                return;
            }
            if g.approval_queue.deny(id) {
                println!("denied: #{id}");
            } else {
                println!("not found: #{id}");
            }
        }
        _ => println!("usage: approve list | approve request <module> <target> [--reason text] [--set key val]... | approve approve <id> | approve deny <id>"),
    }
}

async fn cmd_proxy(a: &[&str], fw: SharedFramework) {
    match a.first().copied() {
        Some("bind") => {
            let Some(target) = a.get(1).map(|s| s.to_string()) else {
                println!("usage: proxy bind <target> <port>");
                return;
            };
            let Some(port) = a.get(2).and_then(|x| x.parse::<u16>().ok()) else {
                println!("usage: proxy bind <target> <port>");
                return;
            };
            let mut g = fw.lock().await;
            if !role_allows(g.operator_role, Role::Operator) {
                println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
                return;
            }
            use icebox::core::proxy::{bind_proxy as reg_bind, NetworkIsolator};
            #[cfg(target_os = "linux")]
            let isolator: Box<dyn NetworkIsolator> = Box::new(icebox::core::proxy::netns::LinuxNetnsIsolator {
                namespace_name: format!("icebox-netns-{}", std::process::id()),
            });

            #[cfg(not(target_os = "linux"))]
            let isolator: Box<dyn NetworkIsolator> = Box::new(icebox::core::proxy::tcp::TcpProxyIsolator);

            let _ = isolator.setup().await;
            
            let Ok((listener, handle)) =
                isolator.spawn_proxy(&target, port).await
            else {
                println!("{COLOR_ORANGE}failed to bind proxy for {target}{COLOR_RESET}");
                return;
            };
            let local = listener.local_addr;
            reg_bind(&target, local);
            let lp = local.port();
            g.proxies.insert(lp, (target.clone(), isolator, handle));
            println!("proxy bound: {target}:{port} -> 127.0.0.1:{lp}");
        }
        Some("unbind") => {
            let Some(port) = a.get(1).and_then(|x| x.parse::<u16>().ok()) else {
                println!("usage: proxy unbind <local_port>");
                return;
            };
            let mut g = fw.lock().await;
            if !role_allows(g.operator_role, Role::Operator) {
                println!("{COLOR_ORANGE}forbidden: operator role required{COLOR_RESET}");
                return;
            }
            if let Some((target, isolator, handle)) = g.proxies.remove(&port) {
                icebox::core::proxy::unbind_proxy(&target);
                let _ = isolator.teardown().await;
                handle.abort();
                println!("proxy unbound: 127.0.0.1:{port}");
            } else {
                println!("no proxy bound on 127.0.0.1:{port}");
            }
        }
        Some("list") => {
            let g = fw.lock().await;
            if g.proxies.is_empty() {
                println!("no proxies bound");
                return;
            }
            for (port, (target, _, _)) in &g.proxies {
                println!("  127.0.0.1:{port} -> {target}");
            }
        }
        _ => println!("usage: proxy bind <target> <port> | proxy unbind <local_port> | proxy list"),
    }
}

async fn cmd_tier(a: &[&str], fw: SharedFramework) {
    use icebox::core::safety::Tier;
    match a.first().copied() {
        Some("set") => {
            let Some(name) = a.get(1) else {
                println!("usage: tier set <fridge|freezer|deep_freeze>");
                return;
            };
            let Ok(tier) = name.parse::<Tier>() else {
                println!("{COLOR_ORANGE}unknown tier: {name}{COLOR_RESET}");
                return;
            };
            let mut g = fw.lock().await;
            g.executor.tier = tier;
            println!("operational tier set: {tier}");
            println!(
                "  sandbox: {} | cvss limit: {} | explicit approval: {}",
                tier.requires_sandbox(),
                tier.cvss_threshold()
                    .map(|t| format!("{t:.1}"))
                    .unwrap_or_else(|| "none".into()),
                tier.requires_explicit_approval(),
            );
        }
        _ => {
            let g = fw.lock().await;
            println!("operational tier: {}", g.executor.tier);
        }
    }
}
