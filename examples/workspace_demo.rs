use icebox::core::executor::ModuleExecutor;
use icebox::core::framework::Framework;
use icebox::core::job::Job;
use icebox::core::safety::{Charter, RiskLevel, ScopeManager};
use icebox::core::session::{Session, SessionKind};
use icebox::core::workspace::WorkspaceSnapshot;

#[tokio::main]
async fn main() {
    let mut fw = Framework::new(ModuleExecutor::new(
        Charter::accept("test-engagement", vec!["rule 1".into()]),
        ScopeManager::new(vec!["10.0.0.0/8".into()]),
        RiskLevel::High,
    ));

    let job = Job::new("tcp_port_scanner", "10.0.0.1");
    fw.jobs.register(job);
    let sesh = Session::new(SessionKind::Shell, "10.0.0.1", "reverse_shell_payload");
    let sid = fw.sessions.register(sesh);
    println!("Created session {sid}");

    let snap = WorkspaceSnapshot::from_framework(&fw);
    let path = "/tmp/workspace_test.json";
    snap.save_to_file(path).expect("save");
    println!("Saved to {path}");

    let file_content = std::fs::read_to_string(path).unwrap();
    println!("File size: {} bytes", file_content.len());

    let mut fw2 = Framework::new(ModuleExecutor::new(
        Charter::default(),
        ScopeManager::default(),
        RiskLevel::None,
    ));
    let loaded = WorkspaceSnapshot::load_from_file(path).expect("load");
    loaded.apply_to_framework(&mut fw2);
    println!(
        "Loaded: charter={} scope={:?} jobs={} sessions={}",
        fw2.executor.charter.accepted,
        fw2.executor.scope.allow,
        fw2.jobs.list_recent(10).len(),
        fw2.sessions.list_all().len()
    );
}
