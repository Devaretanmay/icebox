use std::sync::Arc;
use tokio::sync::Mutex;

use icebox_ai::agent::{Agent, LlmPlanner};
use icebox_core::executor::ModuleExecutor;
use icebox_core::framework::{new_shared_framework, Framework};
use icebox_core::safety::{Charter, RiskLevel, ScopeManager};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Permissive framework for local testing
    let fw: Arc<Mutex<Framework>> = new_shared_framework(ModuleExecutor::new(
        Charter::accept("demo-agent-test", vec!["authorized".into()]),
        ScopeManager::new(vec!["127.0.0.1".into()]),
        RiskLevel::Critical,
    ));

    let planner = Box::new(LlmPlanner::new("ornith:9b"));
    let mut agent = Agent::new(planner, fw, "127.0.0.1", RiskLevel::Critical);
    agent.set_approved(true);

    match agent.run().await {
        Ok(cr) => {
            println!("=== Campaign Complete ===");
            println!("Summary: {}", cr.summary);
            println!("Actions taken: {}", cr.actions_taken.join(", "));
            println!("Jobs: {:?}", cr.job_ids);
            println!("Sessions: {:?}", cr.sessions_opened);
            println!("\nReport:\n{}", cr.report);
        }
        Err(e) => {
            println!("Agent error: {e}");
        }
    }
    Ok(())
}
