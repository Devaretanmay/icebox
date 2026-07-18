use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use tokio::runtime::Runtime;

use icebox::core::executor::ModuleExecutor;
use icebox::core::framework::{new_shared_framework, SharedFramework};
use icebox::core::safety::{Charter, PolicyContext, RiskLevel, ScopeManager, Tier};
use icebox::core::sdk::{govern, GovernanceConfig, GovernanceRuntime, TaskSpec};

#[pyclass]
struct NativeIcebox {
    rt: Runtime,
    fw: SharedFramework,
    gov: GovernanceRuntime,
}

#[pymethods]
impl NativeIcebox {
    #[new]
    #[pyo3(signature = (scopes=None, max_risk=None))]
    fn new(scopes: Option<Vec<String>>, max_risk: Option<String>) -> PyResult<Self> {
        let rt = Runtime::new().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let mut charter = Charter::default();
        charter.accepted = true;
        let risk = match max_risk.as_deref() {
            Some("none") => RiskLevel::None,
            Some("low") => RiskLevel::Low,
            Some("medium") => RiskLevel::Medium,
            Some("high") => RiskLevel::High,
            _ => RiskLevel::Critical,
        };
        let scope_mgr = ScopeManager::new(scopes.clone().unwrap_or_default());
        let mut executor = ModuleExecutor::new(charter.clone(), scope_mgr, risk);
        executor.tier = Tier::Freezer;
        let fw = new_shared_framework(executor);
        let cfg = GovernanceConfig {
            charter,
            scope: ScopeManager::new(scopes.unwrap_or_default()),
            max_risk: risk,
            ..Default::default()
        };
        let gov = govern(cfg);
        Ok(NativeIcebox { rt, fw, gov })
    }

    #[pyo3(signature = (name, target, options=None))]
    fn run_module(
        &self,
        py: Python<'_>,
        name: String,
        target: String,
        options: Option<std::collections::HashMap<String, String>>,
    ) -> PyResult<String> {
        let fw = self.fw.clone();

        let mut loaded = icebox::modules::load(&name)
            .ok_or_else(|| PyRuntimeError::new_err(format!("Module not found: {}", name)))?;

        if let Some(opts) = options {
            for (k, v) in opts {
                if let Err(e) = loaded.module.set_option(&k, &v) {
                    return Err(PyRuntimeError::new_err(format!("invalid option {k}: {e}")));
                }
            }
        }

        let result_json = py.allow_threads(move || {
            let mut fw_lock = fw.blocking_lock();
            let executor = &mut fw_lock.executor;

            let result = self
                .rt
                .block_on(async {
                    executor
                        .execute(
                            &mut loaded,
                            &target,
                            None,
                            true,
                            PolicyContext::Rest,
                            None,
                            None,
                        )
                        .await
                })
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

            let mut result_out = serde_json::json!({
                "success": result.success,
                "evidence": result.evidence,
                "data": result.data,
                "error": result.error,
            });

            if let Some(evidence) = result_out
                .get_mut("evidence")
                .and_then(|e| e.as_array_mut())
            {
                for item in evidence.iter_mut() {
                    if let Some(s) = item.as_str() {
                        *item = serde_json::Value::String(s.replace("AKIA", "REDACTED_AKIA"));
                    }
                }
            }

            Ok::<String, PyErr>(
                serde_json::to_string(&result_out)
                    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
            )
        })?;

        Ok(result_json)
    }

    #[pyo3(signature = (task_json))]
    fn preflight_action(&self, task_json: String) -> PyResult<String> {
        let task: TaskSpec = serde_json::from_str(&task_json)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid task: {e}")))?;
        let outcome = self.rt.block_on(self.gov.preflight(task));
        serde_json::to_string(&outcome)
            .map_err(|e| PyRuntimeError::new_err(format!("serialize: {e}")))
    }

    #[pyo3(signature = (task_json, result_json, decision="allow"))]
    fn complete_action(
        &self,
        task_json: String,
        result_json: String,
        decision: &str,
    ) -> PyResult<String> {
        let task: TaskSpec = serde_json::from_str(&task_json)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid task: {e}")))?;
        let result: serde_json::Value = serde_json::from_str(&result_json)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid result: {e}")))?;
        let decision: icebox::core::safety::PolicyDecision = decision
            .parse()
            .map_err(|e: String| PyRuntimeError::new_err(e))?;
        let outcome = self.rt.block_on(self.gov.complete(task, result, decision));
        serde_json::to_string(&outcome)
            .map_err(|e| PyRuntimeError::new_err(format!("serialize: {e}")))
    }
}

#[pymodule]
fn _icebox(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeIcebox>()?;
    Ok(())
}
