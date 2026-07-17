use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use tokio::runtime::Runtime;

use icebox::core::executor::ModuleExecutor;
use icebox::core::framework::{new_shared_framework, SharedFramework};
use icebox::core::safety::{Charter, PolicyContext, RiskLevel, ScopeManager};

#[pyclass]
struct NativeIcebox {
    rt: Runtime,
    fw: SharedFramework,
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
        let executor =
            ModuleExecutor::new(charter, ScopeManager::new(scopes.unwrap_or_default()), risk);
        let fw = new_shared_framework(executor);
        Ok(NativeIcebox { rt, fw })
    }

    #[pyo3(signature = (name, target, sandbox=false, options=None))]
    fn run_module(
        &self,
        py: Python<'_>,
        name: String,
        target: String,
        sandbox: bool,
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
                            sandbox,
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
}

#[pymodule]
fn _icebox(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeIcebox>()?;
    Ok(())
}
