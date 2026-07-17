use icebox_macro::module;
use icebox::core::module::{Module, ModuleResult, ModuleError};
use icebox::core::Capability;

#[module(name = "my_scanner", capabilities = [Capability::NetworkScan], impact = "low")]
pub struct MyScanner;

#[async_trait::async_trait]
impl Module for MyScanner {
    async fn run(&self) -> Result<ModuleResult, ModuleError> {
        Ok(ModuleResult { success: true, finding: Some("Found!".to_string()), data: serde_json::json!({}), ..Default::default() })
    }
}
