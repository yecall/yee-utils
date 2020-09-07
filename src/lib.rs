use serde_json::Value;

pub use modules::meter::{BlockInfo, System};

pub mod app;
pub mod modules;

pub async fn meter_get_best(rpc: &str) -> Result<BlockInfo, String> {
	modules::meter::meter_get_best(rpc, true).await
}

pub async fn meter_get_finalized(rpc: &str) -> Result<BlockInfo, String> {
	modules::meter::meter_get_finalized(rpc, true).await
}

pub async fn meter_get_system(rpc: &str) -> Result<System, String> {
	modules::meter::meter_get_system(rpc, true).await
}

pub async fn meter_get_peers(rpc: &str) -> Result<Value, String> {
	modules::meter::meter_get_peers(rpc, true).await
}

pub async fn meter_get_network_state(rpc: &str) -> Result<Value, String> {
	modules::meter::meter_get_network_state(rpc, true).await
}

pub async fn meter_get_foreign_network_state(rpc: &str) -> Result<Value, String> {
	modules::meter::meter_get_foreign_network_state(rpc, true).await
}

pub async fn meter_get_runtime(rpc: &str) -> Result<Value, String> {
	modules::meter::meter_get_runtime(rpc, true).await
}

pub async fn meter_get_crfg(rpc: &str) -> Result<Value, String> {
	modules::meter::meter_get_crfg(rpc, true).await
}

pub async fn meter_get_foreign_status(rpc: &str) -> Result<Value, String> {
	modules::meter::meter_get_foreign_status(rpc, true).await
}

pub async fn meter_get_config(rpc: &str) -> Result<Value, String> {
	modules::meter::meter_get_config(rpc, true).await
}
