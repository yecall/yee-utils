use clap::{Arg, ArgMatches, SubCommand};
use futures::future::join_all;
use serde::Serialize;
use serde_json::Value;
use tokio::runtime::Runtime;

use crate::modules::{base, Command, Module};

pub fn module<'a, 'b>() -> Module<'a, 'b> {
	Module {
		desc: "Meter".to_string(),
		commands: commands(),
		get_cases: cases::cases,
	}
}

pub fn commands<'a, 'b>() -> Vec<Command<'a, 'b>> {

	vec![Command {
		app: SubCommand::with_name("meter")
			.about("Meter")
			.arg(
				Arg::with_name("RPC")
					.long("rpc")
					.short("r").help("RPC address")
					.takes_value(true)
					.required(true)),
		f: meter,
	},]
}

fn meter(matches: &ArgMatches) -> Result<Vec<String>, String> {

	let rpc = matches.value_of("RPC").expect("qed");

	let mut runtime = Runtime::new().expect("qed");

	let meter = runtime.block_on(get_meter(rpc));

	base::output(meter)
}

async fn get_meter(rpc: &str) -> Meter{

	let system = get_system(rpc);

	let runtime = get_runtime(rpc);

	let crfg = get_crfg(rpc);

	let (system, runtime, crfg) = tokio::join!(
		system, runtime, crfg
	);

	let meter = Meter {
		system: system.ok(),
		runtime: runtime.ok(),
		crfg: crfg.ok(),
	};

	meter
}

async fn get_system(rpc: &str) -> Result<System, String>{

	let name = base::rpc_call::<_, Value>(rpc, "system_name", &());

	let version = base::rpc_call::<_, Value>(rpc, "system_version", &());

	let chain = base::rpc_call::<_, Value>(rpc, "system_chain", &());

	let health = base::rpc_call::<_, Value>(rpc, "system_health", &());

	let peers = base::rpc_call::<_, Value>(rpc, "system_peers", &());

	let network_state = base::rpc_call::<_, Value>(rpc, "system_networkState", &());

	let result = join_all(vec![name, version, chain, health, peers, network_state]).await;

	let mut result = result.into_iter().map(Some).collect::<Vec<_>>();

	let extract = |x : Option<Result<base::RpcResponse<Value>, String>>| -> Option<Value> {
		match x {
			Some(Ok(x)) => x.result,
			_ => None,
		}
	};

	let system = System{
		name: extract(result[0].take()),
		version: extract(result[1].take()),
		chain: extract(result[2].take()),
		health: extract(result[3].take()),
		peers: extract(result[4].take()),
		network_state: extract(result[5].take()),
	};

	Ok(system)
}

async fn get_runtime(rpc: &str) -> Result<Value, String>{

	let runtime = base::rpc_call::<_, Value>(rpc, "state_getRuntimeVersion", &()).await;

	let extract = |x : Result<base::RpcResponse<Value>, String>| -> Result<Value, String> {
		match x {
			Ok(x) => match x.result{
				Some(x) => Ok(x),
				None => Err("".to_string()),
			},
			Err(e) => Err(e),
		}
	};

	extract(runtime)
}

async fn get_crfg(rpc: &str) -> Result<Value, String>{

	let runtime = base::rpc_call::<_, Value>(rpc, "crfg_state", &()).await;

	let extract = |x : Result<base::RpcResponse<Value>, String>| -> Result<Value, String> {
		match x {
			Ok(x) => match x.result{
				Some(x) => Ok(x),
				None => Err("".to_string()),
			},
			Err(e) => Err(e),
		}
	};

	extract(runtime)
}
#[derive(Serialize)]
struct Meter {
	system: Option<System>,
	runtime: Option<Value>,
	crfg: Option<Value>,
}

#[derive(Serialize)]
struct System {
	name: Option<Value>,
	version: Option<Value>,
	chain: Option<Value>,
	health: Option<Value>,
	peers: Option<Value>,
	network_state: Option<Value>,
}

mod cases {
	use linked_hash_map::LinkedHashMap;

	use crate::modules::Case;

	pub fn cases() -> LinkedHashMap<&'static str, Vec<Case>> {
		vec![]
			.into_iter()
			.collect()
	}
}

#[cfg(test)]
mod tests {
	use crate::modules::base::test::test_module;

	use super::*;

	#[test]
	fn test_cases() {
		test_module(module());
	}
}
