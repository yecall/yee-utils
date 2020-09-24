use std::collections::{hash_map::Entry, HashMap};
use std::str::FromStr;

use chrono::offset::TimeZone;
use chrono::Local;
use clap::{Arg, ArgMatches, SubCommand};
use finality_tracker::FinalityTrackerDigestItem;
use futures::future::join_all;
use parity_codec::Decode;
use runtime_primitives::generic::DigestItem;
use serde::Serialize;
use serde_json::Value;
use substrate_primitives::U256;
use tokio::runtime::Runtime;
use yee_consensus_pow::{CompatibleDigestItem, PowSeal};
use yee_primitives::Hrp;
use yee_runtime::opaque::Block;
use yee_sharding::ShardingDigestItem;

use crate::modules::base::{get_rpc, Hex};
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
					.short("r")
					.help("RPC address")
					.takes_value(true)
					.required(true),
			)
			.arg(
				Arg::with_name("BEST")
					.long("best")
					.help("Best block")
					.required(false),
			)
			.arg(
				Arg::with_name("FINALIZED")
					.long("finalized")
					.help("Finalized block")
					.required(false),
			)
			.arg(
				Arg::with_name("SYSTEM")
					.long("system")
					.help("System: name, version, chain, health")
					.required(false),
			)
			.arg(
				Arg::with_name("PEERS")
					.long("peers")
					.help("Peers")
					.required(false),
			)
			.arg(
				Arg::with_name("NETWORK_STATE")
					.long("network-state")
					.help("Network state")
					.required(false),
			)
			.arg(
				Arg::with_name("FOREIGN_NETWORK_STATE")
					.long("foreign-network-state")
					.help("Foreign network state")
					.required(false),
			)
			.arg(
				Arg::with_name("RUNTIME")
					.long("runtime")
					.help("Runtime")
					.required(false),
			)
			.arg(
				Arg::with_name("CRFG")
					.long("crfg")
					.help("CRFG")
					.required(false),
			)
			.arg(
				Arg::with_name("FOREIGN_STATUS")
					.long("foreign-status")
					.help("Foreign status")
					.required(false),
			)
			.arg(
				Arg::with_name("CONFIG")
					.long("config")
					.help("Config")
					.required(false),
			),
		f: meter,
	}]
}

fn meter(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let rpc = &get_rpc(matches);

	let mut enable_list = EnableList {
		best: matches.is_present("BEST"),
		finalized: matches.is_present("FINALIZED"),
		system: matches.is_present("SYSTEM"),
		peers: matches.is_present("PEERS"),
		network_state: matches.is_present("NETWORK_STATE"),
		foreign_network_state: matches.is_present("FOREIGN_NETWORK_STATE"),
		runtime: matches.is_present("RUNTIME"),
		crfg: matches.is_present("CRFG"),
		foreign_status: matches.is_present("FOREIGN_STATUS"),
		config: matches.is_present("CONFIG"),
	};

	if enable_list.all_false() {
		enable_list = EnableList {
			best: true,
			finalized: true,
			system: true,
			peers: true,
			network_state: true,
			foreign_network_state: true,
			runtime: true,
			crfg: true,
			foreign_status: true,
			config: true,
		}
	}

	let mut runtime = Runtime::new().expect("qed");

	let meter = runtime.block_on(get_meter(rpc, &enable_list));

	base::output(meter)
}

struct EnableList {
	best: bool,
	finalized: bool,
	system: bool,
	peers: bool,
	network_state: bool,
	foreign_network_state: bool,
	runtime: bool,
	crfg: bool,
	foreign_status: bool,
	config: bool,
}

impl EnableList {
	fn all_false(&self) -> bool {
		!self.best
			&& !self.finalized
			&& !self.system
			&& !self.peers
			&& !self.network_state
			&& !self.foreign_network_state
			&& !self.runtime
			&& !self.crfg
			&& !self.foreign_status
			&& !self.config
	}
}

async fn get_meter(rpc: &str, enable_list: &EnableList) -> Meter {
	let best = meter_get_best(rpc, enable_list.best);

	let finalized = meter_get_finalized(rpc, enable_list.finalized);

	let system = meter_get_system(rpc, enable_list.system);

	let peers = meter_get_peers(rpc, enable_list.peers);

	let network_state = meter_get_network_state(rpc, enable_list.network_state);

	let foreign_network_state =
		meter_get_foreign_network_state(rpc, enable_list.foreign_network_state);

	let runtime = meter_get_runtime(rpc, enable_list.runtime);

	let crfg = meter_get_crfg(rpc, enable_list.crfg);

	let foreign_status = meter_get_foreign_status(rpc, enable_list.foreign_status);

	let config = meter_get_config(rpc, enable_list.config);

	let (
		best,
		finalized,
		system,
		peers,
		network_state,
		foreign_network_state,
		runtime,
		crfg,
		foreign_status,
		config,
	) = tokio::join!(
		best,
		finalized,
		system,
		peers,
		network_state,
		foreign_network_state,
		runtime,
		crfg,
		foreign_status,
		config
	);

	let meter = Meter {
		best: best.ok(),
		finalized: finalized.ok(),
		system: system.ok(),
		peers: peers.ok(),
		network_state: network_state.ok(),
		foreign_network_state: foreign_network_state.ok(),
		runtime: runtime.ok(),
		crfg: crfg.ok(),
		foreign_status: foreign_status.ok(),
		config: config.ok(),
	};

	meter
}

pub async fn meter_get_best(rpc: &str, enabled: bool) -> Result<BlockInfo, String> {
	if !enabled {
		return Err("disabled".to_string());
	}
	let info = get_block_info_async(Number::Best, rpc).await?;

	let info = arrange_block_info(info);

	Ok(info)
}

pub async fn meter_get_finalized(rpc: &str, enabled: bool) -> Result<BlockInfo, String> {
	if !enabled {
		return Err("disabled".to_string());
	}
	let info = get_block_info_async(Number::Finalized, rpc).await?;

	let info = arrange_block_info(info);

	Ok(info)
}

pub async fn meter_get_system(rpc: &str, enabled: bool) -> Result<System, String> {
	if !enabled {
		return Err("disabled".to_string());
	}
	let name = base::rpc_call::<_, Value>(rpc, "system_name", &());

	let version = base::rpc_call::<_, Value>(rpc, "system_version", &());

	let chain = base::rpc_call::<_, Value>(rpc, "system_chain", &());

	let health = base::rpc_call::<_, Value>(rpc, "system_health", &());

	let result = join_all(vec![name, version, chain, health]).await;

	let mut result = result.into_iter().map(Some).collect::<Vec<_>>();

	let extract = |x: Option<Result<base::RpcResponse<Value>, String>>| -> Option<Value> {
		match x {
			Some(Ok(x)) => x.result,
			_ => None,
		}
	};

	let system = System {
		name: extract(result[0].take()),
		version: extract(result[1].take()),
		chain: extract(result[2].take()),
		health: extract(result[3].take()),
	};

	Ok(system)
}

pub async fn meter_get_peers(rpc: &str, enabled: bool) -> Result<Value, String> {
	if !enabled {
		return Err("disabled".to_string());
	}
	let result = base::rpc_call::<_, Value>(rpc, "system_peers", &())
		.await?
		.result;

	let result = result.ok_or("none")?;

	Ok(result)
}

pub async fn meter_get_network_state(rpc: &str, enabled: bool) -> Result<Value, String> {
	if !enabled {
		return Err("disabled".to_string());
	}
	let result = base::rpc_call::<_, Value>(rpc, "system_networkState", &())
		.await?
		.result;

	let result = result.ok_or("none")?;

	Ok(result)
}

pub async fn meter_get_foreign_network_state(rpc: &str, enabled: bool) -> Result<Value, String> {
	if !enabled {
		return Err("disabled".to_string());
	}
	let result = base::rpc_call::<_, Value>(rpc, "system_foreignNetworkState", &())
		.await?
		.result;

	let result = result.ok_or("none")?;

	Ok(result)
}

pub async fn meter_get_runtime(rpc: &str, enabled: bool) -> Result<Value, String> {
	if !enabled {
		return Err("disabled".to_string());
	}
	let result = base::rpc_call::<_, Value>(rpc, "state_getRuntimeVersion", &())
		.await?
		.result;

	let result = result.ok_or("none")?;

	Ok(result)
}

pub async fn meter_get_crfg(rpc: &str, enabled: bool) -> Result<Value, String> {
	if !enabled {
		return Err("disabled".to_string());
	}
	let result = base::rpc_call::<_, Value>(rpc, "crfg_state", &())
		.await?
		.result;

	let result = result.ok_or("none")?;

	Ok(result)
}

pub async fn meter_get_foreign_status(rpc: &str, enabled: bool) -> Result<Value, String> {
	if !enabled {
		return Err("disabled".to_string());
	}
	let result = base::rpc_call::<_, Value>(rpc, "system_foreignStatus", &())
		.await?
		.result;

	let result = result.ok_or("none")?;

	Ok(result)
}

pub async fn meter_get_config(rpc: &str, enabled: bool) -> Result<Value, String> {
	if !enabled {
		return Err("disabled".to_string());
	}
	let result = base::rpc_call::<_, Value>(rpc, "system_config", &())
		.await?
		.result;

	let result = result.ok_or("none")?;

	Ok(result)
}

pub enum Number {
	#[allow(dead_code)]
	Number(u64),
	Best,
	Finalized,
}

pub fn get_block_info(number: Number, rpc: &str) -> Result<BlockInfo, String> {
	let mut runtime = Runtime::new().expect("qed");

	let block_info = runtime.block_on(get_block_info_async(number, rpc))?;

	let block_info = arrange_block_info(block_info);

	Ok(block_info)
}

pub fn get_hrp(rpc: &str) -> Result<Hrp, String> {
	let mut runtime = Runtime::new().expect("qed");

	let chain_info = runtime.block_on(get_chain_info_async(rpc))?;

	let hrp = match chain_info.as_str() {
		"MainNet" => Hrp::MAINNET,
		_ => Hrp::TESTNET,
	};

	Ok(hrp)
}

async fn get_chain_info_async(rpc: &str) -> Result<String, String> {
	let chain_info = base::rpc_call::<_, String>(rpc, "system_chain", &())
		.await?
		.result
		.ok_or("decode failed".to_string())?;

	Ok(chain_info)
}

async fn get_block_info_async(
	number: Number,
	rpc: &str,
) -> Result<
	(
		u64,
		Hex,
		Option<(u16, u16)>,
		Option<u64>,
		Option<BlockCrfgInfo>,
		Option<PowSeal<Block, AuthorityId>>,
	),
	String,
> {
	let (header, number, hash) = match number {
		Number::Number(number) => {
			let hash = base::rpc_call::<_, String>(rpc, "chain_getBlockHash", &[number])
				.await?
				.result
				.ok_or("decode failed".to_string())?;
			let header = base::rpc_call::<_, Value>(rpc, "chain_getHeader", &[&hash])
				.await?
				.result
				.ok_or("decode failed".to_string())?;
			let hash = Hex::from_str(&hash).expect("qed");
			(header, number, hash)
		}
		Number::Best => {
			let header = base::rpc_call::<_, Value>(rpc, "chain_getHeader", &())
				.await?
				.result
				.ok_or("decode failed".to_string())?;
			let number_hex = header
				.as_object()
				.ok_or("none error".to_string())?
				.get("number")
				.ok_or("none error".to_string())?
				.as_str()
				.ok_or("none error".to_string())?;
			let number = {
				let tmp = number_hex.trim_start_matches("0x");
				let tmp = u64::from_str_radix(tmp, 16).map_err(|_| "Decode failed")?;
				tmp
			};
			let hash = base::rpc_call::<_, String>(rpc, "chain_getBlockHash", &[number])
				.await?
				.result
				.ok_or("decode failed".to_string())?;
			let hash = Hex::from_str(&hash).expect("qed");
			(header, number, hash)
		}
		Number::Finalized => {
			let hash = base::rpc_call::<_, String>(rpc, "chain_getFinalizedHead", &())
				.await?
				.result
				.ok_or("decode failed".to_string())?;
			let header = base::rpc_call::<_, Value>(rpc, "chain_getHeader", &[&hash])
				.await?
				.result
				.ok_or("decode failed".to_string())?;
			let number_hex = header
				.as_object()
				.ok_or("none error".to_string())?
				.get("number")
				.ok_or("none error".to_string())?
				.as_str()
				.ok_or("none error".to_string())?;
			let number = {
				let tmp = number_hex.trim_start_matches("0x");
				let tmp = u64::from_str_radix(tmp, 16).map_err(|_| "Decode failed")?;
				tmp
			};
			let hash = Hex::from_str(&hash).expect("qed");
			(header, number, hash)
		}
	};

	const CRFG_LOG_PREFIX: u8 = 3;

	let digest = header
		.as_object()
		.ok_or("none error".to_string())?
		.get("digest")
		.ok_or("none error".to_string())?;

	let logs = get_logs(digest)?;

	let shard_info: Option<(u16, u16)> = logs
		.iter()
		.filter_map(ShardingDigestItem::as_sharding_info)
		.next();

	let finalized_number: Option<u64> = logs
		.iter()
		.filter_map(FinalityTrackerDigestItem::as_finality_tracker)
		.next();

	let signals = logs
		.iter()
		.filter_map(|x| match x {
			DigestItem::Other(data) if data.len() >= 2 && data[0] == CRFG_LOG_PREFIX => {
				let input = &mut &data[2..];
				match data[1] {
					0 => {
						let (delay, authorities): (u64, Vec<(AuthorityId, u64)>) =
							Decode::decode(input)?;
						let authorities = arrange_authorities(authorities);
						let authorities = authorities
							.into_iter()
							.map(|(a, b)| (a.to_vec().into(), b))
							.collect::<Vec<_>>();
						Some(CrfgSignal::AuthoritiesChangeSignal(delay, authorities))
					}
					1 => {
						let (median, delay, authorities): (u64, u64, Vec<(AuthorityId, u64)>) =
							Decode::decode(input)?;
						let authorities = arrange_authorities(authorities);
						let authorities = authorities
							.into_iter()
							.map(|(a, b)| (a.to_vec().into(), b))
							.collect::<Vec<_>>();
						Some(CrfgSignal::ForcedAuthoritiesChangeSignal(
							median,
							delay,
							authorities,
						))
					}
					2 => {
						let number: u64 = Decode::decode(input)?;
						Some(CrfgSignal::SkipSignal(number))
					}
					_ => None,
				}
			}
			_ => None,
		})
		.collect::<Vec<_>>();

	let crfg = Some(BlockCrfgInfo { signals });

	let pow: Option<PowSeal<Block, AuthorityId>> = logs
		.iter()
		.filter_map(CompatibleDigestItem::as_pow_seal)
		.next();

	Ok((number, hash, shard_info, finalized_number, crfg, pow))
}

fn get_logs(digest: &Value) -> Result<Vec<DigestItem<Hash, AuthorityId, ()>>, String> {
	let logs = digest
		.as_object()
		.ok_or("none error".to_string())?
		.get("logs")
		.ok_or("none error".to_string())?
		.as_array()
		.ok_or("none error".to_string())?
		.iter()
		.filter_map(|x| {
			let x = x.as_str();
			match x {
				Some(x) => {
					let x = x.trim_start_matches("0x");
					match hex::decode(x) {
						Ok(x) => {
							let x: Option<DigestItem<Hash, AuthorityId, ()>> =
								Decode::decode(&mut &x[..]);
							x
						}
						Err(_) => None,
					}
				}
				None => None,
			}
		})
		.collect::<Vec<_>>();
	Ok(logs)
}

fn arrange_authorities(authorities: Vec<(AuthorityId, u64)>) -> Vec<(AuthorityId, u64)> {
	let mut map = HashMap::<AuthorityId, u64>::new();
	for (key, weight) in authorities {
		match map.entry(key) {
			Entry::Occupied(mut v) => {
				let v = v.get_mut();
				*v += weight;
			}
			Entry::Vacant(v) => {
				v.insert(weight);
			}
		}
	}
	map.into_iter().collect::<Vec<_>>()
}

pub fn arrange_block_info(
	(number, hash, shard, finality_tracker, crfg, pow): (
		u64,
		Hex,
		Option<(u16, u16)>,
		Option<u64>,
		Option<BlockCrfgInfo>,
		Option<PowSeal<Block, AuthorityId>>,
	),
) -> BlockInfo {
	let shard = shard.map(|x| BlockShardInfo {
		shard_num: x.0,
		shard_count: x.1,
	});

	let pow = pow.map(|x| {
		let timestamp = x.timestamp;
		let time = Local
			.timestamp_millis(timestamp as i64)
			.format("%Y-%m-%d %H:%M:%S %z")
			.to_string();
		let target = x.pow_target;

		let diff = format!("{}", target_to_diff(target));
		let target = full_target(target);

		BlockPowInfo {
			timestamp,
			time,
			target,
			diff,
		}
	});

	let finality_tracker = finality_tracker;

	BlockInfo {
		number,
		hash,
		shard,
		finality_tracker,
		crfg,
		pow,
	}
}

fn full_target(target: U256) -> Hex {
	let target: [u8; 32] = target.into();

	target.to_vec().into()
}

fn target_to_diff(target: U256) -> U256 {
	let diff = U256::max_value() / target;
	diff
}

type AuthorityId = [u8; 32];
type Hash = [u8; 32];

#[derive(Debug, Serialize)]
struct Meter {
	#[serde(skip_serializing_if = "Option::is_none")]
	best: Option<BlockInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	finalized: Option<BlockInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	system: Option<System>,
	#[serde(skip_serializing_if = "Option::is_none")]
	peers: Option<Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	network_state: Option<Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	foreign_network_state: Option<Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	runtime: Option<Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	crfg: Option<Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	foreign_status: Option<Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	config: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct System {
	pub name: Option<Value>,
	pub version: Option<Value>,
	pub chain: Option<Value>,
	pub health: Option<Value>,
}

#[derive(Debug, Serialize, Clone)]
pub struct BlockInfo {
	pub number: u64,
	pub hash: Hex,
	pub shard: Option<BlockShardInfo>,
	pub crfg: Option<BlockCrfgInfo>,
	pub finality_tracker: Option<u64>,
	pub pow: Option<BlockPowInfo>,
}

#[derive(Debug, Serialize, Clone)]
pub struct BlockShardInfo {
	pub shard_num: u16,
	pub shard_count: u16,
}

#[derive(Debug, Serialize, Clone)]
pub struct BlockPowInfo {
	pub timestamp: u64,
	pub time: String,
	pub target: Hex,
	pub diff: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct BlockCrfgInfo {
	pub signals: Vec<CrfgSignal>,
}

#[derive(Debug, Serialize, Clone)]
pub enum CrfgSignal {
	AuthoritiesChangeSignal(u64, Vec<(Hex, u64)>),
	ForcedAuthoritiesChangeSignal(u64, u64, Vec<(Hex, u64)>),
	SkipSignal(u64),
}

mod cases {
	use linked_hash_map::LinkedHashMap;

	use crate::modules::Case;

	pub fn cases() -> LinkedHashMap<&'static str, Vec<Case>> {
		vec![(
            "meter",
            vec![Case {
                desc: "".to_string(),
                input: vec!["-r", "http:://localhost:9033"]
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                output: vec![
                    r#"{
  "result": {
    "best": {
      "number": 1014,
      "hash": "0xb31892f4c36dcc32f617bbab595f711125035b28f3cf049f6762f77741450408",
      "shard": {
        "shard_num": 0,
        "shard_count": 4
      },
      "crfg": {
        "authorities": [
          [
            "0x5e9cb166bc21d67b352e97e9d58a8d629b8d1460eee846ed5bda410c3f627d68",
            7
          ],
          [
            "0xc260e48a949ae9fdcfc3386d82b59fa3cb5c9532323cdb48273bf1d1d6f635d9",
            6
          ]
        ]
      },
      "finality_tracker": 599,
      "pow": {
        "timestamp": 1596559492705,
        "time": "2020-08-05 00:44:52 +0800",
        "target": "0x000000000025c6d15c0e4d98207b94131ab05e43ef3b67e4567eb03387423018",
        "diff": "7451034177960"
      }
    },
    "finalized": {
      "number": 599,
      "hash": "0x57b5c972e795f498cecb11c5a2f9cdb64c1dd8bd8f7f7cd645ff1bc9c931bd80",
      "shard": {
        "shard_num": 0,
        "shard_count": 4
      },
      "crfg": {
        "authorities": [
          [
            "0xc260e48a949ae9fdcfc3386d82b59fa3cb5c9532323cdb48273bf1d1d6f635d9",
            5
          ],
          [
            "0x5e9cb166bc21d67b352e97e9d58a8d629b8d1460eee846ed5bda410c3f627d68",
            8
          ]
        ]
      },
      "finality_tracker": 263,
      "pow": {
        "timestamp": 1596548222470,
        "time": "2020-08-04 21:37:02 +0800",
        "target": "0x0000000000513b440c262e9b30243ae100d6afa94f379a132a598f348526f0d0",
        "diff": "3465096079798"
      }
    },
    "system": {
      "name": "yee-node",
      "version": "1.0.0",
      "chain": "MainNet",
      "health": {
        "isSyncing": false,
        "peers": 3,
        "shouldHavePeers": true
      }
    },
    "peers": [
      {
        "bestHash": "0xb31892f4c36dcc32f617bbab595f711125035b28f3cf049f6762f77741450408",
        "bestNumber": 1014,
        "peerId": "QmZbiMcajnp8tk8Z4ABZNBftUYwwRxgPRuhFWx1xcGWxqB",
        "protocolVersion": 2,
        "roles": "AUTHORITY"
      },
      {
        "bestHash": "0xb31892f4c36dcc32f617bbab595f711125035b28f3cf049f6762f77741450408",
        "bestNumber": 1014,
        "peerId": "QmSCedDkPpM48ddde6U18nQCA7A3Em4dHSnueCyMbbPk6b",
        "protocolVersion": 2,
        "roles": "AUTHORITY"
      },
      {
        "bestHash": "0xb31892f4c36dcc32f617bbab595f711125035b28f3cf049f6762f77741450408",
        "bestNumber": 1014,
        "peerId": "QmNLyDrFZYr7AZ3gvxH1qz5U2gQyH7ddvhWFQJ9X3ubpc6",
        "protocolVersion": 2,
        "roles": "AUTHORITY"
      }
    ],
    "network_state": {
      "averageDownloadPerSec": 5576,
      "averageUploadPerSec": 3367,
      "connectedPeers": {
        "QmNLyDrFZYr7AZ3gvxH1qz5U2gQyH7ddvhWFQJ9X3ubpc6": {
          "enabled": true,
          "endpoint": {
            "dialing": "/ip4/106.75.126.55/tcp/30330"
          },
          "knownAddresses": [
            "/ip4/172.17.0.1/tcp/30330",
            "/ip4/127.0.0.1/tcp/30330",
            "/ip4/10.32.75.19/tcp/30330",
            "/ip4/106.75.126.55/tcp/30330",
            "/ip6/::1/tcp/30330"
          ],
          "latestPingTime": {
            "nanos": 295129761,
            "secs": 0
          },
          "open": true,
          "versionString": "yee-node/v1.0.0-36818e9-x86_64-linux-gnu (unknown) shard/0"
        },
        "QmSCedDkPpM48ddde6U18nQCA7A3Em4dHSnueCyMbbPk6b": {
          "enabled": true,
          "endpoint": {
            "dialing": "/ip4/23.91.98.161/tcp/30330"
          },
          "knownAddresses": [
            "/ip4/10.32.31.32/tcp/30330",
            "/ip6/::1/tcp/30330",
            "/ip4/172.17.0.1/tcp/30330",
            "/ip4/23.91.98.161/tcp/30330",
            "/ip4/127.0.0.1/tcp/30330"
          ],
          "latestPingTime": {
            "nanos": 190620274,
            "secs": 0
          },
          "open": true,
          "versionString": "yee-node/v1.0.0-36818e9-x86_64-linux-gnu (unknown) shard/0"
        },
        "QmZbiMcajnp8tk8Z4ABZNBftUYwwRxgPRuhFWx1xcGWxqB": {
          "enabled": true,
          "endpoint": {
            "dialing": "/ip4/106.75.164.126/tcp/30330"
          },
          "knownAddresses": [
            "/ip4/172.17.0.1/tcp/30330",
            "/ip4/127.0.0.1/tcp/30330",
            "/ip4/10.32.41.236/tcp/30330",
            "/ip4/106.75.164.126/tcp/30330",
            "/ip6/::1/tcp/30330"
          ],
          "latestPingTime": null,
          "open": true,
          "versionString": null
        }
      },
      "externalAddresses": [
        "/ip4/120.244.142.175/tcp/30333"
      ],
      "listenedAddresses": [
        "/ip4/127.0.0.1/tcp/30333",
        "/ip4/192.168.0.106/tcp/30333",
        "/ip6/::1/tcp/30333"
      ],
      "notConnectedPeers": {
        "QmRSp7S9Xr693fQX1492ZYW8ZcNitnN8QAUAzZ7S4EXHpS": {
          "knownAddresses": [
            "/ip4/127.0.0.1/tcp/30330",
            "/ip4/118.193.34.63/tcp/30330",
            "/ip6/::1/tcp/30330",
            "/ip4/172.17.0.1/tcp/30330",
            "/ip4/10.32.18.239/tcp/30330"
          ]
        },
        "QmT1sLeDfwo1ZBfne9kEWdE12eBu5ShDdsjZeoXNfoPk5r": {
          "knownAddresses": [
            "/ip4/10.32.33.113/tcp/30330",
            "/ip4/106.75.139.215/tcp/30330",
            "/ip4/172.17.0.1/tcp/30330",
            "/ip4/127.0.0.1/tcp/30330",
            "/ip6/::1/tcp/30330"
          ]
        },
        "QmcaJubwQgzA3ufMhHHgPpAef3M1vgP2b9hDhqPTgtddTq": {
          "knownAddresses": [
            "/ip4/10.32.77.255/tcp/30330",
            "/ip4/127.0.0.1/tcp/30330",
            "/ip4/106.75.36.3/tcp/30330",
            "/ip6/::1/tcp/30330",
            "/ip4/172.17.0.1/tcp/30330"
          ]
        }
      },
      "peerId": "QmbSxfcCnQsYPUVukZ2XJ2jZEZ1MkdSsDjsfXS1ZuENS4o",
      "peerset": null
    },
    "foreign_network_state": {
      "averageDownloadPerSec": 6828,
      "averageUploadPerSec": 3175,
      "connectedPeers": {
        "QmR2FG5qrPyitoYVfXSBp7oUZd1wibfcdnVpEFFyfcC6WV": {
          "enabled": true,
          "endpoint": {
            "dialing": "/ip4/23.91.98.161/tcp/31332"
          },
          "knownAddresses": [
            "/ip6/::1/tcp/31332",
            "/ip4/172.17.0.1/tcp/31332",
            "/ip4/23.91.98.161/tcp/31332",
            "/ip4/127.0.0.1/tcp/31332",
            "/ip4/10.32.31.32/tcp/31332"
          ],
          "latestPingTime": null,
          "open": true,
          "shardNum": 2,
          "versionString": null
        },
        "QmW4fZGZdQNBiVcvyaPdXDHWKfY97ZV2HLrZPHRpNWE7cu": {
          "enabled": true,
          "endpoint": {
            "dialing": "/ip4/23.91.98.161/tcp/31333"
          },
          "knownAddresses": [
            "/ip4/10.32.31.32/tcp/31333",
            "/ip4/127.0.0.1/tcp/31333",
            "/ip4/172.17.0.1/tcp/31333",
            "/ip4/23.91.98.161/tcp/31333",
            "/ip6/::1/tcp/31333"
          ],
          "latestPingTime": null,
          "open": true,
          "shardNum": 3,
          "versionString": null
        },
        "QmYPXN6NCLfWL7Zi5BErStYPTyGYZFakNYhZ2jtYXMoCo5": {
          "enabled": true,
          "endpoint": {
            "dialing": "/ip4/106.75.126.55/tcp/31333"
          },
          "knownAddresses": [
            "/ip4/172.17.0.1/tcp/31333",
            "/ip4/10.32.75.19/tcp/31333",
            "/ip6/::1/tcp/31333",
            "/ip4/127.0.0.1/tcp/31333",
            "/ip4/106.75.126.55/tcp/31333"
          ],
          "latestPingTime": {
            "nanos": 60517803,
            "secs": 0
          },
          "open": true,
          "shardNum": 3,
          "versionString": "yee-node/v1.0.0-36818e9-x86_64-linux-gnu (foreign-unknown) shard/3"
        },
        "QmZbZUin2WnCFLQX2TJEMyMdPYvvNE5rFL8GgzrvDeB65A": {
          "enabled": true,
          "endpoint": {
            "dialing": "/ip4/106.75.126.55/tcp/31332"
          },
          "knownAddresses": [
            "/ip6/::1/tcp/31332",
            "/ip4/10.32.75.19/tcp/31332",
            "/ip4/127.0.0.1/tcp/31332",
            "/ip4/106.75.126.55/tcp/31332",
            "/ip4/172.17.0.1/tcp/31332"
          ],
          "latestPingTime": {
            "nanos": 40697060,
            "secs": 0
          },
          "open": true,
          "shardNum": 2,
          "versionString": "yee-node/v1.0.0-36818e9-x86_64-linux-gnu (foreign-unknown) shard/2"
        },
        "QmaTTCJFBXBB3jqMzrHQwvPPhC2thGG8WY7SD73FDMbUdC": {
          "enabled": true,
          "endpoint": {
            "dialing": "/ip4/23.91.98.161/tcp/31331"
          },
          "knownAddresses": [
            "/ip4/127.0.0.1/tcp/31331",
            "/ip4/23.91.98.161/tcp/31331",
            "/ip4/172.17.0.1/tcp/31331",
            "/ip6/::1/tcp/31331",
            "/ip4/10.32.31.32/tcp/31331"
          ],
          "latestPingTime": {
            "nanos": 272428727,
            "secs": 0
          },
          "open": true,
          "shardNum": 1,
          "versionString": "yee-node/v1.0.0-36818e9-x86_64-linux-gnu (foreign-unknown) shard/1"
        },
        "Qmd5cFPXiaFq2T41hENgPXLK5vRrCu7DqKboNKjQqYy8CV": {
          "enabled": true,
          "endpoint": {
            "dialing": "/ip4/106.75.126.55/tcp/31331"
          },
          "knownAddresses": [
            "/ip6/::1/tcp/31331",
            "/ip4/10.32.75.19/tcp/31331",
            "/ip4/106.75.126.55/tcp/31331",
            "/ip4/172.17.0.1/tcp/31331",
            "/ip4/127.0.0.1/tcp/31331"
          ],
          "latestPingTime": null,
          "open": true,
          "shardNum": 1,
          "versionString": null
        },
        "QmejwAm1EsaSmiYmFL2EiFPVyRnqsUmUB47fJA3v5fn7yg": {
          "enabled": true,
          "endpoint": {
            "dialing": "/ip4/106.75.164.126/tcp/31331"
          },
          "knownAddresses": [
            "/ip4/127.0.0.1/tcp/31331",
            "/ip4/10.32.41.236/tcp/31331",
            "/ip6/::1/tcp/31331",
            "/ip4/172.17.0.1/tcp/31331",
            "/ip4/106.75.164.126/tcp/31331"
          ],
          "latestPingTime": {
            "nanos": 77130512,
            "secs": 0
          },
          "open": true,
          "shardNum": 1,
          "versionString": null
        }
      },
      "externalAddresses": [
        "/ip4/120.244.142.175/tcp/30334"
      ],
      "listenedAddresses": [
        "/ip4/127.0.0.1/tcp/30334",
        "/ip4/192.168.0.106/tcp/30334",
        "/ip6/::1/tcp/30334"
      ],
      "notConnectedPeers": {
        "QmRU3t8p4v8trYPwc7gQLAQaPc4GGVP83RVFmkYUQg3LKo": {
          "knownAddresses": [
            "/ip4/10.32.33.113/tcp/31333",
            "/ip4/106.75.139.215/tcp/31333",
            "/ip4/172.17.0.1/tcp/31333",
            "/ip4/127.0.0.1/tcp/31333",
            "/ip6/::1/tcp/31333"
          ]
        },
        "QmS1rRFdptHCNHxtyBTT4GbMHrYG7RRJQvJdDsLdFaAeBH": {
          "knownAddresses": [
            "/ip4/10.32.31.32/tcp/31330",
            "/ip6/::1/tcp/31330",
            "/ip4/127.0.0.1/tcp/31330",
            "/ip4/23.91.98.161/tcp/31330",
            "/ip4/172.17.0.1/tcp/31330"
          ]
        },
        "QmSYULj88vGXfQKw7SkpPj7ezW2es8tfJeGdra3T1F9W3k": {
          "knownAddresses": [
            "/ip4/10.32.41.236/tcp/31333",
            "/ip4/127.0.0.1/tcp/31333",
            "/ip4/106.75.164.126/tcp/31333",
            "/ip4/106.75.164.126/tcp/30333",
            "/ip4/172.17.0.1/tcp/31333",
            "/ip6/::1/tcp/31333"
          ]
        },
        "QmTbTYa2KS8p6yNREEWQSFjDkBWgrw16oNYvyQNMhunYZp": {
          "knownAddresses": [
            "/ip6/::1/tcp/31331",
            "/ip4/172.17.0.1/tcp/31331",
            "/ip4/106.75.139.215/tcp/31331",
            "/ip4/10.32.33.113/tcp/31331",
            "/ip4/127.0.0.1/tcp/31331"
          ]
        },
        "QmU3zWXUA5TgdZeVdq4NFLuh5pFf7e6atnjCcF2J17FB4J": {
          "knownAddresses": [
            "/ip4/10.32.18.239/tcp/31333",
            "/ip4/118.193.34.63/tcp/31333",
            "/ip6/::1/tcp/31333",
            "/ip4/127.0.0.1/tcp/31333",
            "/ip4/172.17.0.1/tcp/31333"
          ]
        },
        "QmVvQByF9cLcX3sMjxJ3QRXFVUiVEcmnv23LBTWyok7oDJ": {
          "knownAddresses": [
            "/ip4/10.32.41.236/tcp/31332",
            "/ip4/106.75.164.126/tcp/31332",
            "/ip4/172.17.0.1/tcp/31332",
            "/ip6/::1/tcp/31332",
            "/ip4/127.0.0.1/tcp/31332"
          ]
        },
        "QmYCMbGesoMvHoxmWCqv1Co92p798LXrAaQAfGDbV7nWXG": {
          "knownAddresses": [
            "/ip6/::1/tcp/31333",
            "/ip4/106.75.36.3/tcp/31333",
            "/ip4/10.32.77.255/tcp/31333",
            "/ip4/127.0.0.1/tcp/31333",
            "/ip4/172.17.0.1/tcp/31333"
          ]
        },
        "QmZ47pBx47UsaNAVaMLapPuy58z9vBFsJnXdKyLiUYKhn5": {
          "knownAddresses": [
            "/ip4/118.193.34.63/tcp/31331",
            "/ip6/::1/tcp/31331",
            "/ip4/127.0.0.1/tcp/31331",
            "/ip4/10.32.18.239/tcp/31331",
            "/ip4/172.17.0.1/tcp/31331"
          ]
        },
        "Qma1uXm7EsjwNs8Juu55rTeo7fhFPs9XRvcCeYrca7jS6a": {
          "knownAddresses": [
            "/ip4/127.0.0.1/tcp/31332",
            "/ip4/106.75.36.3/tcp/31332",
            "/ip4/172.17.0.1/tcp/31332",
            "/ip4/10.32.77.255/tcp/31332",
            "/ip6/::1/tcp/31332"
          ]
        },
        "QmaaXBAQk5tVafVkuAYeasMh2H1Pk3vBVpMYdAyRzNptZy": {
          "knownAddresses": [
            "/ip4/127.0.0.1/tcp/31331",
            "/ip4/106.75.36.3/tcp/31331",
            "/ip6/::1/tcp/31331",
            "/ip4/10.32.77.255/tcp/31331",
            "/ip4/172.17.0.1/tcp/31331"
          ]
        },
        "QmbyrEK4tPnR4xytoeoHKjQ3kpx7s5XThCgDXmStD6xzS1": {
          "knownAddresses": [
            "/ip4/118.193.34.63/tcp/31332",
            "/ip4/172.17.0.1/tcp/31332",
            "/ip4/127.0.0.1/tcp/31332",
            "/ip6/::1/tcp/31332",
            "/ip4/10.32.18.239/tcp/31332"
          ]
        },
        "QmcpALPHtpuowhJcUGtQ9Ac3Zk5Ag6TaFJtPeWALN4gXck": {
          "knownAddresses": [
            "/ip4/106.75.126.55/tcp/31330",
            "/ip6/::1/tcp/31330",
            "/ip4/127.0.0.1/tcp/31330",
            "/ip4/172.17.0.1/tcp/31330",
            "/ip4/10.32.75.19/tcp/31330"
          ]
        },
        "Qmd6ZUcEfzq1BzB3njvM3zzgfhgHyvSxwesgwccasReyXM": {
          "knownAddresses": [
            "/ip4/10.32.33.113/tcp/31332",
            "/ip4/127.0.0.1/tcp/31332",
            "/ip4/172.17.0.1/tcp/31332",
            "/ip6/::1/tcp/31332",
            "/ip4/106.75.139.215/tcp/31332"
          ]
        }
      },
      "peerId": "QmbQ6rdmDAqo4TKxPRybPSEtY8Kp2v5cGvkVVSRuJfy5rd",
      "peerset": "{3: Peerset { data: PeersetData { discovered: Discovered { reserved: {}, common: {} }, reserved_only: false, out_slots: Slots { max_slots: 200, slots: {PeerId(\"QmSYULj88vGXfQKw7SkpPj7ezW2es8tfJeGdra3T1F9W3k\"): Common, PeerId(\"QmRU3t8p4v8trYPwc7gQLAQaPc4GGVP83RVFmkYUQg3LKo\"): Common, PeerId(\"QmYPXN6NCLfWL7Zi5BErStYPTyGYZFakNYhZ2jtYXMoCo5\"): Common, PeerId(\"QmYCMbGesoMvHoxmWCqv1Co92p798LXrAaQAfGDbV7nWXG\"): Common, PeerId(\"QmW4fZGZdQNBiVcvyaPdXDHWKfY97ZV2HLrZPHRpNWE7cu\"): Common, PeerId(\"QmU3zWXUA5TgdZeVdq4NFLuh5pFf7e6atnjCcF2J17FB4J\"): Common} }, in_slots: Slots { max_slots: 100, slots: {} }, scores: {} }, rx: UnboundedReceiver(Receiver { inner: Inner { buffer: None, state: 9223372036854775808, message_queue: Queue { head: 0x7f8764c52f10, tail: UnsafeCell }, parked_queue: Queue { head: 0x7f8764c69a10, tail: UnsafeCell }, num_senders: 1, recv_task: Mutex { data: ReceiverTask { unparked: false, task: Some(Task) } } } }), message_queue: [] }, 2: Peerset { data: PeersetData { discovered: Discovered { reserved: {}, common: {} }, reserved_only: false, out_slots: Slots { max_slots: 200, slots: {PeerId(\"QmVvQByF9cLcX3sMjxJ3QRXFVUiVEcmnv23LBTWyok7oDJ\"): Common, PeerId(\"Qmd6ZUcEfzq1BzB3njvM3zzgfhgHyvSxwesgwccasReyXM\"): Common, PeerId(\"QmZbZUin2WnCFLQX2TJEMyMdPYvvNE5rFL8GgzrvDeB65A\"): Common, PeerId(\"Qma1uXm7EsjwNs8Juu55rTeo7fhFPs9XRvcCeYrca7jS6a\"): Common, PeerId(\"QmR2FG5qrPyitoYVfXSBp7oUZd1wibfcdnVpEFFyfcC6WV\"): Common, PeerId(\"QmbyrEK4tPnR4xytoeoHKjQ3kpx7s5XThCgDXmStD6xzS1\"): Common} }, in_slots: Slots { max_slots: 100, slots: {} }, scores: {} }, rx: UnboundedReceiver(Receiver { inner: Inner { buffer: None, state: 9223372036854775808, message_queue: Queue { head: 0x7f876684ab30, tail: UnsafeCell }, parked_queue: Queue { head: 0x7f8766852600, tail: UnsafeCell }, num_senders: 1, recv_task: Mutex { data: ReceiverTask { unparked: false, task: Some(Task) } } } }), message_queue: [] }, 1: Peerset { data: PeersetData { discovered: Discovered { reserved: {}, common: {} }, reserved_only: false, out_slots: Slots { max_slots: 200, slots: {PeerId(\"QmejwAm1EsaSmiYmFL2EiFPVyRnqsUmUB47fJA3v5fn7yg\"): Common, PeerId(\"QmTbTYa2KS8p6yNREEWQSFjDkBWgrw16oNYvyQNMhunYZp\"): Common, PeerId(\"Qmd5cFPXiaFq2T41hENgPXLK5vRrCu7DqKboNKjQqYy8CV\"): Common, PeerId(\"QmaaXBAQk5tVafVkuAYeasMh2H1Pk3vBVpMYdAyRzNptZy\"): Common, PeerId(\"QmaTTCJFBXBB3jqMzrHQwvPPhC2thGG8WY7SD73FDMbUdC\"): Common, PeerId(\"QmZ47pBx47UsaNAVaMLapPuy58z9vBFsJnXdKyLiUYKhn5\"): Common} }, in_slots: Slots { max_slots: 100, slots: {} }, scores: {} }, rx: UnboundedReceiver(Receiver { inner: Inner { buffer: None, state: 9223372036854775808, message_queue: Queue { head: 0x7f8764c5b6f0, tail: UnsafeCell }, parked_queue: Queue { head: 0x7f8764c57880, tail: UnsafeCell }, num_senders: 1, recv_task: Mutex { data: ReceiverTask { unparked: false, task: Some(Task) } } } }), message_queue: [] }}"
    },
    "runtime": {
      "apis": [
        [
          "0xdf6acb689907609b",
          2
        ],
        [
          "0x37e397fc7c91f5e4",
          1
        ],
        [
          "0x40fe3ad401f8959a",
          3
        ],
        [
          "0xd2bc9897eed08f15",
          1
        ],
        [
          "0x1e6525524a4d44ac",
          1
        ],
        [
          "0xf78b278be53f454c",
          1
        ],
        [
          "0x7801759919ee83e5",
          1
        ],
        [
          "0x47aa0c87543ebabb",
          2
        ],
        [
          "0x6eb83e3f57eeeff6",
          1
        ]
      ],
      "authoringVersion": 3,
      "implName": "yee-rs",
      "implVersion": 4,
      "specName": "yee",
      "specVersion": 4
    },
    "crfg": {
      "config": {
        "gossip_duration": {
          "nanos": 333000000,
          "secs": 0
        },
        "justification_period": 4096,
        "local_key_public": "0x95a781554f633b47262d5e9264522c8abc8af77d4afae1441832b40e5f0f2e99",
        "local_next_key_public": null,
        "name": "zealous-slope-5574"
      },
      "set_id": 599,
      "set_status": {
        "Live": [
          0,
          {
            "completable": true,
            "estimate": [
              "0x57b5c972e795f498cecb11c5a2f9cdb64c1dd8bd8f7f7cd645ff1bc9c931bd80",
              599
            ],
            "finalized": [
              "0x57b5c972e795f498cecb11c5a2f9cdb64c1dd8bd8f7f7cd645ff1bc9c931bd80",
              599
            ],
            "prevote_ghost": [
              "0x57b5c972e795f498cecb11c5a2f9cdb64c1dd8bd8f7f7cd645ff1bc9c931bd80",
              599
            ]
          }
        ]
      },
      "voters": {
        "threshold": 9,
        "voters": [
          [
            "0x5e9cb166bc21d67b352e97e9d58a8d629b8d1460eee846ed5bda410c3f627d68",
            8
          ],
          [
            "0xc260e48a949ae9fdcfc3386d82b59fa3cb5c9532323cdb48273bf1d1d6f635d9",
            5
          ]
        ],
        "weights": {
          "0x5e9cb166bc21d67b352e97e9d58a8d629b8d1460eee846ed5bda410c3f627d68": {
            "canon_idx": 0,
            "weight": 8
          },
          "0xc260e48a949ae9fdcfc3386d82b59fa3cb5c9532323cdb48273bf1d1d6f635d9": {
            "canon_idx": 1,
            "weight": 5
          }
        }
      }
    },
    "foreign_status": {
      "0": {
        "best_hash": "0xb31892f4c36dcc32f617bbab595f711125035b28f3cf049f6762f77741450408",
        "best_number": 1014,
        "finalized_hash": "0x57b5c972e795f498cecb11c5a2f9cdb64c1dd8bd8f7f7cd645ff1bc9c931bd80",
        "finalized_number": 599
      },
      "1": {
        "best_hash": "0x5d83c7463a3a37d3d20b11c448f01fb9d28dccb357bb0fa4db450c6e6dca7d5d",
        "best_number": 1009,
        "finalized_hash": "0x8dbb976ef26f0bd52c607547d381e6bce1cfe0c851a09801c573eb05b4eead7f",
        "finalized_number": 974
      },
      "2": {
        "best_hash": "0xb0269cc97349501fc11442b8b2f2364ae25cf24483f5b6cab1480f7b10047809",
        "best_number": 559,
        "finalized_hash": "0xf69a4a03f4b024f879d3f3dd66cd235a1202d6c80100bdac295f416eb4ceaedc",
        "finalized_number": 553
      },
      "3": {
        "best_hash": "0xce9987d852973bc35ad7edd99113c3bc8aa0d6e34b597150aaf8b841a2524650",
        "best_number": 934,
        "finalized_hash": "0x1b4fe790a63c37ceb9960ae043d2d6bb6da78262ba6b5709b5d9444e5e55070d",
        "finalized_number": 645
      }
    },
    "config": {
      "coinbase": "yee1zqe7q4mgy2n2sdhkz2sexqmqggzsu2rd53tp7hx9mrh9vrrym32qzlkq6f"
    }
  }
}"#,
                ]
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                is_example: true,
                is_test: false,
                since: "0.1.0".to_string(),
            }],
        )]
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
