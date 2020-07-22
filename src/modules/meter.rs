use std::collections::{hash_map::Entry, HashMap};

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
use yee_runtime::opaque::Block;
use yee_sharding::ShardingDigestItem;

use crate::modules::base::Hex;
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
		app: SubCommand::with_name("meter").about("Meter").arg(
			Arg::with_name("RPC")
				.long("rpc")
				.short("r")
				.help("RPC address")
				.takes_value(true)
				.required(true),
		),
		f: meter,
	}]
}

fn meter(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let rpc = matches.value_of("RPC").expect("qed");

	let mut runtime = Runtime::new().expect("qed");

	let meter = runtime.block_on(get_meter(rpc));

	base::output(meter)
}

async fn get_meter(rpc: &str) -> Meter {
	let system = get_system(rpc);

	let runtime = get_runtime(rpc);

	let crfg = get_crfg(rpc);

	let chain = get_chain(rpc);

	let (system, runtime, crfg, chain) = tokio::join!(system, runtime, crfg, chain);

	let meter = Meter {
		chain: chain.ok(),
		system: system.ok(),
		runtime: runtime.ok(),
		crfg: crfg.ok(),
	};

	meter
}

async fn get_system(rpc: &str) -> Result<System, String> {
	let name = base::rpc_call::<_, Value>(rpc, "system_name", &());

	let version = base::rpc_call::<_, Value>(rpc, "system_version", &());

	let chain = base::rpc_call::<_, Value>(rpc, "system_chain", &());

	let health = base::rpc_call::<_, Value>(rpc, "system_health", &());

	let peers = base::rpc_call::<_, Value>(rpc, "system_peers", &());

	let network_state = base::rpc_call::<_, Value>(rpc, "system_networkState", &());

	let result = join_all(vec![name, version, chain, health, peers, network_state]).await;

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
		peers: extract(result[4].take()),
		network_state: extract(result[5].take()),
	};

	Ok(system)
}

async fn get_runtime(rpc: &str) -> Result<Value, String> {
	let runtime = base::rpc_call::<_, Value>(rpc, "state_getRuntimeVersion", &()).await;

	let extract = |x: Result<base::RpcResponse<Value>, String>| -> Result<Value, String> {
		match x {
			Ok(x) => match x.result {
				Some(x) => Ok(x),
				None => Err("none error".to_string()),
			},
			Err(e) => Err(e),
		}
	};

	extract(runtime)
}

async fn get_crfg(rpc: &str) -> Result<Value, String> {
	let runtime = base::rpc_call::<_, Value>(rpc, "crfg_state", &()).await;

	let extract = |x: Result<base::RpcResponse<Value>, String>| -> Result<Value, String> {
		match x {
			Ok(x) => match x.result {
				Some(x) => Ok(x),
				None => Err("".to_string()),
			},
			Err(e) => Err(e),
		}
	};

	extract(runtime)
}

async fn get_chain(rpc: &str) -> Result<Chain, String> {
	let best = get_block_info(None, rpc).await?;

	let finalized_number = best.3;

	let finalized = match finalized_number {
		Some(n) => Some(get_block_info(Some(n), rpc).await?),
		None => None,
	};

	let best = arrange_block_info(best);
	let finalized = finalized.map(arrange_block_info);

	let chain = Chain {
		best: Some(best),
		finalized,
	};

	Ok(chain)
}

pub async fn get_block_info(
	number: Option<u64>,
	rpc: &str,
) -> Result<
	(
		u64,
		String,
		Option<(u16, u16)>,
		Option<u64>,
		Option<(u64, Vec<(AuthorityId, u64)>)>,
		Option<PowSeal<Block, AuthorityId>>,
	),
	String,
> {
	const CRFG_LOG_PREFIX: u8 = 3;

	let (header, number, hash) = match number {
		Some(number) => {
			let hash = base::rpc_call::<_, String>(rpc, "chain_getBlockHash", &[number])
				.await?
				.result
				.ok_or("decode failed".to_string())?;
			let header = base::rpc_call::<_, Value>(rpc, "chain_getHeader", &[&hash])
				.await?
				.result
				.ok_or("decode failed".to_string())?;
			(header, number, hash)
		}
		None => {
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
			(header, number, hash)
		}
	};

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

	let authorities = logs
		.iter()
		.filter_map(|x| match x {
			DigestItem::Other(data)
				if data.len() >= 2 && data[0] == CRFG_LOG_PREFIX && data[1] == 0 =>
			{
				let input = &mut &data[2..];
				let x: (u64, Vec<(AuthorityId, u64)>) = Decode::decode(input)?;
				Some(x)
			}
			_ => None,
		})
		.next()
		.map(arrange_authorities);

	let pow: Option<PowSeal<Block, AuthorityId>> = logs
		.iter()
		.filter_map(CompatibleDigestItem::as_pow_seal)
		.next();

	Ok((number, hash, shard_info, finalized_number, authorities, pow))
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

fn arrange_authorities(
	authorities: (u64, Vec<(AuthorityId, u64)>),
) -> (u64, Vec<(AuthorityId, u64)>) {
	let (delay, list) = authorities;

	let mut map = HashMap::<AuthorityId, u64>::new();
	for (key, weight) in list {
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

	(delay, map.into_iter().collect::<Vec<_>>())
}

fn arrange_block_info(
	(number, hash, shard, _, authorities, pow): (
		u64,
		String,
		Option<(u16, u16)>,
		Option<u64>,
		Option<(u64, Vec<(AuthorityId, u64)>)>,
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

	let crfg = authorities.map(|x| BlockCrfgInfo {
		authorities: x
			.1
			.into_iter()
			.map(|(a, w)| (a.to_vec().into(), w))
			.collect::<Vec<_>>(),
	});

	BlockInfo {
		number,
		hash,
		shard,
		pow,
		crfg,
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
	chain: Option<Chain>,
	system: Option<System>,
	runtime: Option<Value>,
	crfg: Option<Value>,
}

#[derive(Debug, Serialize)]
struct System {
	name: Option<Value>,
	version: Option<Value>,
	chain: Option<Value>,
	health: Option<Value>,
	peers: Option<Value>,
	network_state: Option<Value>,
}

#[derive(Debug, Serialize)]
struct Chain {
	best: Option<BlockInfo>,
	finalized: Option<BlockInfo>,
}

#[derive(Debug, Serialize)]
struct BlockInfo {
	number: u64,
	hash: String,
	shard: Option<BlockShardInfo>,
	pow: Option<BlockPowInfo>,
	crfg: Option<BlockCrfgInfo>,
}

#[derive(Debug, Serialize)]
struct BlockShardInfo {
	shard_num: u16,
	shard_count: u16,
}

#[derive(Debug, Serialize)]
struct BlockPowInfo {
	timestamp: u64,
	time: String,
	target: Hex,
	diff: String,
}

#[derive(Debug, Serialize)]
struct BlockCrfgInfo {
	authorities: Vec<(Hex, u64)>,
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
    "chain": {
      "best": {
        "number": 45,
        "hash": "0x000004c65b2e9240dd85ddb101aef17d0cf2c2fdbe133ad9b44e870b445292d0",
        "shard": {
          "shard_num": 0,
          "shard_count": 4
        },
        "pow": {
          "timestamp": 1595251179978,
          "time": "2020-07-20 21:19:39 +0800",
          "target": "0x0000ffff00000000000000000000000000000000000000000000000000000000",
          "diff": "65537"
        },
        "crfg": {
          "authorities": [
            [
              "0x162a9760f58ba60b03dc97bfe7af8f748ee2a0e8c73718821aeed5303304c8b7",
              13
            ]
          ]
        }
      },
      "finalized": {
        "number": 38,
        "hash": "0x0000fd222b6c373a05b9641c2eaf16b896794e95ceb3cb44946e19495ddd193b",
        "shard": {
          "shard_num": 0,
          "shard_count": 4
        },
        "pow": {
          "timestamp": 1595250973546,
          "time": "2020-07-20 21:16:13 +0800",
          "target": "0x0000ffff00000000000000000000000000000000000000000000000000000000",
          "diff": "65537"
        },
        "crfg": {
          "authorities": [
            [
              "0x162a9760f58ba60b03dc97bfe7af8f748ee2a0e8c73718821aeed5303304c8b7",
              13
            ]
          ]
        }
      }
    },
    "system": {
      "name": "yee-node",
      "version": "0.6.0",
      "chain": "Development",
      "health": {
        "isSyncing": false,
        "peers": 0,
        "shouldHavePeers": true
      },
      "peers": [],
      "network_state": {
        "averageDownloadPerSec": 0,
        "averageUploadPerSec": 0,
        "connectedPeers": {},
        "externalAddresses": [],
        "listenedAddresses": [
          "/ip6/::1/tcp/30333",
          "/ip4/127.0.0.1/tcp/30333",
          "/ip4/192.168.0.106/tcp/30333"
        ],
        "notConnectedPeers": {},
        "peerId": "QmQZ8TjTqeDj3ciwr93EJ95hxfDsb9pEYDizUAbWpigtQN",
        "peerset": null
      }
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
        "local_key_public": "0x162a9760f58ba60b03dc97bfe7af8f748ee2a0e8c73718821aeed5303304c8b7",
        "local_next_key_public": null,
        "name": "rebel-linen-7201"
      },
      "set_id": 39,
      "set_status": {
        "Live": [
          2,
          {
            "completable": true,
            "estimate": [
              "0x0000da5aee921dd40703acab9b9e221356ba98c48e90a78f9f601bc9116c54ac",
              39
            ],
            "finalized": [
              "0x0000da5aee921dd40703acab9b9e221356ba98c48e90a78f9f601bc9116c54ac",
              39
            ],
            "prevote_ghost": [
              "0x0000da5aee921dd40703acab9b9e221356ba98c48e90a78f9f601bc9116c54ac",
              39
            ]
          }
        ]
      },
      "voters": {
        "threshold": 9,
        "voters": [
          [
            "0x162a9760f58ba60b03dc97bfe7af8f748ee2a0e8c73718821aeed5303304c8b7",
            13
          ]
        ],
        "weights": {
          "0x162a9760f58ba60b03dc97bfe7af8f748ee2a0e8c73718821aeed5303304c8b7": {
            "canon_idx": 0,
            "weight": 13
          }
        }
      }
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
