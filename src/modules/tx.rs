use std::cmp::min;
use std::str::FromStr;

use clap::{Arg, ArgMatches, SubCommand};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use parity_codec::alloc::borrow::Cow;
use parity_codec::alloc::collections::{hash_map::Entry, HashMap};
use parity_codec::{Compact, Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use srml_system::{EventRecord, Phase};
use substrate_primitives::blake2_256;
use substrate_primitives::storage::StorageData;
use tokio::runtime::Runtime;
use yee_primitives::AddressCodec;
use yee_primitives::Hrp;
use yee_runtime::Event;
use yee_sharding_primitives::utils;
use yee_signer::tx::call::Call;
use yee_signer::tx::types::{Era, Transaction, HASH_LEN};
use yee_signer::tx::{build_call, build_tx};
use yee_signer::{KeyPair, PUBLIC_KEY_LEN, SECRET_KEY_LEN};

use crate::modules::base::{get_rpc, Hex, RpcResponse};
use crate::modules::keystore::get_keystore;
use crate::modules::meter::{get_block_info, Number};
use crate::modules::state::{get_map_storage_key_encode, get_value_storage_key};
use crate::modules::{base, Command, Module};

pub fn module<'a, 'b>() -> Module<'a, 'b> {
	Module {
		desc: "Tx tools".to_string(),
		commands: commands(),
		get_cases: cases::cases,
	}
}

pub fn commands<'a, 'b>() -> Vec<Command<'a, 'b>> {
	let mut app = SubCommand::with_name("tx").about("Tx tools");
	for sub_command in sub_commands() {
		app = app.subcommand(sub_command.app);
	}
	let f = run;

	vec![Command { app, f }]
}

fn run(matches: &ArgMatches) -> Result<Vec<String>, String> {
	base::run(matches, || sub_commands(), || commands())
}

fn sub_commands<'a, 'b>() -> Vec<Command<'a, 'b>> {
	vec![
		Command {
			app: SubCommand::with_name("desc").about("Desc tx").arg(
				Arg::with_name("INPUT")
					.help("raw tx")
					.required(false)
					.index(1),
			),
			f: desc,
		},
		Command {
			app: SubCommand::with_name("compose")
				.about("Compose tx")
				.arg(
					Arg::with_name("RPC")
						.long("rpc")
						.short("r")
						.help("RPC address")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("KEYSTORE_PATH")
						.long("keystore-path")
						.short("k")
						.help("Keystore path")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("NONCE")
						.long("nonce")
						.short("n")
						.help("Nonce: get from node for default")
						.takes_value(true)
						.required(false),
				)
				.arg(
					Arg::with_name("PERIOD")
						.long("period")
						.short("p")
						.help("Period: 64 for default")
						.takes_value(true)
						.required(false),
				)
				.arg(
					Arg::with_name("CALL")
						.long("call")
						.short("c")
						.help("Call: json")
						.takes_value(true)
						.required(true),
				),
			f: compose,
		},
		Command {
			app: SubCommand::with_name("submit")
				.about("Submit tx")
				.arg(
					Arg::with_name("RPC")
						.long("rpc")
						.short("r")
						.help("RPC address")
						.takes_value(true)
						.required(true),
				)
				.arg(Arg::with_name("INPUT").required(false).index(1)),
			f: submit,
		},
		Command {
			app: SubCommand::with_name("search")
				.about("Search tx")
				.arg(
					Arg::with_name("RPC")
						.long("rpc")
						.short("r")
						.help("RPC address")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("HASH")
						.long("hash")
						.help("TX hash")
						.takes_value(true)
						.required(false),
				)
				.arg(
					Arg::with_name("RAW")
						.long("raw")
						.help("TX raw")
						.takes_value(true)
						.required(false),
				)
				.arg(
					Arg::with_name("SENDER")
						.long("sender")
						.help("TX sender")
						.takes_value(true)
						.required(false),
				)
				.arg(
					Arg::with_name("FROM_BLOCK_NUMBER")
						.long("from")
						.help("From block number: (numeric or pending, waiting)")
						.takes_value(true)
						.required(false),
				)
				.arg(
					Arg::with_name("TO_BLOCK_NUMBER")
						.long("to")
						.help("To block number: (numeric or pending, waiting)")
						.takes_value(true)
						.required(false),
				)
				.arg(
					Arg::with_name("INCLUDE_INHERENT")
						.long("include-inherent")
						.help("Whether include inherent")
						.required(false),
				),
			f: search,
		},
	]
}

fn desc(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let input = base::input_string(matches)?;

	let input: Vec<u8> = input.parse::<Hex>().map_err(|_| "Convert failed")?.into();

	let tx: Transaction = Decode::decode(&mut &input[..]).ok_or("invalid tx")?;

	let tx: SerdeTransaction = tx.into();

	base::output(&tx)
}

fn compose(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let rpc = &get_rpc(matches);

	let keystore_path = matches.value_of("KEYSTORE_PATH").expect("qed");

	let period = match matches.value_of("PERIOD") {
		Some(period) => period.parse::<u64>().map_err(|_| "Invalid period")?,
		None => 64,
	};

	let call = matches.value_of("CALL").expect("qed");

	let call_cow = match call {
		"-" => Cow::Owned(base::input_string(matches)?),
		call => Cow::Borrowed(call),
	};

	let call = call_cow.as_ref();

	let block_info = get_block_info(Number::Best, rpc)?;
	let (best_number, best_hash, shard_info) = (
		block_info.number,
		block_info.hash,
		block_info.shard.map(|x| (x.shard_num, x.shard_count)),
	);

	let best_hash: Vec<u8> = best_hash.into();

	let (shard_num, shard_count) = shard_info.ok_or("Invalid shard info".to_string())?;

	let secret_key = if keystore_path.starts_with("0x") {
		let mut secret_key = match hex::decode(keystore_path.trim_start_matches("0x")) {
			Ok(v) => v,
			Err(_) => return Err("Invalid hex secret key".to_string())
		};
		if secret_key.len() == 32 {
			let key_pair = KeyPair::from_mini_secret_key(&secret_key.clone())?;
			secret_key = key_pair.secret_key().to_vec();
		}
		if secret_key.len() != 64 {
			return Err("Invalid hex secret key length".to_string())
		}
		secret_key
	} else {
		get_keystore(keystore_path)?
	};

	let key_pair = KeyPair::from_secret_key(&secret_key)?;

	let public_key = key_pair.public_key();

	let shard_num_for_public_key =
		utils::shard_num_for_bytes(&public_key, shard_count).expect("qed");

	if shard_num_for_public_key != shard_num {
		return Err("the shard number of the secret key and the node not match".to_string());
	}

	let nonce = match matches.value_of("NONCE") {
		Some(nonce) => nonce.parse::<u64>().map_err(|_| "Invalid nonce")?,
		None => get_nonce(public_key, rpc)?,
	};

	let call = build_call(call.as_bytes())?;

	let secret_key = {
		let mut tmp = [0u8; SECRET_KEY_LEN];
		tmp.copy_from_slice(&secret_key);
		tmp
	};

	let current = best_number;
	let current_hash = {
		let mut tmp = [0u8; HASH_LEN];
		tmp.copy_from_slice(&best_hash);
		tmp
	};

	let tx = build_tx(secret_key, nonce, period, current, current_hash, call)?;
	let raw = tx.encode();

	let result = ComposeResult {
		shard_num,
		shard_count,
		sender_address: public_key
			.to_address(Hrp::MAINNET)
			.map_err(|_e| "Address encode failed")?
			.0,
		sender_testnet_address: public_key
			.to_address(Hrp::TESTNET)
			.map_err(|_e| "Address encode failed")?
			.0,
		nonce,
		period,
		current,
		current_hash: current_hash.to_vec().into(),
		raw: raw.into(),
	};

	base::output(result)
}

fn submit(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let input = base::input_string(matches)?;

	let rpc = &get_rpc(matches);

	let try_get_raw_from_hex = |input: String| -> Result<String, String> {
		let _raw = Hex::from_str(&input)?;
		Ok(input)
	};

	let try_get_raw_from_json = |input: String| -> Result<String, String> {
		let result: base::Output<ComposeResult> =
			serde_json::from_str(&input).map_err(|_| "Invalid json")?;
		let result = result.result.ok_or("Invalid json")?;
		Ok(result.raw.into())
	};

	let mut raw = try_get_raw_from_hex(input.clone());

	if raw.is_err() {
		raw = try_get_raw_from_json(input);
	}

	let raw = raw.map_err(|e| format!("Invalid raw: {}", e))?;

	// verify raw
	let raw1 = Hex::from_str(&raw)?;
	let raw1: Vec<u8> = raw1.into();
	let _tx: Transaction = Decode::decode(&mut &raw1[..]).ok_or("Invalid tx")?;

	// submit
	let mut runtime = Runtime::new().expect("qed");
	let result: RpcResponse<String> = runtime.block_on(base::rpc_call::<_, String>(
		rpc,
		"author_submitExtrinsic",
		&(raw,),
	))?;

	if let Some(error) = result.error {
		return Err(error.message);
	}

	base::output(result.result)
}

fn search(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let rpc = &get_rpc(matches);

	let best_number = get_block_info(Number::Best, rpc)?.number;

	let expected_hash: Option<Vec<u8>> = match matches.value_of("HASH") {
		Some(v) => {
			let tmp = Hex::from_str(v)?;
			Some(tmp.into())
		}
		None => None,
	};

	let expected_raw: Option<Vec<u8>> = match matches.value_of("RAW") {
		Some(v) => {
			let tmp = Hex::from_str(v)?;
			Some(tmp.into())
		}
		None => None,
	};

	let expected_sender: Option<Vec<u8>> = match matches.value_of("SENDER") {
		Some(v) => {
			let tmp = Hex::from_str(v)?;
			Some(tmp.into())
		}
		None => None,
	};

	let include_inherent: bool = matches.is_present("INCLUDE_INHERENT");

	let from: BlockNumber = match matches.value_of("FROM_BLOCK_NUMBER") {
		Some(v) => match v {
			"waiting" => BlockNumber::Waiting,
			"pending" => BlockNumber::Pending,
			n => {
				let tmp = n.parse::<u64>().map_err(|_| "Invalid from block number")?;
				BlockNumber::Number(tmp)
			}
		},
		None => BlockNumber::Number(best_number - 20),
	};

	let to: BlockNumber = match matches.value_of("TO_BLOCK_NUMBER") {
		Some(v) => match v {
			"waiting" => BlockNumber::Waiting,
			"pending" => BlockNumber::Pending,
			n => {
				let tmp = n.parse::<u64>().map_err(|_| "Invalid to block number")?;
				BlockNumber::Number(tmp)
			}
		},
		None => BlockNumber::Waiting,
	};

	let search_in_waiting = match (from, to) {
		(BlockNumber::Number(_), BlockNumber::Waiting) => true,
		(BlockNumber::Pending, BlockNumber::Waiting) => true,
		(BlockNumber::Waiting, BlockNumber::Waiting) => true,
		_ => false,
	};

	let search_in_pending = match (from, to) {
		(BlockNumber::Number(_), BlockNumber::Waiting) => true,
		(BlockNumber::Number(_), BlockNumber::Pending) => true,
		(BlockNumber::Pending, BlockNumber::Waiting) => true,
		(BlockNumber::Pending, BlockNumber::Pending) => true,
		_ => false,
	};

	let number_range = match (from, to) {
		(BlockNumber::Number(from), BlockNumber::Waiting) => Some((from, best_number)),
		(BlockNumber::Number(from), BlockNumber::Pending) => Some((from, best_number)),
		(BlockNumber::Number(from), BlockNumber::Number(to)) => {
			let to = min(to, best_number);
			if from <= to {
				Some((from, to))
			} else {
				None
			}
		}
		_ => None,
	};

	let mut items = vec![];

	let build_search_item = |raw: Vec<u8>,
	                         block: SearchItemBlock,
	                         success: Option<bool>,
	                         events: Option<Vec<String>>|
	 -> Result<SearchItem, String> {
		let tx: Transaction = Decode::decode(&mut &raw[..]).ok_or("invalid tx")?;
		let hash = blake2_256(&raw).to_vec();
		let item = SearchItem {
			hash,
			raw,
			tx,
			block,
			success,
			events,
		};
		Ok(item)
	};

	// append in block
	if let Some((from, to)) = number_range {
		for i in from..(to + 1) {
			let block_hash = get_block_info(Number::Number(i), rpc)?.hash;
			let block_hash: Vec<u8> = block_hash.into();
			let extrinsics = get_block_extrinsics(rpc, &block_hash)?;
			let results = get_block_extrinsics_result(rpc, &block_hash)?;
			for (index, raw) in extrinsics.into_iter().enumerate() {
				let block = SearchItemBlock::Number {
					number: i,
					hash: block_hash.clone(),
					index: index as u32,
				};
				let result = results.get(&(index as u32));
				let success = result.map(|x| x.0);
				let events = result.map(|x| x.1.clone());
				let item = build_search_item(raw, block, success, events)?;
				let accept = accept_item(
					&item,
					expected_hash.as_ref(),
					expected_raw.as_ref(),
					expected_sender.as_ref(),
					include_inherent,
				);

				if accept {
					items.push(item);
				}
			}
		}
	}

	// append in pending
	if search_in_pending {
		let extrinsics = get_pending_extrinsics(rpc)?;
		for raw in extrinsics {
			let item = build_search_item(raw, SearchItemBlock::Pending, None, None)?;
			let accept = accept_item(
				&item,
				expected_hash.as_ref(),
				expected_raw.as_ref(),
				expected_sender.as_ref(),
				include_inherent,
			);

			if accept {
				items.push(item);
			}
		}
	}

	// append in waiting
	if search_in_waiting {
		let extrinsics = get_waiting_extrinsics(rpc)?;
		for raw in extrinsics {
			let item = build_search_item(raw, SearchItemBlock::Waiting, None, None)?;
			let accept = accept_item(
				&item,
				expected_hash.as_ref(),
				expected_raw.as_ref(),
				expected_sender.as_ref(),
				include_inherent,
			);

			if accept {
				items.push(item);
			}
		}
	}

	let result = items
		.into_iter()
		.map(Into::into)
		.collect::<Vec<SerdeSearchItem>>();

	base::output(&result)
}

#[derive(Serialize, Deserialize)]
struct ComposeResult {
	shard_num: u16,
	shard_count: u16,
	sender_address: String,
	sender_testnet_address: String,
	nonce: u64,
	period: u64,
	current: u64,
	current_hash: Hex,
	raw: Hex,
}

struct SearchItem {
	hash: Vec<u8>,
	raw: Vec<u8>,
	tx: Transaction,
	block: SearchItemBlock,
	success: Option<bool>,
	events: Option<Vec<String>>,
}

enum SearchItemBlock {
	Number {
		number: u64,
		hash: Vec<u8>,
		index: u32,
	},
	Pending,
	Waiting,
}

#[derive(Serialize)]
struct SerdeSearchItem {
	hash: Hex,
	raw: Hex,
	tx: SerdeTransaction,
	block: SerdeSearchItemBlock,
	success: Option<bool>,
	events: Option<Vec<String>>,
}

#[derive(Serialize)]
enum SerdeSearchItemBlock {
	Number { number: u64, hash: Hex, index: u32 },
	Pending,
	Waiting,
}

impl From<SearchItem> for SerdeSearchItem {
	fn from(t: SearchItem) -> Self {
		SerdeSearchItem {
			hash: t.hash.into(),
			raw: t.raw.into(),
			tx: t.tx.into(),
			block: t.block.into(),
			success: t.success,
			events: t.events,
		}
	}
}

impl From<SearchItemBlock> for SerdeSearchItemBlock {
	fn from(t: SearchItemBlock) -> Self {
		match t {
			SearchItemBlock::Number {
				number,
				hash,
				index,
			} => SerdeSearchItemBlock::Number {
				number,
				hash: hash.into(),
				index,
			},
			SearchItemBlock::Pending => SerdeSearchItemBlock::Pending,
			SearchItemBlock::Waiting => SerdeSearchItemBlock::Waiting,
		}
	}
}

#[derive(Serialize, Debug, Copy, Clone)]
enum BlockNumber {
	Number(u64),
	Pending,
	Waiting,
}

#[derive(Serialize)]
struct SerdeSignature {
	pub sender: Hex,
	pub signature: Hex,
	pub nonce: u64,
	pub era: SerdeEra,
}

#[derive(Serialize)]
struct SerdeTransaction {
	pub signature: Option<SerdeSignature>,
	pub call: Call,
}

#[derive(Serialize)]
pub enum SerdeEra {
	Immortal,
	Mortal(u64, u64),
}

impl From<Era> for SerdeEra {
	fn from(t: Era) -> Self {
		match t {
			Era::Immortal => Self::Immortal,
			Era::Mortal(period, phase) => Self::Mortal(period, phase),
		}
	}
}

impl From<Transaction> for SerdeTransaction {
	fn from(t: Transaction) -> Self {
		let signature = t
			.signature
			.map(|(address, sig, nonce, era)| SerdeSignature {
				sender: address.0.to_vec().into(),
				signature: sig.to_vec().into(),
				nonce: nonce.0,
				era: era.into(),
			});
		Self {
			signature,
			call: t.call,
		}
	}
}

fn accept_item(
	item: &SearchItem,
	expected_hash: Option<&Vec<u8>>,
	expected_raw: Option<&Vec<u8>>,
	expected_sender: Option<&Vec<u8>>,
	include_inherent: bool,
) -> bool {
	if let Some(expected_hash) = expected_hash {
		if expected_hash != &item.hash {
			return false;
		}
	}

	if let Some(expected_raw) = expected_raw {
		if expected_raw != &item.raw {
			return false;
		}
	}

	if let Some(expected_sender) = expected_sender {
		let tx_sender = item
			.tx
			.signature
			.as_ref()
			.map(|(address, _, _, _)| address.0.to_vec());
		if Some(expected_sender) != tx_sender.as_ref() {
			return false;
		}
	}

	if !include_inherent {
		let no_sig = item.tx.signature.is_none();
		let is_relay_tx = match item.tx.call {
			Call::Relay(_) => true,
			_ => false,
		};
		if no_sig && !is_relay_tx {
			return false;
		}
	}

	true
}

fn get_block_extrinsics(rpc: &str, block_hash: &[u8]) -> Result<Vec<Vec<u8>>, String> {
	let mut runtime = Runtime::new().expect("qed");

	let block_hash: Hex = block_hash.to_vec().into();
	let block_hash: String = block_hash.into();

	let block = runtime
		.block_on(base::rpc_call::<_, Value>(
			rpc,
			"chain_getBlock",
			&(&block_hash,),
		))?
		.result;

	let block: Value = block.ok_or(format!("Block hash not found: {}", block_hash))?;

	let block = block
		.as_object()
		.ok_or("Decode block failed")?
		.get("block")
		.ok_or("Decode block failed")?;
	let extrinsics = block
		.as_object()
		.ok_or("Decode block failed")?
		.get("extrinsics")
		.ok_or("Decode block failed")?;
	let extrinsics = extrinsics
		.as_array()
		.ok_or("Decode block failed")?
		.into_iter()
		.map(|x| {
			let x = x.as_str().ok_or("Decode block failed".to_string())?;
			let x = Hex::from_str(x)?;
			let mut x: Vec<u8> = x.into();
			let mut length_prefix: Vec<u8> = Compact(x.len() as u32).encode();
			length_prefix.append(&mut x);
			Ok(length_prefix)
		})
		.collect::<Result<Vec<Vec<u8>>, String>>()?;

	Ok(extrinsics)
}

fn get_block_extrinsics_result(
	rpc: &str,
	block_hash: &[u8],
) -> Result<HashMap<u32, (bool, Vec<String>)>, String> {
	let mut runtime = Runtime::new().expect("qed");

	let mut result = HashMap::new();

	let block_hash: Hex = block_hash.to_vec().into();
	let block_hash: String = block_hash.into();

	let events_storage_key = get_value_storage_key(b"System Events");

	let events = runtime
		.block_on(base::rpc_call::<_, String>(
			rpc,
			"state_getStorage",
			&(&events_storage_key, &block_hash),
		))?
		.result;

	let events: String = match events {
		Some(events) => events,
		None => return Ok(result),
	};

	let events = Hex::from_str(&events)?;
	let events: Vec<u8> = events.into();
	let events: Vec<EventRecord<Event>> =
		Decode::decode(&mut &events[..]).ok_or("Decode event record failed")?;

	for event in events.into_iter() {
		match event.phase {
			Phase::ApplyExtrinsic(index) => match &event.event {
				Event::system(system_event) => {
					let success = match system_event {
						srml_system::Event::ExtrinsicSuccess => true,
						srml_system::Event::ExtrinsicFailed => false,
					};
					match result.entry(index) {
						Entry::Vacant(entry) => {
							entry.insert((success, vec![]));
						}
						Entry::Occupied(mut entry) => {
							let entry = entry.get_mut();
							entry.0 = success;
						}
					}
				}
				_ => {
					let event_str = format!("{:?}", event.event);
					match result.entry(index) {
						Entry::Vacant(entry) => {
							entry.insert((false, vec![event_str]));
						}
						Entry::Occupied(mut entry) => {
							let entry = entry.get_mut();
							entry.1.push(event_str);
						}
					}
				}
			},
			_ => {}
		}
	}

	Ok(result)
}

fn get_pending_extrinsics(rpc: &str) -> Result<Vec<Vec<u8>>, String> {
	let mut runtime = Runtime::new().expect("qed");
	let result = runtime
		.block_on(base::rpc_call::<_, Vec<String>>(
			rpc,
			"author_pendingExtrinsics",
			&(),
		))?
		.result;

	let result = result.ok_or(format!("Get pending extrinsics failed"))?;

	let result = result
		.into_iter()
		.map(|x| {
			let x = Hex::from_str(&x)?;
			let x: Vec<u8> = x.into();
			Ok(x)
		})
		.collect::<Result<Vec<_>, String>>()?;

	Ok(result)
}

fn get_waiting_extrinsics(rpc: &str) -> Result<Vec<Vec<u8>>, String> {
	let mut runtime = Runtime::new().expect("qed");
	let result = runtime
		.block_on(base::rpc_call::<_, Vec<String>>(
			rpc,
			"author_waitingExtrinsics",
			&(),
		))?
		.result;

	let result = result.ok_or(format!("Get waiting extrinsics failed"))?;

	let result = result
		.into_iter()
		.map(|x| {
			let x = Hex::from_str(&x)?;
			let x: Vec<u8> = x.into();
			Ok(x)
		})
		.collect::<Result<Vec<_>, String>>()?;

	Ok(result)
}

fn get_nonce(public_key: [u8; PUBLIC_KEY_LEN], rpc: &str) -> Result<u64, String> {
	let nonce_key = get_map_storage_key_encode(&public_key, b"System AccountNonce");

	let params = (nonce_key,);

	let nonce = base::rpc_call::<_, StorageData>(rpc, "state_getStorage", &params);

	let mut runtime = Runtime::new().expect("qed");

	let nonce = runtime.block_on(nonce)?.result;

	let nonce = nonce
		.map(|x| BigUint::from_bytes_le(&x.0))
		.unwrap_or(BigUint::from(0u64));

	let nonce = nonce.to_u64().unwrap_or(0u64);

	Ok(nonce)
}

mod cases {
	use linked_hash_map::LinkedHashMap;

	use crate::modules::Case;

	pub fn cases() -> LinkedHashMap<&'static str, Vec<Case>> {
		vec![
            (
                "tx",
                vec![Case {
                    desc: "Desc tx".to_string(),
                    input: vec!["desc", "0x290281ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70a8796f3650bf99d094f7004f27849bf712ce7a032425ce13b8e334ff834b084f3a7ead9eb04520912a1018c26d3c49519f6d70c7fa4f799fa33b007854efd40f00a5030400ffa6158c2b928d5d495922366ad9b4339a023366b322fb22f4db12751e0ea93f5ca10f"].into_iter().map(Into::into).collect(),
                    output: vec![r#"{
  "result": {
    "signature": {
      "sender": "0xff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70",
      "signature": "0xa8796f3650bf99d094f7004f27849bf712ce7a032425ce13b8e334ff834b084f3a7ead9eb04520912a1018c26d3c49519f6d70c7fa4f799fa33b007854efd40f",
      "nonce": 0,
      "era": {
        "Mortal": [
          64,
          58
        ]
      }
    },
    "call": {
      "module": 4,
      "method": 0,
      "params": {
        "dest": "0xffa6158c2b928d5d495922366ad9b4339a023366b322fb22f4db12751e0ea93f5c",
        "value": 1000
      }
    }
  }
}"#].into_iter().map(Into::into).collect(),
                    is_example: true,
                    is_test: true,
                    since: "0.1.0".to_string(),
                }, Case {
                    desc: "Compose tx".to_string(),
                    input: vec!["compose", "-r", "http://localhost:9033", "-k", "keystore.dat", "-c", r#"'{ "module":4, "method":0, "params":{"dest":"0xffa6158c2b928d5d495922366ad9b4339a023366b322fb22f4db12751e0ea93f5c","value":1000}}'"#].into_iter().map(Into::into).collect(),
                    output: vec![r#"{
  "result": {
    "shard_num": 0,
    "shard_count": 4,
    "sender_address": "yee1jfakj2rvqym79lmxcmjkraep6tn296deyspd9mkh467u4xgqt3cqmtaf9v",
    "sender_testnet_address": "tyee1jfakj2rvqym79lmxcmjkraep6tn296deyspd9mkh467u4xgqt3cqkv6lyl",
    "nonce": 2,
    "period": 64,
    "current": 45,
    "current_hash": "0x000004c65b2e9240dd85ddb101aef17d0cf2c2fdbe133ad9b44e870b445292d0",
    "raw": "0x290281ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c706a16d3939a69e025592d997e68073a60008503d2d7251092b5e13e7b44f9367bf47c8f307624f10f348ca96a39cec64701c399518f82b43804e01cdf876c5c0708d5020400ffa6158c2b928d5d495922366ad9b4339a023366b322fb22f4db12751e0ea93f5ca10f"
  }
}"#].into_iter().map(Into::into).collect(),
                    is_example: true,
                    is_test: false,
                    since: "0.1.0".to_string(),
                },
                     Case {
                         desc: "Submit tx".to_string(),
                         input: vec!["submit", "-r", "http://localhost:9033", "0x310281ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70a669fea60899f954d36146355528c0a24f8e6a7d2d04fe78384e4c5f9e0b8231560fbb54b967e0c868f23c3f9d141641b064688b0683d56741af6908b9fbeb012045010400ff94d988b42d96dcbd6605ff47f19c6ab35f626eb1bc8bbd28f59a74997a253a3d0284d717"].into_iter().map(Into::into).collect(),
                         output: vec![r#"{
  "result": "0x7ccbbd54aa554053ad7f9a45e40abe53baaba8795317a71e308b0a2f761eb431"
}"#].into_iter().map(Into::into).collect(),
                         is_example: true,
                         is_test: false,
                         since: "0.1.0".to_string(),
                     },
                     Case {
                         desc: "Search tx".to_string(),
                         input: vec!["search", "-r", "http://localhost:9033", "--hash", "0x6624c259102365d2c4fe036ff4cfc5ef502a4c527b3bcb81080da2d07cbe5505"].into_iter().map(Into::into).collect(),
                         output: vec![r#"{
  "result": [
    {
      "hash": "0xad1eeb7f893dc1a7104d91caa0418b38ebe43880e5e79341bff50edc90aeb2bf",
      "raw": "0x310281ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70b4c7fd2f9484e881a8e57132412575b8978a7443ddb13b98052dfc62f2dbb35f72bc5c25e42b2be4b3125f9ab5362a1b3826df0744370e70788f8f3eb25c100c00e5030400ff94d988b42d96dcbd6605ff47f19c6ab35f626eb1bc8bbd28f59a74997a253a3d0284d717",
      "tx": {
        "signature": {
          "sender": "0xff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70",
          "signature": "0xb4c7fd2f9484e881a8e57132412575b8978a7443ddb13b98052dfc62f2dbb35f72bc5c25e42b2be4b3125f9ab5362a1b3826df0744370e70788f8f3eb25c100c",
          "nonce": 0,
          "era": {
            "Mortal": [
              64,
              62
            ]
          }
        },
        "call": {
          "module": 4,
          "method": 0,
          "params": {
            "dest": "0xff94d988b42d96dcbd6605ff47f19c6ab35f626eb1bc8bbd28f59a74997a253a3d",
            "value": 100000000
          }
        }
      },
      "block": {
        "Number": {
          "number": 63,
          "hash": "0x453822219ba447ad31bc7c5499a6a09e475435f7bb9e43b885a8d38c06b50643",
          "index": 5
        }
      },
      "success": true,
      "events": [
        "balances(Transfer(927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70 (5FNmWUUd...), 94d988b42d96dcbd6605ff47f19c6ab35f626eb1bc8bbd28f59a74997a253a3d (5FRsZjZU...), 100000000, 0))"
      ]
    }
  ]
}"#].into_iter().map(Into::into).collect(),
                         is_example: true,
                         is_test: false,
                         since: "0.1.0".to_string(),
                     }],
            )
        ].into_iter().collect()
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
