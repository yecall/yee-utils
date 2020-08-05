use std::str::FromStr;

use clap::{Arg, ArgMatches, SubCommand};
use parity_codec::{Codec, KeyedVec};
use substrate_primitives::blake2_256;
use substrate_primitives::storage::{StorageData, StorageKey};
use tokio::runtime::Runtime;
use yee_primitives::Address;
use yee_primitives::AddressCodec;

use crate::modules::base::{get_rpc, Hex};
use crate::modules::{base, Command, Module};

pub fn module<'a, 'b>() -> Module<'a, 'b> {
	Module {
		desc: "State tools".to_string(),
		commands: commands(),
		get_cases: cases::cases,
	}
}

pub fn commands<'a, 'b>() -> Vec<Command<'a, 'b>> {
	let mut app = SubCommand::with_name("state").about("State tools");
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
			app: SubCommand::with_name("value")
				.about("Get value")
				.arg(
					Arg::with_name("RPC")
						.long("rpc")
						.short("r")
						.help("RPC address")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("KEY")
						.help("key: str")
						.required(true)
						.index(1),
				),
			f: value,
		},
		Command {
			app: SubCommand::with_name("unhashed_value")
				.about("Get unhashed value")
				.arg(
					Arg::with_name("RPC")
						.long("rpc")
						.short("r")
						.help("RPC address")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("KEY")
						.help("key: str")
						.required(true)
						.index(1),
				),
			f: unhashed_value,
		},
		Command {
			app: SubCommand::with_name("map")
				.about("Get map")
				.arg(
					Arg::with_name("RPC")
						.long("rpc")
						.short("r")
						.help("RPC address")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("PREFIX")
						.help("prefix: str")
						.required(true)
						.index(1),
				)
				.arg(
					Arg::with_name("KEY")
						.help("key: hex")
						.required(true)
						.index(2),
				),
			f: map,
		},
		Command {
			app: SubCommand::with_name("balance")
				.about("Get balance")
				.arg(
					Arg::with_name("RPC")
						.long("rpc")
						.short("r")
						.help("RPC address")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("ADDRESS")
						.help("prefix: str")
						.required(true)
						.index(1),
				),
			f: balance,
		},
	]
}

fn value(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let rpc = &get_rpc(matches);
	let key = matches.value_of("KEY").expect("qed");

	let key = key.as_bytes();

	let storage_key = get_value_storage_key(key);

	let data = get_storage(rpc, storage_key)?;

	let data: Option<Hex> = data.map(|x| x.into());

	base::output(&data)
}

fn unhashed_value(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let rpc = &get_rpc(matches);
	let key = matches.value_of("KEY").expect("qed");

	let key = key.as_bytes();

	let storage_key = StorageKey(key.to_vec());

	let data = get_storage(rpc, storage_key)?;

	let data: Option<Hex> = data.map(|x| x.into());

	base::output(&data)
}

fn map(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let rpc = &get_rpc(matches);

	let prefix = matches.value_of("PREFIX").expect("qed");
	let key = matches.value_of("KEY").expect("qed");

	let prefix = prefix.as_bytes().to_vec();
	let key: Vec<u8> = Hex::from_str(key)?.into();

	let storage_key = get_map_storage_key(&key, &prefix);

	let data = get_storage(rpc, storage_key)?;

	let data: Option<Hex> = data.map(|x| x.into());

	base::output(&data)
}

fn balance(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let rpc = &get_rpc(matches);

	let prefix = "Balances FreeBalance";
	let address = matches.value_of("ADDRESS").expect("qed");
	let address = Address(address.to_string());
	let (public_key, _hrp) =
		<[u8; 32]>::from_address(&address).map_err(|_| "Address decode failed")?;

	let prefix = prefix.as_bytes().to_vec();
	let key: Vec<u8> = public_key.to_vec();

	let storage_key = get_map_storage_key(&key, &prefix);

	let data = get_storage(rpc, storage_key)?;

	let data: Option<u128> = match data {
		Some(data) => Some(u128_from_slice(&data)?),
		None => None,
	};

	base::output(&data)
}

fn u128_from_slice(bytes: &[u8]) -> Result<u128, String> {
	const LEN: usize = 16;
	if bytes.len() != LEN {
		return Err("u128 decode error".to_string());
	}
	let mut array = [0; LEN];
	let bytes = &bytes[..];
	array.copy_from_slice(bytes);
	Ok(u128::from_le_bytes(array))
}

pub fn get_value_storage_key(key: &[u8]) -> StorageKey {
	StorageKey(twox_128(key))
}

pub fn get_map_storage_key(key: &[u8], prefix: &[u8]) -> StorageKey {
	let mut prefix = prefix.to_vec();
	prefix.extend(key);
	let a = blake2_256(&prefix).to_vec();
	StorageKey(a)
}

pub fn get_map_storage_key_encode<T>(key: &T, prefix: &[u8]) -> StorageKey
where
	T: Codec,
{
	let a = blake2_256(&key.to_keyed_vec(prefix)).to_vec();
	StorageKey(a)
}

fn twox_128(data: &[u8]) -> Vec<u8> {
	let hash0 = twox(data, 0);
	let hash1 = twox(data, 1);
	let mut result = vec![0u8; 16];
	result[0..8].copy_from_slice(&hash0);
	result[8..16].copy_from_slice(&hash1);
	result
}

fn twox(data: &[u8], seed: u64) -> Vec<u8> {
	use ::core::hash::Hasher;
	let mut h = twox_hash::XxHash::with_seed(seed);
	h.write(&data);
	let r = h.finish();
	use byteorder::{ByteOrder, LittleEndian};
	let mut dest = vec![0u8; 8];
	LittleEndian::write_u64(&mut dest[0..8], r);
	dest
}

mod cases {
	use linked_hash_map::LinkedHashMap;

	use crate::modules::Case;

	pub fn cases() -> LinkedHashMap<&'static str, Vec<Case>> {
		vec![
            (
                "state",
                vec![
                    Case {
                        desc: "Get value".to_string(),
                        input: vec!["value", "-r", "http://localhost:9033", "'System Events'"].into_iter().map(Into::into).collect(),
                        output: vec![r#"{
  "result": "0x1c00000000000000000100000000000002000000000000030000000000000400000000000101004b000000000000001033e0576822a6a836f612a193036042050e286da4561f5cc5d8ee560c64dc540040787d0100000000000000000000000000000000000000000000000000000001040034a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000a529d05a5e5b756d279f1aa873512c68ddf4cdf48a8376513f055e0935e398410100000000000000"
}"#].into_iter().map(Into::into).collect(),
                        is_example: true,
                        is_test: false,
                        since: "0.1.0".to_string(),
                    },
                    Case {
                        desc: "Get map".to_string(),
                        input: vec!["map", "-r", "http://localhost:9033", "'Balances FreeBalance'", "0x1033e0576822a6a836f612a193036042050e286da4561f5cc5d8ee560c64dc54"].into_iter().map(Into::into).collect(),
                        output: vec![r#"{
  "result": "0x4003acc36f0000000000000000000000"
}"#].into_iter().map(Into::into).collect(),
                        is_example: true,
                        is_test: false,
                        since: "0.1.0".to_string(),
                    },
                    Case {
                        desc: "Get unhash value".to_string(),
                        input: vec!["unhash_value", "-r", "http://localhost:9033", "':code'"].into_iter().map(Into::into).collect(),
                        output: vec![r#"{
  "result": "0x0000"
}"#].into_iter().map(Into::into).collect(),
                        is_example: true,
                        is_test: false,
                        since: "0.1.0".to_string(),
                    }
                ],
            ),
        ].into_iter().collect()
	}
}

fn get_storage(rpc: &str, storage_key: StorageKey) -> Result<Option<Vec<u8>>, String> {
	let mut runtime = Runtime::new().expect("qed");
	let result = runtime.block_on(base::rpc_call::<_, Option<StorageData>>(
		rpc,
		"state_getStorage",
		&(&storage_key,),
	))?;

	if let Some(_error) = result.error {
		return Err("Get storage failed".to_string());
	}

	let result = result.result.unwrap_or(None);

	let result = result.map(|x| x.0);

	Ok(result)
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
