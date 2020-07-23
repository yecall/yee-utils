use clap::{Arg, ArgMatches, SubCommand};
use rand::thread_rng;
use rand::Rng;
use serde::Serialize;
use yee_primitives::{Address, AddressCodec, Hrp};
use yee_sharding_primitives::utils;
use yee_signer::KeyPair;

use crate::modules::base::Hex;
use crate::modules::{base, Command, Module};

const SHARD_COUNT_LIST: [u16; 2] = [4, 8];

pub fn module<'a, 'b>() -> Module<'a, 'b> {
	Module {
		desc: "Account tools".to_string(),
		commands: commands(),
		get_cases: cases::cases,
	}
}

pub fn commands<'a, 'b>() -> Vec<Command<'a, 'b>> {
	let mut app = SubCommand::with_name("account").about("Account tools");
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
			app: SubCommand::with_name("generate")
				.about("Generate account")
				.arg(
					Arg::with_name("SHARD_NUM")
						.long("shard-num")
						.short("s")
						.help("Shard number")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("SHARD_COUNT")
						.long("shard-count")
						.short("c")
						.help("Shard count")
						.takes_value(true)
						.required(true),
				),
			f: generate,
		},
		Command {
			app: SubCommand::with_name("mini_secret_key")
				.about("Desc mini secret key")
				.arg(Arg::with_name("INPUT").required(false).index(1)),
			f: mini_secret_key,
		},
		Command {
			app: SubCommand::with_name("secret_key")
				.about("Desc secret key")
				.arg(Arg::with_name("INPUT").required(false).index(1)),
			f: secret_key,
		},
		Command {
			app: SubCommand::with_name("public_key")
				.about("Desc public key")
				.arg(Arg::with_name("INPUT").required(false).index(1)),
			f: public_key,
		},
		Command {
			app: SubCommand::with_name("address")
				.about("Desc address")
				.arg(Arg::with_name("INPUT").required(false).index(1)),
			f: address,
		},
	]
}

fn generate(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let shard_num = matches
		.value_of("SHARD_NUM")
		.expect("qed")
		.parse::<u16>()
		.map_err(|_| "Invalid shard num")?;
	let shard_count = matches
		.value_of("SHARD_COUNT")
		.expect("qed")
		.parse::<u16>()
		.map_err(|_| "Invalid shard count")?;

	let (mini_secret_key, public_key, secret_key, address, testnet_address) =
		generate_account(shard_num, shard_count)?;

	#[derive(Serialize)]
	struct Output {
		shard_num: u16,
		shard_count: u16,
		mini_secret_key: Hex,
		secret_key: Hex,
		public_key: Hex,
		address: String,
		testnet_address: String,
	}

	let output = Output {
		shard_num,
		shard_count,
		mini_secret_key: mini_secret_key.to_vec().into(),
		secret_key: secret_key.to_vec().into(),
		public_key: public_key.to_vec().into(),
		address: address.0,
		testnet_address: testnet_address.0,
	};

	base::output(&output)
}

fn mini_secret_key(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let input = base::input_string(matches)?;

	let input: Vec<u8> = input
		.parse::<Hex>()
		.map_err(|_| "Invalid mini secret key")?
		.into();

	let key_pair = KeyPair::from_mini_secret_key(&input.clone())?;

	let secret_key = key_pair.secret_key();

	let public_key = key_pair.public_key();

	let address = public_key
		.to_address(Hrp::MAINNET)
		.map_err(|_e| "Address encode failed")?;
	let testnet_address = public_key
		.to_address(Hrp::TESTNET)
		.map_err(|_e| "Address encode failed")?;

	#[derive(Serialize)]
	struct Shard {
		shard_num: u16,
		shard_count: u16,
	}

	let shard = SHARD_COUNT_LIST
		.iter()
		.map(|&shard_count| {
			let shard_num = utils::shard_num_for_bytes(&public_key, shard_count).expect("qed");
			Shard {
				shard_num,
				shard_count,
			}
		})
		.collect::<Vec<_>>();

	#[derive(Serialize)]
	struct Output {
		mini_secret_key: Hex,
		secret_key: Hex,
		public_key: Hex,
		address: String,
		testnet_address: String,
		shard: Vec<Shard>,
	}

	let output = Output {
		mini_secret_key: input.into(),
		secret_key: secret_key.to_vec().into(),
		public_key: public_key.to_vec().into(),
		address: address.0,
		testnet_address: testnet_address.0,
		shard,
	};

	base::output(&output)
}

fn secret_key(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let input = base::input_string(matches)?;

	let input: Vec<u8> = input
		.parse::<Hex>()
		.map_err(|_| "Invalid secret key")?
		.into();

	let key_pair = KeyPair::from_secret_key(&input.clone())?;

	let public_key = key_pair.public_key();

	let address = public_key
		.to_address(Hrp::MAINNET)
		.map_err(|_e| "Address encode failed")?;
	let testnet_address = public_key
		.to_address(Hrp::TESTNET)
		.map_err(|_e| "Address encode failed")?;

	#[derive(Serialize)]
	struct Shard {
		shard_num: u16,
		shard_count: u16,
	}

	let shard = SHARD_COUNT_LIST
		.iter()
		.map(|&shard_count| {
			let shard_num = utils::shard_num_for_bytes(&public_key, shard_count).expect("qed");
			Shard {
				shard_num,
				shard_count,
			}
		})
		.collect::<Vec<_>>();

	#[derive(Serialize)]
	struct Output {
		secret_key: Hex,
		public_key: Hex,
		address: String,
		testnet_address: String,
		shard: Vec<Shard>,
	}

	let output = Output {
		secret_key: input.into(),
		public_key: public_key.to_vec().into(),
		address: address.0,
		testnet_address: testnet_address.0,
		shard,
	};

	base::output(&output)
}

fn public_key(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let input = base::input_string(matches)?;

	let input: Vec<u8> = input
		.parse::<Hex>()
		.map_err(|_| "Invalid public key")?
		.into();

	let public_key = input;

	let output = desc_public_key(public_key)?;

	base::output(&output)
}

fn address(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let input = base::input_string(matches)?;

	let address = Address(input);

	let (public_key, hrp) =
		<[u8; 32]>::from_address(&address).map_err(|_| "Address decode failed")?;

	#[derive(Serialize)]
	struct Shard {
		shard_num: u16,
		shard_count: u16,
	}

	let shard = SHARD_COUNT_LIST
		.iter()
		.map(|&shard_count| {
			let shard_num = utils::shard_num_for_bytes(&public_key, shard_count).expect("qed");
			Shard {
				shard_num,
				shard_count,
			}
		})
		.collect::<Vec<_>>();

	#[derive(Serialize)]
	struct Output {
		address: String,
		public_key: Hex,
		hrp: String,
		shard: Vec<Shard>,
	}

	let output = Output {
		address: address.0.clone(),
		public_key: public_key.to_vec().into(),
		hrp: hrp.into(),
		shard,
	};

	base::output(&output)
}

pub fn generate_account(
	shard_num: u16,
	shard_count: u16,
) -> Result<([u8; 32], [u8; 32], [u8; 64], Address, Address), String> {
	loop {
		let mini_secret_key = random_32_bytes(&mut thread_rng());
		let key_pair = KeyPair::from_mini_secret_key(&mini_secret_key)?;
		let public_key = key_pair.public_key();
		let secret_key = key_pair.secret_key();
		let address_shard_num = utils::shard_num_for_bytes(&public_key, shard_count);
		if address_shard_num == Some(shard_num) {
			let address = public_key
				.to_address(Hrp::MAINNET)
				.map_err(|_e| "Address encode failed")?;
			let testnet_address = public_key
				.to_address(Hrp::TESTNET)
				.map_err(|_e| "Address encode failed")?;

			break Ok((
				mini_secret_key,
				public_key,
				secret_key,
				address,
				testnet_address,
			));
		}
	}
}

#[derive(Serialize)]
pub struct Shard {
	shard_num: u16,
	shard_count: u16,
}

#[derive(Serialize)]
pub struct DescPublicKeyOutput {
	public_key: Hex,
	address: String,
	testnet_address: String,
	shard: Vec<Shard>,
}

pub fn desc_public_key(public_key: Vec<u8>) -> Result<DescPublicKeyOutput, String> {
	let address = public_key
		.to_address(Hrp::MAINNET)
		.map_err(|_e| "Address encode failed")?;
	let testnet_address = public_key
		.to_address(Hrp::TESTNET)
		.map_err(|_e| "Address encode failed")?;

	let shard = SHARD_COUNT_LIST
		.iter()
		.map(|&shard_count| {
			let shard_num = utils::shard_num_for_bytes(&public_key, shard_count).expect("qed");
			Shard {
				shard_num,
				shard_count,
			}
		})
		.collect::<Vec<_>>();

	let output = DescPublicKeyOutput {
		public_key: public_key.into(),
		address: address.0,
		testnet_address: testnet_address.0,
		shard,
	};

	Ok(output)
}

pub fn random_32_bytes<R: Rng + ?Sized>(rng: &mut R) -> [u8; 32] {
	let mut ret = [0u8; 32];
	rng.fill_bytes(&mut ret);
	ret
}

mod cases {
	use linked_hash_map::LinkedHashMap;

	use crate::modules::Case;

	pub fn cases() -> LinkedHashMap<&'static str, Vec<Case>> {
		vec![
			(
				"account",
				vec![Case {
					desc: "Generate account".to_string(),
					input: vec!["generate", "-s", "0", "-c", "4"].into_iter().map(Into::into).collect(),
					output: vec![r#"{
  "result": {
    "shard_num": 0,
    "shard_count": 4,
    "mini_secret_key": "0xbd08b0bf13e4489e167e34b38189813098f6ce58ca35cb562d2bdec19ddbe08d",
    "secret_key": "0xb8fc0fffbec280d6115076ae78bb74342df51628d762bd953e8109d798ca3e6512124477a98392a283831ff9d6f0d454e97dfb9ef6cbf8dbe159e9deb08bfb0a",
    "public_key": "0x76d29674e24b92cdd5b4f2fd9586bf2637fa99184292a617c0b573383bc33c04",
    "address": "yee1wmffva8zfwfvm4d57t7etp4lycml4xgcg2f2v97qk4ensw7r8szqd0acf7",
    "testnet_address": "tyee1wmffva8zfwfvm4d57t7etp4lycml4xgcg2f2v97qk4ensw7r8szqqg6wgd"
  }
}
"#].into_iter().map(Into::into).collect(),
					is_example: true,
					is_test: false,
					since: "0.1.0".to_string(),
				}, Case {
					desc: "Desc mini secret key".to_string(),
					input: vec!["mini_secret_key", "0xbd08b0bf13e4489e167e34b38189813098f6ce58ca35cb562d2bdec19ddbe08d"].into_iter().map(Into::into).collect(),
					output: vec![r#"{
  "result": {
    "mini_secret_key": "0xbd08b0bf13e4489e167e34b38189813098f6ce58ca35cb562d2bdec19ddbe08d",
    "secret_key": "0xb8fc0fffbec280d6115076ae78bb74342df51628d762bd953e8109d798ca3e6512124477a98392a283831ff9d6f0d454e97dfb9ef6cbf8dbe159e9deb08bfb0a",
    "public_key": "0x76d29674e24b92cdd5b4f2fd9586bf2637fa99184292a617c0b573383bc33c04",
    "address": "yee1wmffva8zfwfvm4d57t7etp4lycml4xgcg2f2v97qk4ensw7r8szqd0acf7",
    "testnet_address": "tyee1wmffva8zfwfvm4d57t7etp4lycml4xgcg2f2v97qk4ensw7r8szqqg6wgd",
    "shard": [
      {
        "shard_num": 0,
        "shard_count": 4
      },
      {
        "shard_num": 4,
        "shard_count": 8
      }
    ]
  }
}"#].into_iter().map(Into::into).collect(),
					is_example: true,
					is_test: true,
					since: "0.1.0".to_string(),
				}, Case {
					desc: "Desc secret key".to_string(),
					input: vec!["secret_key", "0xb8fc0fffbec280d6115076ae78bb74342df51628d762bd953e8109d798ca3e6512124477a98392a283831ff9d6f0d454e97dfb9ef6cbf8dbe159e9deb08bfb0a"].into_iter().map(Into::into).collect(),
					output: vec![r#"{
  "result": {
    "secret_key": "0xb8fc0fffbec280d6115076ae78bb74342df51628d762bd953e8109d798ca3e6512124477a98392a283831ff9d6f0d454e97dfb9ef6cbf8dbe159e9deb08bfb0a",
    "public_key": "0x76d29674e24b92cdd5b4f2fd9586bf2637fa99184292a617c0b573383bc33c04",
    "address": "yee1wmffva8zfwfvm4d57t7etp4lycml4xgcg2f2v97qk4ensw7r8szqd0acf7",
    "testnet_address": "tyee1wmffva8zfwfvm4d57t7etp4lycml4xgcg2f2v97qk4ensw7r8szqqg6wgd",
    "shard": [
      {
        "shard_num": 0,
        "shard_count": 4
      },
      {
        "shard_num": 4,
        "shard_count": 8
      }
    ]
  }
}"#].into_iter().map(Into::into).collect(),
					is_example: true,
					is_test: true,
					since: "0.1.0".to_string(),
				}, Case {
					desc: "Desc public key".to_string(),
					input: vec!["public_key", "0x76d29674e24b92cdd5b4f2fd9586bf2637fa99184292a617c0b573383bc33c04"].into_iter().map(Into::into).collect(),
					output: vec![r#"{
  "result": {
    "public_key": "0x76d29674e24b92cdd5b4f2fd9586bf2637fa99184292a617c0b573383bc33c04",
    "address": "yee1wmffva8zfwfvm4d57t7etp4lycml4xgcg2f2v97qk4ensw7r8szqd0acf7",
    "testnet_address": "tyee1wmffva8zfwfvm4d57t7etp4lycml4xgcg2f2v97qk4ensw7r8szqqg6wgd",
    "shard": [
      {
        "shard_num": 0,
        "shard_count": 4
      },
      {
        "shard_num": 4,
        "shard_count": 8
      }
    ]
  }
}"#].into_iter().map(Into::into).collect(),
					is_example: true,
					is_test: true,
					since: "0.1.0".to_string(),
				}, Case {
					desc: "Desc address".to_string(),
					input: vec!["address", "yee1wmffva8zfwfvm4d57t7etp4lycml4xgcg2f2v97qk4ensw7r8szqd0acf7"].into_iter().map(Into::into).collect(),
					output: vec![r#"{
  "result": {
    "address": "yee1wmffva8zfwfvm4d57t7etp4lycml4xgcg2f2v97qk4ensw7r8szqd0acf7",
    "public_key": "0x76d29674e24b92cdd5b4f2fd9586bf2637fa99184292a617c0b573383bc33c04",
    "hrp": "yee",
    "shard": [
      {
        "shard_num": 0,
        "shard_count": 4
      },
      {
        "shard_num": 4,
        "shard_count": 8
      }
    ]
  }
}"#].into_iter().map(Into::into).collect(),
					is_example: true,
					is_test: true,
					since: "0.1.0".to_string(),
				}, ],
			),
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
