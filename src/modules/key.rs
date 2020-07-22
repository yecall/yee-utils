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
		desc: "Key tools".to_string(),
		commands: commands(),
		get_cases: cases::cases,
	}
}

pub fn commands<'a, 'b>() -> Vec<Command<'a, 'b>> {
	let mut app = SubCommand::with_name("key").about("Key tools");
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
				.about("Generate key pair")
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
		Command {
			app: SubCommand::with_name("put_key")
				.about("Put secret key to a keystore file")
				.arg(
					Arg::with_name("KEYSTORE_PATH")
						.long("keystore-path")
						.short("k")
						.help("Keystore path")
						.takes_value(true)
						.required(true),
				),
			f: put_key,
		},
		Command {
			app: SubCommand::with_name("get_key")
				.about("Get secret key from a keystore file")
				.arg(
					Arg::with_name("KEYSTORE_PATH")
						.long("keystore-path")
						.short("k")
						.help("Keystore path")
						.takes_value(true)
						.required(true),
				),
			f: get_key,
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

	let (mini_secret_key, public_key, secret_key, address, testnet_address) = loop {
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

			break (
				mini_secret_key,
				public_key,
				secret_key,
				address,
				testnet_address,
			);
		}
	};

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
		public_key: Hex,
		address: String,
		testnet_address: String,
		shard: Vec<Shard>,
	}

	let output = Output {
		public_key: public_key.into(),
		address: address.0,
		testnet_address: testnet_address.0,
		shard,
	};

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

fn put_key(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let keystore_path = matches.value_of("KEYSTORE_PATH").expect("qed");

	match std::fs::File::open(keystore_path) {
		Ok(_) => return Err("Keystore file exists".to_string()),
		_ => (),
	}

	let secret_key = rpassword::read_password_from_tty(Some("Secret key (Hex): ")).unwrap();

	let secret_key: Vec<u8> = secret_key
		.parse::<Hex>()
		.map_err(|_| "Invalid secret key")?
		.into();

	let _key_pair = KeyPair::from_secret_key(&secret_key).map_err(|_| "Invalid secret key")?;

	let password = rpassword::read_password_from_tty(Some("Password: ")).unwrap();

	base::put_key(&secret_key, &password, keystore_path)?;

	base::output("Ok")
}

fn get_key(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let keystore_path = matches.value_of("KEYSTORE_PATH").expect("qed");

	let password = rpassword::read_password_from_tty(Some("Password: ")).unwrap();

	let secret_key = base::get_key(&password, keystore_path)?;

	let secret_key: Hex = secret_key.into();

	base::output(secret_key)
}

fn random_32_bytes<R: Rng + ?Sized>(rng: &mut R) -> [u8; 32] {
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
				"key",
				vec![Case {
					desc: "Generate key pair".to_string(),
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
				}, Case {
					desc: "Put secret key to a keystore file".to_string(),
					input: vec!["put_key", "-k", "./keystore.dat"].into_iter().map(Into::into).collect(),
					output: vec![r#"{
  "result": "Ok"
}
"#].into_iter().map(Into::into).collect(),
					is_example: true,
					is_test: false,
					since: "0.1.0".to_string(),
				}, Case {
					desc: "Get secret key from a keystore file".to_string(),
					input: vec!["get_key", "-k", "./keystore.dat"].into_iter().map(Into::into).collect(),
					output: vec![r#"{
  "result": "0xa8666e483fd6c26dbb6deeec5afae765561ecc94df432f02920fc5d9cd4ae206ead577e5bc11215d4735cee89218e22f2d950a2a4667745ea1b5ea8b26bba5d6"
}"#].into_iter().map(Into::into).collect(),
					is_example: true,
					is_test: false,
					since: "0.1.0".to_string(),
				}],
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
