use core::num::NonZeroU32;
use std::str::FromStr;

use clap::{Arg, ArgMatches, SubCommand};
use crypto::aes::{ctr, KeySize};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::symmetriccipher::{Decryptor, Encryptor};
use parity_codec::alloc::collections::HashMap;
use rand::thread_rng;
use ring::digest::SHA256;
use ring::pbkdf2::derive;
use serde::{Deserialize, Serialize};
use sss_rs::wrapped_sharing::share;
use yee_signer::KeyPair;

use crate::modules::account::{desc_public_key, generate_account, random_32_bytes};
use crate::modules::base::Hex;
use crate::modules::{base, Command, Module};

pub fn module<'a, 'b>() -> Module<'a, 'b> {
	Module {
		desc: "Keystore tools".to_string(),
		commands: commands(),
		get_cases: cases::cases,
	}
}

pub fn commands<'a, 'b>() -> Vec<Command<'a, 'b>> {
	let mut app = SubCommand::with_name("keystore").about("Keystore tools");
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
				.about("Generate account and save to keystore file")
				.arg(
					Arg::with_name("KEYSTORE_PATH")
						.long("keystore-path")
						.short("k")
						.help("Keystore path")
						.takes_value(true)
						.required(true),
				)
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
				)
				.arg(
					Arg::with_name("TOTAL")
						.long("total")
						.short("t")
						.help("Total password keepers")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("REQUIRE")
						.long("require")
						.short("r")
						.help("Require password keepers")
						.takes_value(true)
						.required(true),
				),
			f: generate,
		},
		Command {
			app: SubCommand::with_name("desc")
				.about("Desc keystore file")
				.arg(
					Arg::with_name("KEYSTORE_PATH")
						.long("keystore-path")
						.short("k")
						.help("Keystore path")
						.takes_value(true)
						.required(true),
				),
			f: desc,
		},
		Command {
			app: SubCommand::with_name("import")
				.about("Import account and save to keystore file")
				.arg(
					Arg::with_name("KEYSTORE_PATH")
						.long("keystore-path")
						.short("k")
						.help("Keystore path")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("TOTAL")
						.long("total")
						.short("t")
						.help("Total password keepers")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("REQUIRE")
						.long("require")
						.short("r")
						.help("Require password keepers")
						.takes_value(true)
						.required(true),
				),
			f: import,
		},
		Command {
			app: SubCommand::with_name("export")
				.about("Export account and save to a new keystore file")
				.arg(
					Arg::with_name("KEYSTORE_PATH")
						.long("keystore-path")
						.short("k")
						.help("Keystore path")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("NEW_KEYSTORE_PATH")
						.long("new-keystore-path")
						.short("n")
						.help("New keystore path")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("TOTAL")
						.long("total")
						.short("t")
						.help("Total password keepers")
						.takes_value(true)
						.required(true),
				)
				.arg(
					Arg::with_name("REQUIRE")
						.long("require")
						.short("r")
						.help("Require password keepers")
						.takes_value(true)
						.required(true),
				),
			f: export,
		},
	]
}

fn generate(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let keystore_path = matches.value_of("KEYSTORE_PATH").expect("qed");

	match std::fs::File::open(keystore_path) {
		Ok(_) => return Err("Keystore file exists".to_string()),
		_ => (),
	}

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

	let total = matches
		.value_of("TOTAL")
		.expect("qed")
		.parse::<u8>()
		.map_err(|_| "Invalid total")?;

	let require = matches
		.value_of("REQUIRE")
		.expect("qed")
		.parse::<u8>()
		.map_err(|_| "Invalid require")?;

	let (_mini_secret_key, public_key, secret_key, _address, _testnet_address) =
		generate_account(shard_num, shard_count)?;

	put_keystore(&public_key, &secret_key, total, require, keystore_path)?;

	base::output("Ok")
}

fn desc(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let keystore_path = matches.value_of("KEYSTORE_PATH").expect("qed");
	let secret_key = get_keystore(keystore_path)?;

	let key_pair = KeyPair::from_secret_key(&secret_key)?;

	let public_key = key_pair.public_key();

	let output = desc_public_key(public_key.to_vec());

	base::output(output)
}

fn import(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let keystore_path = matches.value_of("KEYSTORE_PATH").expect("qed");

	match std::fs::File::open(keystore_path) {
		Ok(_) => return Err("Keystore file exists".to_string()),
		_ => (),
	}

	let total = matches
		.value_of("TOTAL")
		.expect("qed")
		.parse::<u8>()
		.map_err(|_| "Invalid total")?;

	let require = matches
		.value_of("REQUIRE")
		.expect("qed")
		.parse::<u8>()
		.map_err(|_| "Invalid require")?;

	let prompt = format!("Secret key: ");
	let secret_key = rpassword::read_password_from_tty(Some(&prompt)).unwrap();
	let secret_key: Vec<u8> = Hex::from_str(&secret_key)?.into();

	let key_pair = KeyPair::from_secret_key(&secret_key)?;
	let public_key = key_pair.public_key();

	put_keystore(&public_key, &secret_key, total, require, keystore_path)?;

	base::output("Ok")
}

fn export(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let keystore_path = matches.value_of("KEYSTORE_PATH").expect("qed");

	let new_keystore_path = matches.value_of("NEW_KEYSTORE_PATH").expect("qed");

	match std::fs::File::open(new_keystore_path) {
		Ok(_) => return Err("New keystore file exists".to_string()),
		_ => (),
	}

	let total = matches
		.value_of("TOTAL")
		.expect("qed")
		.parse::<u8>()
		.map_err(|_| "Invalid total")?;

	let require = matches
		.value_of("REQUIRE")
		.expect("qed")
		.parse::<u8>()
		.map_err(|_| "Invalid require")?;

	println!("Load from old keystore file: ");
	let secret_key = get_keystore(keystore_path)?;

	let key_pair = KeyPair::from_secret_key(&secret_key)?;

	let public_key = key_pair.public_key();

	println!("Save to new keystore file: ");

	put_keystore(&public_key, &secret_key, total, require, new_keystore_path)?;

	base::output("Ok")
}

#[derive(Serialize, Deserialize)]
struct Keystore {
	version: String,
	index_salt: Hex,
	key_salt: Hex,
	public_key: Hex,
	share_list: HashMap<String, Hex>,
	require: u8,
}

fn put_keystore(
	public_key: &[u8],
	secret_key: &[u8],
	total: u8,
	require: u8,
	keystore_path: &str,
) -> Result<(), String> {
	let mut password_list: Vec<String> = vec![];
	for i in 0..total {
		let password = loop {
			let index = i + 1;
			let prompt = format!("Password ({}/{}): ", index, total);
			let password = rpassword::read_password_from_tty(Some(&prompt)).unwrap();
			let prompt = format!("Retype password: ({}/{}): ", index, total);
			let password2 = rpassword::read_password_from_tty(Some(&prompt)).unwrap();
			if password == password2 {
				break password;
			}
			println!("Passwords do not match\n");
		};
		password_list.push(password);
	}
	let secret = secret_key.to_vec();

	let share_list = match total {
		total if total > 1 => share(
			sss_rs::wrapped_sharing::Secret::InMemory(secret),
			require,
			total,
		)
		.map_err(|_| "Create share failed")?,
		1 => vec![secret],
		_ => {
			return Err("Invalid total".to_string());
		}
	};

	let index_salt = random_32_bytes(&mut thread_rng());
	let key_salt = random_32_bytes(&mut thread_rng());

	let share_list = password_list
		.into_iter()
		.zip(share_list.into_iter())
		.map(|(password, share)| {
			let index = password_to_index(&password, &index_salt);
			let index: String = {
				let tmp: Hex = index.into();
				tmp.into()
			};
			let share = aes_enc(&share, &password, &key_salt)?;
			let share: Hex = share.into();
			Ok((index, share))
		})
		.collect::<Result<HashMap<_, _>, String>>()?;

	let keystore = Keystore {
		version: KEYSTORE_VERSION.to_string(),
		index_salt: index_salt.to_vec().into(),
		key_salt: key_salt.to_vec().into(),
		public_key: public_key.to_vec().into(),
		share_list,
		require,
	};

	let content = serde_json::to_string(&keystore).map_err(|_| "Keystore encode failed")?;

	base::put_to_file(content.as_bytes(), keystore_path)?;

	Ok(())
}

pub fn get_keystore(keystore_path: &str) -> Result<Vec<u8>, String> {
	let content = base::get_from_file(keystore_path)?;

	let keystore: Keystore =
		serde_json::from_slice(&content).map_err(|_| "Keystore decode failed")?;

	if keystore.version != KEYSTORE_VERSION {
		return Err("Invalid keystore version".to_string());
	}

	let mut password_list: Vec<String> = vec![];
	for i in 0..keystore.require {
		let prompt = format!("Password ({}/{}): ", i + 1, keystore.require);
		let password = rpassword::read_password_from_tty(Some(&prompt)).unwrap();
		password_list.push(password);
	}

	let index_salt: Vec<u8> = keystore.index_salt.into();
	let key_salt: Vec<u8> = keystore.key_salt.into();

	let share_list = keystore.share_list;

	let recon_share_list = password_list
		.into_iter()
		.map(|password| {
			let index: Hex = password_to_index(&password, &index_salt).into();
			let index: String = index.into();

			let share = share_list
				.get(&index)
				.ok_or("Invalid password list")?
				.clone();
			let share: Vec<u8> = share.into();
			let share = aes_dec(&share, &password, &key_salt)?;
			Ok(share)
		})
		.collect::<Result<Vec<_>, String>>()?;

	let secret_key = match recon_share_list.len() {
		len if len > 1 => {
			let mut recon = sss_rs::wrapped_sharing::Secret::empty_in_memory();
			recon
				.reconstruct(recon_share_list)
				.map_err(|_| "Reco failed")?;

			let secret_key = recon.unwrap_to_vec().map_err(|_| "Recon failed")?;
			secret_key
		}
		1 => recon_share_list.get(0).expect("qed").clone(),
		_ => {
			return Err("Invalid keystore".to_string());
		}
	};

	let key_pair = KeyPair::from_secret_key(&secret_key)?;

	let expected_public_key: Hex = key_pair.public_key().to_vec().into();

	if expected_public_key != keystore.public_key {
		return Err("Invalid password list".to_string());
	}

	Ok(secret_key)
}

const KEYSTORE_VERSION: &'static str = "1.0";
const KEY_SIZE: KeySize = KeySize::KeySize256;

pub fn aes_enc(plain: &[u8], password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
	let (key, iv) = password_to_key(&password, salt);

	let mut a = ctr(KEY_SIZE, &key, &iv);
	let mut result = vec![0u8; plain.len()];
	a.encrypt(
		&mut RefReadBuffer::new(&plain),
		&mut RefWriteBuffer::new(&mut result),
		true,
	)
	.map_err(|_| "Enc failed")?;

	Ok(result)
}

pub fn aes_dec(cipher: &[u8], password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
	let (key, iv) = password_to_key(&password, salt);
	let mut a = ctr(KEY_SIZE, &key, &iv);
	let mut result = vec![0u8; cipher.len()];
	let mut buffer = RefWriteBuffer::new(&mut result);
	a.decrypt(&mut RefReadBuffer::new(&cipher), &mut buffer, true)
		.map_err(|_| "Dec failed")?;

	Ok(result)
}

const INDEX_ITERATIONS: u32 = 32;
const INDEX_SALT_PREFIX: &'static [u8] = b"yee-utils-password-index";

fn password_to_index(password: &str, salt: &[u8]) -> Vec<u8> {
	let mut whole_salt = INDEX_SALT_PREFIX.to_vec();
	whole_salt.append(&mut salt.to_vec());

	let secret = password.as_bytes();
	let iterations = NonZeroU32::new(INDEX_ITERATIONS).expect("qed");
	let mut result = [0u8; 8];
	derive(&SHA256, iterations, &whole_salt, &secret, &mut result);

	result.to_vec()
}

const KEY_ITERATIONS: u32 = 1024;
const KEY_SALT_PREFIX: &'static [u8] = b"yee-utils-password-key";

fn password_to_key(password: &str, salt: &[u8]) -> ([u8; 32], [u8; 32]) {
	let mut whole_salt = KEY_SALT_PREFIX.to_vec();
	whole_salt.append(&mut salt.to_vec());

	let secret = password.as_bytes();
	let iterations = NonZeroU32::new(KEY_ITERATIONS).expect("qed");
	let mut result = [0u8; 64];
	derive(&SHA256, iterations, &whole_salt, &secret, &mut result);

	let mut key = [0u8; 32];
	let mut iv = [0u8; 32];
	key.copy_from_slice(&result[0..32]);
	iv.copy_from_slice(&result[32..]);

	(key, iv)
}

mod cases {
	use linked_hash_map::LinkedHashMap;

	use crate::modules::Case;

	pub fn cases() -> LinkedHashMap<&'static str, Vec<Case>> {
		vec![(
			"keystore",
			vec![
				Case {
					desc: "Generate key pair and save to keystore file".to_string(),
					input: vec![
						"generate",
						"-k",
						"./keystore.json",
						"-s",
						"0",
						"-c",
						"4",
						"-t",
						"3",
						"-r",
						"2",
					]
					.into_iter()
					.map(Into::into)
					.collect(),
					output: vec![
						r#"{
  "result": "Ok"
}"#,
					]
					.into_iter()
					.map(Into::into)
					.collect(),
					is_example: true,
					is_test: false,
					since: "0.1.0".to_string(),
				},
				Case {
					desc: "Desc keystore file".to_string(),
					input: vec!["desc", "-k", "./keystore.json"]
						.into_iter()
						.map(Into::into)
						.collect(),
					output: vec![
						r#"{
  "result": {
    "Ok": {
      "public_key": "0x68f84b8652acc98505827f092b3652ad8329f5a3e504ccdf29f1c44d1538b578",
      "address": "yee1druyhpjj4nyc2pvz0uyjkdjj4kpjnadru5zvehef78zy69fck4uq2vaymh",
      "testnet_address": "tyee1druyhpjj4nyc2pvz0uyjkdjj4kpjnadru5zvehef78zy69fck4uq8t6j6y",
      "shard": [
        {
          "shard_num": 0,
          "shard_count": 4
        },
        {
          "shard_num": 0,
          "shard_count": 8
        }
      ]
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
				},
				Case {
					desc: "Import account and save to keystore file".to_string(),
					input: vec!["import", "-k", "./keystore.json"]
						.into_iter()
						.map(Into::into)
						.collect(),
					output: vec![
						r#"{
  "result": "Ok"
}"#,
					]
					.into_iter()
					.map(Into::into)
					.collect(),
					is_example: true,
					is_test: false,
					since: "0.1.0".to_string(),
				},
				Case {
					desc: "Export account and save to a new keystore file".to_string(),
					input: vec![
						"export",
						"-k",
						"./keystore.json",
						"-n",
						"./new_keystore.json",
						"-t",
						"3",
						"-r",
						"2",
					]
					.into_iter()
					.map(Into::into)
					.collect(),
					output: vec![
						r#"{
  "result": "Ok"
}"#,
					]
					.into_iter()
					.map(Into::into)
					.collect(),
					is_example: true,
					is_test: false,
					since: "0.1.0".to_string(),
				},
			],
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
