use clap::{Arg, ArgMatches, SubCommand};
use parity_codec::Decode;
use serde::Serialize;
use yee_signer::tx::call::Call;
use yee_signer::tx::types::{Era, Transaction};

use crate::modules::base::Hex;
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
	vec![Command {
		app: SubCommand::with_name("desc").about("Desc tx").arg(
			Arg::with_name("INPUT")
				.help("raw tx")
				.required(false)
				.index(1),
		),
		f: desc,
	}]
}

fn desc(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let input = base::input_string(matches)?;

	let input: Vec<u8> = input.parse::<Hex>().map_err(|_| "Convert failed")?.into();

	let tx: Transaction = Decode::decode(&mut &input[..]).ok_or("invalid tx")?;

	#[derive(Serialize)]
	struct SerdeTransaction {
		pub signature: Option<(Hex, Hex, u64, SerdeEra)>,
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
			let signature = t.signature.map(|(address, sig, nonce, era)| {
				(
					address.0.to_vec().into(),
					sig.to_vec().into(),
					nonce.0,
					era.into(),
				)
			});
			Self {
				signature,
				call: t.call,
			}
		}
	}

	let tx: SerdeTransaction = tx.into();

	base::output(&tx)
}

mod cases {
	use linked_hash_map::LinkedHashMap;

	use crate::modules::Case;

	pub fn cases() -> LinkedHashMap<&'static str, Vec<Case>> {
		vec![].into_iter().collect()
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
