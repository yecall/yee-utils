use clap::{Arg, ArgMatches, SubCommand};
use serde::Serialize;
use substrate_primitives::{crypto::Pair as PairT, ed25519::Pair};

use crate::modules::base::Hex;
use crate::modules::{base, Command, Module};

pub fn module<'a, 'b>() -> Module<'a, 'b> {
	Module {
		desc: "Authority tools".to_string(),
		commands: commands(),
		get_cases: cases::cases,
	}
}

pub fn commands<'a, 'b>() -> Vec<Command<'a, 'b>> {
	let mut app = SubCommand::with_name("authority").about("Authority tools");
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
			app: SubCommand::with_name("generate").about("Generate authority"),
			f: generate,
		},
		Command {
			app: SubCommand::with_name("phrase")
				.about("Desc phrase")
				.arg(Arg::with_name("INPUT").required(false).index(1)),
			f: phrase,
		},
	]
}

fn generate(_matches: &ArgMatches) -> Result<Vec<String>, String> {
	let (pair, phrase) = Pair::generate_with_phrase(None);

	let public_key = pair.public();

	#[derive(Serialize)]
	struct Output {
		phrase: String,
		public_key: Hex,
	}

	let output = Output {
		phrase,
		public_key: public_key.0.to_vec().into(),
	};

	base::output(output)
}

fn phrase(matches: &ArgMatches) -> Result<Vec<String>, String> {
	let phrase = base::input_string(matches)?;

	let pair = Pair::from_phrase(&phrase, None).map_err(|_| "Invalid phrase")?;

	let public_key = pair.public();

	#[derive(Serialize)]
	struct Output {
		phrase: String,
		public_key: Hex,
	}

	let output = Output {
		phrase,
		public_key: public_key.0.to_vec().into(),
	};

	base::output(output)
}

mod cases {
	use linked_hash_map::LinkedHashMap;

	use crate::modules::Case;

	pub fn cases() -> LinkedHashMap<&'static str, Vec<Case>> {
		vec![(
			"authority",
			vec![
				Case {
					desc: "Generate authority".to_string(),
					input: vec!["generate"].into_iter().map(Into::into).collect(),
					output: vec![r#"{
  "result": {
    "phrase": "travel pair strategy banana marine nature clean remember later excess arrow merry",
    "public_key": "0x2fc157a6859a9d48e1ff8d4e3e3fba5ffb7e1bcbb2e390f120e853d3997d677a"
  }
}"#].into_iter().map(Into::into).collect(),
					is_example: true,
					is_test: false,
					since: "0.1.0".to_string(),
				},
				Case {
					desc: "Desc authority key phrase".to_string(),
					input: vec!["phrase", "'travel pair strategy banana marine nature clean remember later excess arrow merry'"].into_iter().map(Into::into).collect(),
					output: vec![r#"{
  "result": {
    "phrase": "travel pair strategy banana marine nature clean remember later excess arrow merry",
    "public_key": "0x2fc157a6859a9d48e1ff8d4e3e3fba5ffb7e1bcbb2e390f120e853d3997d677a"
  }
}"#].into_iter().map(Into::into).collect(),
					is_example: true,
					is_test: true,
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
