use std::str::FromStr;

use clap::{Arg, ArgMatches, SubCommand};

use crate::modules::{base, Command, Module};
use crate::modules::base::{get_rpc, Hex};
use crate::modules::meter::{BlockInfo, get_block_info, Number};

pub fn module<'a, 'b>() -> Module<'a, 'b> {
    Module {
        desc: "Block tools".to_string(),
        commands: commands(),
        get_cases: cases::cases,
    }
}

pub fn commands<'a, 'b>() -> Vec<Command<'a, 'b>> {
    let mut app = SubCommand::with_name("block").about("Block tools");
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
                    Arg::with_name("FROM_BLOCK_NUMBER")
                        .long("from")
                        .help("From block number: (numeric)")
                        .takes_value(true)
                        .required(false),
                )
                .arg(
                    Arg::with_name("TO_BLOCK_NUMBER")
                        .long("to")
                        .help("To block number: (numeric)")
                        .takes_value(true)
                        .required(false),
                ),
            f: search,
        },
    ]
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

    let from: u64 = match matches.value_of("FROM_BLOCK_NUMBER") {
        Some(v) => {
            let tmp = v.parse::<u64>().map_err(|_| "Invalid from block number")?;
            tmp
        }
        None => best_number - 20,
    };

    let to: u64 = match matches.value_of("TO_BLOCK_NUMBER") {
        Some(v) => {
            let tmp = v.parse::<u64>().map_err(|_| "Invalid to block number")?;
            tmp
        }
        None => best_number,
    };

    let number_range = Some((from, to));

    let mut items = vec![];

    if let Some((from, to)) = number_range {
        for i in from..(to + 1) {
            let info = get_block_info(Number::Number(i), rpc)?;
            if accept_item(&info, expected_hash.as_ref()) {
                items.push(info);
            }
        }
    }

    let result = items
        .into_iter()
        .map(Into::into)
        .collect::<Vec<BlockInfo>>();

    base::output(&result)
}

fn accept_item(
    item: &BlockInfo,
    expected_hash: Option<&Vec<u8>>,
) -> bool {
    if let Some(expected_hash) = expected_hash {
        let expected_hash: Hex = expected_hash.clone().into();
        if &expected_hash != &item.hash {
            return false;
        }
    }

    true
}

mod cases {
    use linked_hash_map::LinkedHashMap;

    use crate::modules::Case;

    pub fn cases() -> LinkedHashMap<&'static str, Vec<Case>> {
        vec![
            (
                "block",
                vec![Case {
                    desc: "Search block".to_string(),
                    input: vec!["search", "-r", "http://localhost:9033", "--from", "1150"].into_iter().map(Into::into).collect(),
                    output: vec![r#"{
  "result": [
    {
      "number": 1150,
      "hash": "0x903a8e02336a47b536c5b13a9d4d8b1b5a2930eee242667b9a97e318e33cb3d9",
      "shard": {
        "shard_num": 0,
        "shard_count": 4
      },
      "crfg": {
        "authorities": [
          [
            "0x5e9cb166bc21d67b352e97e9d58a8d629b8d1460eee846ed5bda410c3f627d68",
            8
          ],
          [
            "0xc260e48a949ae9fdcfc3386d82b59fa3cb5c9532323cdb48273bf1d1d6f635d9",
            5
          ]
        ]
      },
      "finality_tracker": 1143,
      "pow": {
        "timestamp": 1596617127799,
        "time": "2020-08-05 16:45:27 +0800",
        "target": "0x000000000029e58079ffc641bce1b5a880ea48e3a7684b0d15c9142ec8c445ea",
        "diff": "6718342411201"
      }
    },
    {
      "number": 1151,
      "hash": "0x3aee43c4df4323292321debcbe3a957f7af8a88220300308a79d0a1e735332d2",
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
      "finality_tracker": 1144,
      "pow": {
        "timestamp": 1596617131797,
        "time": "2020-08-05 16:45:31 +0800",
        "target": "0x000000000029e58079ffc641bce1b5a880ea48e3a7684b0d15c9142ec8c445ea",
        "diff": "6718342411201"
      }
    },
    {
      "number": 1152,
      "hash": "0x8f2d363a10d4f1ff7a93c5b289e2d000230d9f2d7213a622962c24e237bc48ad",
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
      "finality_tracker": 1145,
      "pow": {
        "timestamp": 1596617180943,
        "time": "2020-08-05 16:46:20 +0800",
        "target": "0x000000000029e58079ffc641bce1b5a880ea48e3a7684b0d15c9142ec8c445ea",
        "diff": "6718342411201"
      }
    },
    {
      "number": 1153,
      "hash": "0x24b7f98e9917ff3b41f50f661fc7e914bd28ce681615936b2b42f118cb87b249",
      "shard": {
        "shard_num": 0,
        "shard_count": 4
      },
      "crfg": {
        "authorities": [
          [
            "0xc260e48a949ae9fdcfc3386d82b59fa3cb5c9532323cdb48273bf1d1d6f635d9",
            6
          ],
          [
            "0x5e9cb166bc21d67b352e97e9d58a8d629b8d1460eee846ed5bda410c3f627d68",
            7
          ]
        ]
      },
      "finality_tracker": 1145,
      "pow": {
        "timestamp": 1596617183930,
        "time": "2020-08-05 16:46:23 +0800",
        "target": "0x000000000029e58079ffc641bce1b5a880ea48e3a7684b0d15c9142ec8c445ea",
        "diff": "6718342411201"
      }
    }
  ]
}"#].into_iter().map(Into::into).collect(),
                    is_example: true,
                    is_test: false,
                    since: "0.6.0".to_string(),
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
