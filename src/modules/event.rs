use std::str::FromStr;

use clap::{Arg, ArgMatches, SubCommand};
use parity_codec::Decode;
use serde::Serialize;
use srml_system::{EventRecord, Phase};
use tokio::runtime::Runtime;
use yee_runtime::Event;

use crate::modules::{base, Command, Module};
use crate::modules::base::{get_rpc, Hex};
use crate::modules::meter::{get_block_info, Number};
use crate::modules::state::get_value_storage_key;

pub fn module<'a, 'b>() -> Module<'a, 'b> {
    Module {
        desc: "Event tools".to_string(),
        commands: commands(),
        get_cases: cases::cases,
    }
}

pub fn commands<'a, 'b>() -> Vec<Command<'a, 'b>> {
    let mut app = SubCommand::with_name("event").about("Event tools");
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
        app: SubCommand::with_name("search")
            .about("Search event")
            .arg(
                Arg::with_name("RPC")
                    .long("rpc")
                    .short("r")
                    .help("RPC address")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("KEYWORD")
                    .long("keyword")
                    .short("k")
                    .help("Keyword")
                    .takes_value(true)
                    .required(false),
            )
            .arg(
                Arg::with_name("FROM_BLOCK_NUMBER")
                    .long("from")
                    .help("From block number: numeric")
                    .takes_value(true)
                    .required(false),
            )
            .arg(
                Arg::with_name("TO_BLOCK_NUMBER")
                    .long("to")
                    .help("To block number: numeric")
                    .takes_value(true)
                    .required(false),
            ),
        f: search,
    }]
}

fn search(matches: &ArgMatches) -> Result<Vec<String>, String> {
    let rpc = &get_rpc(matches);

    let best_number = get_block_info(Number::Best, rpc)?.number;

    let keyword = matches.value_of("KEYWORD");

    let from = match matches.value_of("FROM_BLOCK_NUMBER") {
        Some(v) => {
            let tmp = v.parse::<u64>().map_err(|_| "Invalid from block number")?;
            tmp
        }
        None => best_number - 20,
    };

    let to = match matches.value_of("TO_BLOCK_NUMBER") {
        Some(v) => {
            let tmp = v.parse::<u64>().map_err(|_| "Invalid to block number")?;
            tmp
        }
        None => best_number,
    };

    let mut items = vec![];

    let build_search_item = |event: String, block: SearchItemBlock| -> Result<SearchItem, String> {
        let item = SearchItem { event, block };
        Ok(item)
    };

    for i in from..(to + 1) {
        let block_hash = get_block_info(Number::Number(i), rpc)?.hash;
        let block_hash: Vec<u8> = block_hash.into();
        let events = get_block_events(rpc, &block_hash)?;
        for event in events {
            let block = SearchItemBlock {
                number: i,
                hash: block_hash.clone().into(),
            };
            let item = build_search_item(event, block)?;
            let accept = accept_item(&item, keyword);

            if accept {
                items.push(item);
            }
        }
    }

    base::output(&items)
}

#[derive(Serialize)]
struct SearchItem {
    event: String,
    block: SearchItemBlock,
}

#[derive(Serialize)]
struct SearchItemBlock {
    number: u64,
    hash: Hex,
}

fn accept_item(item: &SearchItem, keyword: Option<&str>) -> bool {
    if let Some(keyword) = keyword {
        return item.event.to_lowercase().contains(&keyword.to_lowercase());
    }

    true
}

fn get_block_events(rpc: &str, block_hash: &[u8]) -> Result<Vec<String>, String> {
    let mut runtime = Runtime::new().expect("qed");

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
        None => return Ok(vec![]),
    };

    let events = Hex::from_str(&events)?;
    let events: Vec<u8> = events.into();
    let events: Vec<EventRecord<Event>> =
        Decode::decode(&mut &events[..]).ok_or("Decode event record failed")?;

    let result = events
        .into_iter()
        .filter_map(|x| match x.phase {
            Phase::ApplyExtrinsic(_index) => match x.event {
                Event::system(_event) => None,
                _ => Some(format!("{:?}", x)),
            },
            Phase::Finalization => Some(format!("{:?}", x)),
        })
        .collect::<Vec<_>>();

    Ok(result)
}

mod cases {
	use linked_hash_map::LinkedHashMap;

	use crate::modules::Case;

	pub fn cases() -> LinkedHashMap<&'static str, Vec<Case>> {
        vec![
            (
                "event",
                vec![
                    Case {
                        desc: "Search event".to_string(),
                        input: vec!["search", "-r", "http://localhost:9033"].into_iter().map(Into::into).collect(),
                        output: vec![r#"{
  "result": [
    {
      "event": "EventRecord { phase: ApplyExtrinsic(5), event: balances(Transfer(927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70 (5FNmWUUd...), 94d988b42d96dcbd6605ff47f19c6ab35f626eb1bc8bbd28f59a74997a253a3d (5FRsZjZU...), 100000000, 0)) }",
      "block": {
        "number": 63,
        "hash": "0x453822219ba447ad31bc7c5499a6a09e475435f7bb9e43b885a8d38c06b50643"
      }
    }
  ]
}"#].into_iter().map(Into::into).collect(),
                        is_example: true,
                        is_test: false,
                        since: "0.3.0".to_string(),
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
