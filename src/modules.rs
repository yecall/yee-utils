use clap::{App, ArgMatches};
use linked_hash_map::LinkedHashMap;
use std::iter;

mod base;
mod completion;
mod key;
mod meter;
mod usage;

#[derive(Clone)]
pub struct Module<'a, 'b> {
    pub desc: String,
    pub commands: Vec<Command<'a, 'b>>,
    pub get_cases: fn() -> LinkedHashMap<&'static str, Vec<Case>>, //lazy
}

#[derive(Clone)]
pub struct Command<'a, 'b> {
    pub app: App<'a, 'b>,
    pub f: fn(&ArgMatches<'a>) -> Result<Vec<String>, String>,
}

#[derive(Clone)]
pub struct Case {
    pub desc: String,
    pub input: Vec<String>,
    pub output: Vec<String>,
    pub is_example: bool,
    pub is_test: bool,
    pub since: String,
}

pub struct ModuleManager<'a, 'b> {
    modules: Vec<Module<'a, 'b>>,
    commands: LinkedHashMap<String, Command<'a, 'b>>,
}

impl<'a, 'b> ModuleManager<'a, 'b> {
    pub fn new() -> Self {
        let mut mm = Self {
            modules: Vec::new(),
            commands: LinkedHashMap::new(),
        };
        mm.register(key::module());
        mm.register(meter::module());
        mm
    }

    pub fn apps(&self) -> Vec<App<'a, 'b>> {
        self.commands
            .iter()
            .map(|(_, command)| command.app.to_owned())
            .chain(iter::once(usage::app()))
            .chain(iter::once(completion::app()))
            .collect()
    }

    pub fn run(&self, name: &str, matches: &ArgMatches<'a>) {
        let result = match name {
            "usage" => usage::run(matches, &self.modules),
            "completion" => completion::run(matches),
            _ => (self.commands.get(name).expect("subcommand must exist").f)(matches),
        };

        match result {
            Ok(result) => result.iter().for_each(|x| println!("{}", x)),
            Err(e) => eprintln!("{}", base::output_error(e)),
        }
    }

    fn register(&mut self, module: Module<'a, 'b>) {
        self.modules.push(module.clone());
        for command in module.commands {
            self.commands
                .insert(command.app.get_name().to_string(), command);
        }
    }
}
