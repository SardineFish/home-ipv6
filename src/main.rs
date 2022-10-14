use std::{env::args, fs, thread::spawn};

use config::Config;
use ra_sender::{PrefixManager, RASender};

mod config;
mod handler;
mod icmp_v6;
mod ra_sender;

fn main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));
    let config = if let Some(config_path) = args().nth(1) {
        let data = fs::read(&config_path).unwrap();
        serde_yaml::from_slice::<Config>(&data).unwrap()
    } else {
        Config::default()
    };

    let prefix_manager = PrefixManager::new();

    let join_handles = config.clone().into_iter().map(|(interface, config)| {
        let prefix_manager = prefix_manager.clone();
        spawn(move || handler::InterfaceConfigTask::new(interface, config, prefix_manager).handle())
    });

    for (name, config) in config.into_iter() {
        if !config.send_ra {
            continue;
        }
        let prefix_manager = prefix_manager.clone();
        spawn(move || {
            RASender::new(&name, config, prefix_manager)
                .unwrap()
                .handle()
        });
    }

    for handle in join_handles {
        handle.join().unwrap();
    }
}
