use std::{env::args, fs, thread::spawn};

use config::Config;

mod config;
mod handler;

fn main() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    let config = if let Some(config_path) = args().nth(1) {
        let data = fs::read(&config_path).unwrap();
        serde_yaml::from_slice::<Config>(&data).unwrap()
    } else {
        Config::default()
    };

    let join_handles = config.into_iter().map(|(interface, config)| {
        spawn(move || handler::InterfaceConfigTask::new(interface, config).handle())
    });

    for handle in join_handles {
        handle.join().unwrap();
    }
}
