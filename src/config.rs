use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub type Config = HashMap<String, InterfaceConfig>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InterfaceConfig {
    pub accept_ra: bool,
    pub address_config: AddressConfig,
    pub set_link_route: bool,
    pub set_gateway_route: bool,
    pub rs_duration: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AddressConfig {
    Slaac,
    DHCPv6,
    Static(String),
}
