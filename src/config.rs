use std::collections::HashMap;

use serde::{Serialize, Deserialize};

pub type Config = HashMap<String, InterfaceConfig>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InterfaceConfig {
    pub accept_ra: bool,
    pub address_config: AddressConfig,
    pub set_link_route: bool,
    pub set_gateway_route: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AddressConfig {
    Slaac,
    DHCPv6,
    Static(String)
}