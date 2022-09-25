use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub type Config = HashMap<String, InterfaceConfig>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InterfaceConfig {
    pub accept_ra: bool,
    pub address_config: AddressConfig,
    pub set_link_route: bool,
    pub set_gateway_route: bool,

    /// A host SHOULD transmit up to MAX_RTR_SOLICITATIONS Router Solicitation messages
    ///
    /// See [RFC 6864 Section-6.3.7](https://www.rfc-editor.org/rfc/rfc4861#section-6.3.7)
    pub max_rtr_solicitations: usize,

    /// Each Router Solicitation separated by at least RTR_SOLICITATION_INTERVAL seconds
    ///
    /// See [RFC 6864 Section-6.3.7](https://www.rfc-editor.org/rfc/rfc4861#section-6.3.7)
    pub rtr_solicitation_interval: u64,

    /// If a host sends MAX_RTR_SOLICITATIONS solicitations, and receives no
    /// Router Advertisements after having waited MAX_RTR_SOLICITATION_DELAY
    /// seconds after sending the last solicitation
    ///
    /// See [RFC 6864 Section-6.3.7](https://www.rfc-editor.org/rfc/rfc4861#section-6.3.7)
    pub max_rtr_solicitation_delay: u64,

    pub valid_lft: Option<u64>,

    pub prefer_lft: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AddressConfig {
    Slaac,
    DHCPv6,
    Static(String),
}
