use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub type Config = HashMap<String, InterfaceConfig>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InterfaceConfig {
    pub accept_ra: bool,
    pub send_ra: bool,
    #[serde(default)]
    pub address_config: AddressConfig,
    #[serde(default)]
    pub set_link_route: bool,
    #[serde(default)]
    pub set_gateway_route: bool,

    /// A host SHOULD transmit up to MAX_RTR_SOLICITATIONS Router Solicitation messages
    ///
    /// See [RFC 6864 Section-6.3.7](https://www.rfc-editor.org/rfc/rfc4861#section-6.3.7)
    #[serde(default = "default_max_rtr_solicitations")]
    pub max_rtr_solicitations: usize,

    /// Each Router Solicitation separated by at least RTR_SOLICITATION_INTERVAL seconds
    ///
    /// See [RFC 6864 Section-6.3.7](https://www.rfc-editor.org/rfc/rfc4861#section-6.3.7)
    #[serde(default = "default_rtr_solicitation_interval")]
    pub rtr_solicitation_interval: u64,

    /// If a host sends MAX_RTR_SOLICITATIONS solicitations, and receives no
    /// Router Advertisements after having waited MAX_RTR_SOLICITATION_DELAY
    /// seconds after sending the last solicitation
    ///
    /// See [RFC 6864 Section-6.3.7](https://www.rfc-editor.org/rfc/rfc4861#section-6.3.7)
    #[serde(default = "default_max_rtr_solicitation_delay")]
    pub max_rtr_solicitation_delay: u64,

    pub valid_lft: Option<u64>,

    pub prefer_lft: Option<u64>,

    /// See https://www.rfc-editor.org/rfc/rfc4861#section-6.2.6
    pub ra_min_delay: Option<u64>,

    /// See https://www.rfc-editor.org/rfc/rfc4861#section-6.2.6
    pub ra_max_delay: Option<u64>,

    /// See https://www.rfc-editor.org/rfc/rfc4861#section-4.2
    pub ra_router_lifetime: Option<u64>,

    /// See https://www.rfc-editor.org/rfc/rfc4861#section-4.2
    pub ra_reachable_time: Option<u64>,

    /// See https://www.rfc-editor.org/rfc/rfc4861#section-4.2
    ///
    /// And https://www.rfc-editor.org/rfc/rfc4861#section-7.2
    pub ra_ns_retrans_time: Option<u64>,
}

fn default_max_rtr_solicitations() -> usize {
    3
}

fn default_rtr_solicitation_interval() -> u64 {
    5
}

fn default_max_rtr_solicitation_delay() -> u64 {
    300
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AddressConfig {
    Slaac,
    DHCPv6,
    Static(String),
}

impl Default for AddressConfig {
    fn default() -> Self {
        Self::Slaac
    }
}
