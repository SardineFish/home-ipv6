use std::{borrow::Cow, fmt::format, net::Ipv6Addr};

use crate::config::{AddressConfig, InterfaceConfig};
use pnet::{
    datalink::{self, Channel, ChannelType, EtherType, NetworkInterface},
    packet::{
        ethernet,
        icmpv6::{
            ndp::{NdpOptionTypes, RouterAdvertPacket},
            Icmpv6Packet, Icmpv6Type, Icmpv6Types,
        },
        ip,
        ipv6::Ipv6Packet,
        Packet,
    },
};
use pnet_macros::packet;
use pnet_macros_support::types::u32be;

const ETH_P_IPV6: EtherType = 0x86DD;

pub struct InterfaceConfigTask {
    iface_name: String,
    config: InterfaceConfig,
    interface: NetworkInterface,
}

impl InterfaceConfigTask {
    pub fn new(iface_name: String, config: InterfaceConfig) -> Self {
        let interface = datalink::interfaces()
            .into_iter()
            .filter(|iface| iface.name == iface_name)
            .next()
            .unwrap();
        Self {
            iface_name,
            config,
            interface,
        }
    }
    pub fn handle(self) {
        if let Channel::Ethernet(mut tx, mut rx) = datalink::channel(
            &self.interface,
            pnet::datalink::Config {
                channel_type: ChannelType::Layer3(ETH_P_IPV6),
                ..Default::default()
            },
        )
        .unwrap()
        {
            loop {
                let packet = rx.next().unwrap();
                if let Err(err) = self.handle_ipv6_packet(packet) {
                    log::error!("{err}");
                }
            }
        }
    }

    fn handle_ipv6_packet(&self, packet: &[u8]) -> Result<(), Cow<str>> {
        let ipv6_packet = Ipv6Packet::new(packet).ok_or("Received non IPv6 packet")?;

        let icmpv6_packet = match Icmpv6Packet::new(ipv6_packet.payload()) {
            Some(pk) => pk,
            None => return Ok(()),
        };

        if icmpv6_packet.get_icmpv6_type() != Icmpv6Types::RouterAdvert {
            return Ok(());
        }

        let ra_packet =
            RouterAdvertPacket::new(icmpv6_packet.payload()).ok_or("Invalid RA packet")?;

        if self.config.accept_ra {
            for option in ra_packet.get_options_iter() {
                match option.get_option_type() {
                    NdpOptionTypes::PrefixInformation => {
                        self.handle_prefix_info(option.payload());
                    }
                    _ => (),
                }
            }
        }

        Ok(())
    }

    fn handle_prefix_info(&self, payload: &[u8]) -> Result<(), Cow<str>> {
        let prefix_info =
            RAPrefixInfomationPacket::new(payload).ok_or("Invalid RA Prefix Info packet")?;

        match self.config.address_config {
            AddressConfig::Slaac => {
                let mac = self
                    .interface
                    .mac
                    .ok_or(format!("No MAC on interface {}", self.iface_name))?;
                let mut ipv6_addr: [u8; 16] = prefix_info.get_prefix().octets();
                let mut suffix: [u8; 8] = [mac.0, mac.1, mac.2, 0xFF, 0xF2, mac.3, mac.4, mac.5];
                suffix[0] = suffix[0] ^ 0b00000010;
                for i in 0..8 {
                    ipv6_addr[i + 8] = suffix[i];
                }
                let ipv6_addr = Ipv6Addr::from(ipv6_addr);
                log::info!(
                    "Construct IPv6 address {ipv6_addr} from prefix {}",
                    prefix_info.get_prefix()
                );
            }
            _ => (),
        }

        Ok(())
    }
}

#[packet]
pub struct RAPrefixInfomation {
    pub typ: u8,
    pub length: u8,
    pub prefix_length: u8,
    pub flags: u8,

    pub valid_lifetime: u32be,

    pub prefered_lifetime: u32be,

    pub reserved_2: u32be,

    #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
    pub prefix: Ipv6Addr,

    #[payload]
    #[length = "0"]
    _payload: Vec<u8>,
}
