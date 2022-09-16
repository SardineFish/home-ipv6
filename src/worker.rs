use std::{
    borrow::Cow,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    process::{self, Command},
    thread::spawn,
    time::{Duration, Instant},
};

use crate::config::{AddressConfig, InterfaceConfig};
use pnet::{
    datalink::{self, Channel, ChannelType, DataLinkSender, EtherType, NetworkInterface},
    packet::{
        icmpv6::{
            self,
            ndp::{MutableRouterSolicitPacket, NdpOptionTypes, RouterAdvertPacket},
            Icmpv6Packet, Icmpv6Types,
        },
        ip::IpNextHeaderProtocols,
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        Packet, PacketSize,
    },
};
use pnet_macros::packet;
use pnet_macros_support::types::{u16be, u32be, u64be};

const ETH_P_IPV6: EtherType = 0x86DD;

#[derive(Debug, Clone)]
pub struct InterfaceConfigTask {
    iface_name: String,
    config: InterfaceConfig,
    interface: NetworkInterface,
}

impl InterfaceConfigTask {
    pub fn new(iface_name: String, config: InterfaceConfig) -> Self {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == iface_name)
            .unwrap();
        Self {
            iface_name,
            config,
            interface,
        }
    }
    pub fn handle(self) {
        if self.config.accept_teredo.is_some() {
            let task = self.clone();
            spawn(move || task.handle_teredo_tunnel());
        }
        if let Channel::Ethernet(mut tx, mut rx) = datalink::channel(
            &self.interface,
            pnet::datalink::Config {
                channel_type: ChannelType::Layer3(ETH_P_IPV6),
                promiscuous: true,
                read_timeout: Some(Duration::from_secs(1)),
                ..Default::default()
            },
        )
        .unwrap()
        {
            let mut next_rs = Instant::now();
            log::info!("Listening packet on {}", self.iface_name);
            loop {
                match rx.next() {
                    Ok(packet) => {
                        if let Err(err) = self.handle_ipv6_packet(packet) {
                            log::error!("{err}");
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::TimedOut => (),
                    err => {
                        err.unwrap();
                    }
                }

                if Instant::now() >= next_rs {
                    next_rs = Instant::now() + Duration::from_secs(self.config.rs_duration);
                    if let Err(err) = self.send_rs(&mut tx) {
                        log::error!("{err}");
                    }
                }
            }
        }
    }

    fn handle_teredo_tunnel(self) {
        let _addr = if let Some(addr) = &self.config.accept_teredo {
            let addr: Ipv4Addr = addr.parse().unwrap();
            addr
        } else {
            return;
        };

        let socket = std::net::UdpSocket::bind("0.0.0.0:3544").unwrap();
        let mut buf = [0u8; 1500];
        loop {
            let packet = match socket.recv(&mut buf) {
                Ok(len) => &buf[..len],
                Err(err) => {
                    log::error!("{err}");
                    return;
                }
            };

            if let Err(err) = self.handle_teredo_ipv6_packet(packet) {
                log::error!("{err}");
            }
        }
    }

    fn handle_teredo_ipv6_packet(&self, mut packet: &[u8]) -> Result<(), Cow<str>> {
        loop {
            packet = match &packet[..2] {
                // Authentication
                [0, 1] => {
                    let auth_packet = TeredoAuthenticationPacket::new(packet)
                        .ok_or("Failed to parse TeredoAuthenticationPacket")?;
                    let header_size = auth_packet.packet_size() - auth_packet.payload().len();
                    &packet[header_size..]
                }

                // Origin indication
                [0, 0] => &packet[8..],

                // IPv6 payload
                [6, _] => {
                    self.handle_ipv6_packet(packet)?;
                    break;
                }
                _ => Err("Invalid Teredo payload")?,
            };
        }

        Ok(())
    }

    fn handle_ipv6_packet(&self, packet: &[u8]) -> Result<(), Cow<str>> {
        let ipv6_packet = Ipv6Packet::new(packet).ok_or("Received non IPv6 packet")?;

        // log::debug!(
        //     "get ipv6 packet from {} type {}",
        //     ipv6_packet.get_source(),
        //     ipv6_packet.get_next_header()
        // );

        if ipv6_packet.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
            return Ok(());
        }
        let icmpv6_packet =
            Icmpv6Packet::new(ipv6_packet.payload()).ok_or("Invalid ICMPv6 packet")?;

        if icmpv6_packet.get_icmpv6_type() != Icmpv6Types::RouterAdvert {
            return Ok(());
        }

        // log::debug!(
        //     "Get ICMPv6 packet type = {:?}",
        //     icmpv6_packet.get_icmpv6_type()
        // );

        let ra_packet =
            RouterAdvertPacket::new(ipv6_packet.payload()).ok_or("Invalid RA packet")?;

        // log::debug!(
        //     "Get RA packet with {} options",
        //     ra_packet.get_options().len()
        // );

        if self.config.accept_ra {
            for option in ra_packet.get_options_iter() {
                if let NdpOptionTypes::PrefixInformation = option.get_option_type() {
                    if let Err(err) = self.handle_prefix_info(option.packet()) {
                        log::error!("{err}");
                    }
                }
            }
        }

        if let Err(err) = self.config_default_route(&ipv6_packet, ra_packet) {
            log::error!("Failed to config default route: {err}");
        }

        Ok(())
    }

    fn config_default_route(
        &self,
        ipv6_packet: &Ipv6Packet,
        ra_packet: RouterAdvertPacket,
    ) -> Result<(), Cow<str>> {
        if self.config.set_gateway_route {
            Command::new("ip")
                .args([
                    "-6",
                    "route",
                    "replace",
                    "default",
                    "via",
                    &ipv6_packet.get_source().to_string(),
                    "dev",
                    &self.iface_name,
                    "expires",
                    &ra_packet.get_lifetime().to_string(),
                ])
                .spawn()
                .map_err(|e| e.to_string())?;
            log::info!(
                "Added default route via {} dev {}",
                ipv6_packet.get_source(),
                self.iface_name
            );
        }

        Ok(())
    }

    fn handle_prefix_info(&self, payload: &[u8]) -> Result<(), Cow<str>> {
        let prefix_info =
            RAPrefixInfomationPacket::new(payload).ok_or("Invalid RA Prefix Info packet")?;

        if let Err(err) = self.config_addr(prefix_info) {
            log::error!("Failed to config address: {err}");
        }

        Ok(())
    }

    fn config_addr(&self, prefix_info: RAPrefixInfomationPacket) -> Result<(), Cow<str>> {
        if let AddressConfig::Slaac = self.config.address_config {
            let mac = self
                .interface
                .mac
                .ok_or(format!("No MAC on interface {}", self.iface_name))?;
            let mut ipv6_addr: [u8; 16] = prefix_info.get_prefix().octets();
            let mut suffix: [u8; 8] = [mac.0, mac.1, mac.2, 0xFF, 0xFE, mac.3, mac.4, mac.5];
            suffix[0] ^= 0b00000010;
            (0..8).for_each(|i| {
                ipv6_addr[i + 8] = suffix[i];
            });
            let ipv6_addr = Ipv6Addr::from(ipv6_addr);

            process::Command::new("ip")
                .args([
                    "addr",
                    "add",
                    &ipv6_addr.to_string(),
                    "dev",
                    &self.iface_name,
                    "valid_lft",
                    &prefix_info.get_valid_lifetime().to_string(),
                    "preferred_lft",
                    &prefix_info.get_prefered_lifetime().to_string(),
                ])
                .spawn()
                .map_err(|e| e.to_string())?;

            log::info!(
                "Added IPv6 address {ipv6_addr} from prefix {} with valid_lft {}",
                prefix_info.get_prefix(),
                prefix_info.get_valid_lifetime(),
            );
        };
        Ok(())
    }

    fn send_rs(&self, sender: &mut Box<dyn DataLinkSender>) -> Result<(), Cow<str>> {
        // log::debug!("Construct Router Solicit");
        let mut buf = [0u8; MutableRouterSolicitPacket::minimum_packet_size()];
        let mut rs_packet =
            MutableRouterSolicitPacket::new(&mut buf).ok_or("Failed to create RS packet")?;
        rs_packet.set_icmpv6_type(Icmpv6Types::RouterSolicit);
        rs_packet.set_icmpv6_code(icmpv6::Icmpv6Code(0));
        rs_packet.set_checksum(0xffff);
        let icmp_packet =
            Icmpv6Packet::new(rs_packet.packet()).ok_or("Failed to construct ICMPv6 packet")?;
        let src_addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0xffff, 0xffff, 0xfffe);
        let dst_addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
        let checksum = icmpv6::checksum(&icmp_packet, &src_addr, &dst_addr);
        drop(icmp_packet);
        rs_packet.set_checksum(checksum);

        let mut ip_buf = [0u8; MutableIpv6Packet::minimum_packet_size() + 8];
        let mut ipv6_packet =
            MutableIpv6Packet::new(&mut ip_buf).ok_or("Failed to create IPv6 packet")?;
        ipv6_packet.set_version(6);
        ipv6_packet.set_payload_length(rs_packet.packet_size() as u16);
        ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ipv6_packet.set_hop_limit(255);
        ipv6_packet.set_source(src_addr);
        ipv6_packet.set_destination(dst_addr);
        ipv6_packet.set_payload(rs_packet.packet());
        let size = ipv6_packet.packet_size();
        drop(ipv6_packet);
        sender
            .send_to(&ip_buf[..size], Some(self.interface.clone()))
            .unwrap()
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

/// ``` text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Valid Lifetime                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Preferred Lifetime                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved2                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                            Prefix                             +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
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

/// ```text
/// +--------+--------+--------+--------+
/// |  0x00  | 0x01   | ID-len | AU-len |
/// +--------+--------+--------+--------+
/// |  Client identifier (ID-len        |
/// +-----------------+-----------------+
/// |  octets)        |  Authentication |
/// +-----------------+--------+--------+
/// | value (AU-len octets)    | Nonce  |
/// +--------------------------+--------+
/// | value (8 octets)                  |
/// +--------------------------+--------+
/// |                          | Conf.  |
/// +--------------------------+--------+
/// ```
#[packet]
pub struct TeredoAuthentication {
    pub null: u8,
    pub one: u8,
    pub id_len: u8,
    pub au_len: u8,
    #[length = "id_len"]
    pub client_id: Vec<u8>,
    #[length = "au_len"]
    pub authentication: Vec<u8>,
    pub nonce: u64be,
    pub confirmation: u8,

    #[payload]
    #[length_fn = "teredo_authentication_payload_length"]
    pub payload: Vec<u8>,
}

fn teredo_authentication_payload_length(packet: &TeredoAuthenticationPacket) -> usize {
    let header_size = 4 + packet.get_id_len() + packet.get_au_len() + 8 + 1;
    packet.packet_size() - header_size as usize
}

/// ```text
/// +--------+--------+-----------------+
/// |  0x00  | 0x00   | Origin port #   |
/// +--------+--------+-----------------+
/// |  Origin IPv4 address              |
/// +-----------------------------------+
/// ```
#[packet]
pub struct TeredoOriginIndication {
    pub null: u16be,
    pub origin_port: u16be,
    #[construct_with(u8, u8, u8, u8)]
    pub origin_ipv4_addr: Ipv4Addr,
    #[payload]
    #[length_fn = "teredo_origin_indication_payload_length"]
    pub payload: Vec<u8>,
}

fn teredo_origin_indication_payload_length(packet: &TeredoOriginIndicationPacket) -> usize {
    packet.packet_size() - 8
}
