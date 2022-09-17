use std::{
    borrow::Cow,
    net::Ipv6Addr,
    process::{self, Command},
    thread::spawn,
    time::Duration,
};

use crate::{
    config::{AddressConfig, InterfaceConfig},
    icmp_v6::ICMPv6Socket,
};
use pnet::{
    datalink::{self, NetworkInterface},
    packet::{
        icmpv6::{
            self,
            ndp::{MutableRouterSolicitPacket, NdpOptionTypes, RouterAdvertPacket},
            Icmpv6Packet, Icmpv6Types,
        },
        Packet, PacketSize,
    },
};
use pnet_macros::packet;
use pnet_macros_support::types::u32be;

#[derive(Debug, Clone)]
pub struct InterfaceConfigTask {
    iface_name: String,
    config: InterfaceConfig,
    interface: NetworkInterface,
    socket: ICMPv6Socket,
}

impl InterfaceConfigTask {
    pub fn new(iface_name: String, config: InterfaceConfig) -> Self {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == iface_name)
            .unwrap();
        Self {
            socket: ICMPv6Socket::new(&iface_name).unwrap(),
            iface_name,
            config,
            interface,
        }
    }
    pub fn handle(self) {
        let task = self.clone();
        spawn(move || task.send_rs());

        let mut buf = [0u8; 1500];
        loop {
            let (size, addr) = self.socket.recv_from(&mut buf).unwrap();
            let packet = &buf[..size];
            if let Err(err) = self.handle_icmpv6_packet(addr, packet) {
                log::error!("{err}");
            }
        }
    }

    pub fn send_rs(self) {
        let mut buf = [0u8; 1500];
        let size = self.build_rs_packet(&mut buf).unwrap();
        let packet = &buf[..size];

        loop {
            for _ in 0..self.config.max_rtr_solicitations {
                let result = self
                    .socket
                    .send(packet, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2));
                if let Err(err) = result {
                    log::error!("{err}");
                }

                std::thread::sleep(Duration::from_secs(self.config.rtr_solicitation_interval));
            }

            std::thread::sleep(Duration::from_secs(self.config.max_rtr_solicitation_delay));
        }
    }

    fn handle_icmpv6_packet(&self, remote_addr: Ipv6Addr, packet: &[u8]) -> Result<(), Cow<str>> {
        let icmpv6_packet = Icmpv6Packet::new(packet).ok_or("Invalid ICMPv6 packet")?;

        if icmpv6_packet.get_icmpv6_type() != Icmpv6Types::RouterAdvert {
            return Ok(());
        }

        // log::debug!(
        //     "Get ICMPv6 packet type = {:?}",
        //     icmpv6_packet.get_icmpv6_type()
        // );

        let ra_packet = RouterAdvertPacket::new(packet).ok_or("Invalid RA packet")?;

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

        if let Err(err) = self.config_default_route(remote_addr, ra_packet) {
            log::error!("Failed to config default route: {err}");
        }

        Ok(())
    }

    fn config_default_route(
        &self,
        remote_addr: Ipv6Addr,
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
                    &remote_addr.to_string(),
                    "dev",
                    &self.iface_name,
                    "expires",
                    &ra_packet.get_lifetime().to_string(),
                ])
                .spawn()
                .map_err(|e| e.to_string())?;
            log::info!(
                "Added default route via {} dev {}",
                remote_addr,
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

            ipv6_addr[8..].copy_from_slice(&suffix);

            let ipv6_addr = Ipv6Addr::from(ipv6_addr);

            process::Command::new("ip")
                .args([
                    "addr",
                    "add",
                    &format!("{}/{}", ipv6_addr, prefix_info.get_prefix_length()),
                    "dev",
                    &self.iface_name,
                    "valid_lft",
                    &prefix_info.get_valid_lifetime().to_string(),
                    "preferred_lft",
                    &prefix_info.get_prefered_lifetime().to_string(),
                    "noprefixroute",
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

    fn build_rs_packet(&self, buf: &mut [u8]) -> Result<usize, Cow<str>> {
        // log::debug!("Construct Router Solicit");
        let buf = &mut buf[..MutableRouterSolicitPacket::minimum_packet_size()];
        let mut rs_packet =
            MutableRouterSolicitPacket::new(buf).ok_or("Failed to create RS packet")?;
        rs_packet.set_icmpv6_type(Icmpv6Types::RouterSolicit);
        rs_packet.set_icmpv6_code(icmpv6::Icmpv6Code(0));
        rs_packet.set_checksum(0xffff);
        let icmp_packet =
            Icmpv6Packet::new(rs_packet.packet()).ok_or("Failed to construct ICMPv6 packet")?;
        let src_addr = Ipv6Addr::UNSPECIFIED;
        let dst_addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
        let checksum = icmpv6::checksum(&icmp_packet, &src_addr, &dst_addr);
        drop(icmp_packet);
        rs_packet.set_checksum(checksum);

        // let mut ip_buf = [0u8; MutableIpv6Packet::minimum_packet_size() + 8];
        // let mut ipv6_packet =
        //     MutableIpv6Packet::new(&mut ip_buf).ok_or("Failed to create IPv6 packet")?;
        // ipv6_packet.set_version(6);
        // ipv6_packet.set_payload_length(rs_packet.packet_size() as u16);
        // ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
        // ipv6_packet.set_hop_limit(255);
        // ipv6_packet.set_source(src_addr);
        // ipv6_packet.set_destination(dst_addr);
        // ipv6_packet.set_payload(rs_packet.packet());
        // let size = ipv6_packet.packet_size();
        // drop(ipv6_packet);
        // sender
        //     .send_to(&ip_buf[..size], Some(self.interface.clone()))
        //     .unwrap()
        //     .map_err(|e| e.to_string())?;

        Ok(rs_packet.packet_size())
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
