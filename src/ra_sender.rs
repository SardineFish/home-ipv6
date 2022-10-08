use std::{
    borrow::Cow,
    collections::HashMap,
    io,
    net::{IpAddr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, spawn},
    time::{Duration, Instant},
};

use crate::{
    config::InterfaceConfig,
    handler::{
        calc_icmp_checksum, LinkLayerAddress, MutableLinkLayerAddressPacket,
        MutableRAPrefixInfomationPacket, RAPrefixInfomation,
    },
    icmp_v6::ICMPv6Socket,
};

use pnet::{
    datalink,
    packet::{
        icmpv6::{
            ndp::{self, NdpOptionPacket, NdpOptionTypes, RouterAdvert, RouterAdvertPacket},
            Icmpv6Packet,
        },
        Packet, PacketSize,
    },
};
use pnet::{
    packet::{
        icmpv6::{ndp::MutableRouterAdvertPacket, Icmpv6Types},
        FromPacket,
    },
    util::MacAddr,
};
use pnet_macros_support::types::{u16be, u32be};

#[derive(Clone)]
pub struct PrefixStatus {
    info: RAPrefixInfomation,
    last_update: Instant,
    deprecated: bool,
}

#[derive(Clone)]
pub struct PrefixManager {
    prefix: Arc<Mutex<HashMap<Ipv6Addr, PrefixStatus>>>,
}

impl PrefixManager {
    pub fn new() -> Self {
        Self {
            prefix: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_prefix(&self, prefix: RAPrefixInfomation) {
        let mut guard = self.prefix.lock().unwrap();
        guard.insert(
            prefix.prefix,
            PrefixStatus {
                info: prefix,
                last_update: Instant::now(),
                deprecated: false,
            },
        );
    }

    /// Update timer and handle deprecation
    pub fn update(&self) {
        let mut guard = self.prefix.lock().unwrap();

        for status in &mut guard.values_mut() {
            let elapsed = Instant::now() - status.last_update;
            if elapsed.as_secs() > (status.info.prefered_lifetime as u64) {
                status.deprecated = true
            }
        }

        *guard = guard
            .drain()
            .filter_map(|(prefix, status)| {
                let elapsed = Instant::now() - status.last_update;
                if elapsed.as_secs() > (status.info.valid_lifetime as u64) {
                    None
                } else {
                    Some((prefix, status))
                }
            })
            .collect();
    }

    #[allow(unused)]
    pub fn get_prefixes(&self) -> Vec<RAPrefixInfomation> {
        self.prefix
            .lock()
            .unwrap()
            .values()
            .map(|status| status.info.clone())
            .collect()
    }

    pub fn get_prefix_status(&self) -> Vec<PrefixStatus> {
        self.prefix.lock().unwrap().values().cloned().collect()
    }
}

#[derive(Clone)]
pub struct RASender {
    iface_name: String,
    link_layer_addr: MacAddr,
    config: InterfaceConfig,
    prefix_manager: PrefixManager,
    rs_received: Arc<AtomicBool>,
    socket: ICMPv6Socket,
}

impl RASender {
    pub fn new(
        if_name: &str,
        config: InterfaceConfig,
        prefix_manager: PrefixManager,
    ) -> io::Result<Self> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == if_name)
            .unwrap();
        Ok(Self {
            iface_name: if_name.to_string(),
            config,
            prefix_manager,
            rs_received: Arc::new(AtomicBool::new(false)),
            socket: ICMPv6Socket::new(if_name)?,
            link_layer_addr: interface.mac.expect("No MAC address on interface"),
        })
    }

    pub fn handle(self) {
        let sender = self.clone();
        spawn(move || sender.recv_rs());

        let mut last_send = Instant::now();
        let min_delay = self.config.ra_min_delay.unwrap_or(300);
        let max_delay = self.config.ra_max_delay.unwrap_or(600);

        loop {
            thread::sleep(Duration::from_secs(1));

            let elapsed = Instant::now() - last_send;

            let response_rs =
                self.rs_received.swap(false, Ordering::AcqRel) && elapsed.as_secs() > min_delay;
            let ra_timeout = elapsed.as_secs() > max_delay;

            if response_rs || ra_timeout {
                self.prefix_manager.update();

                if let Err(err) = self.send_ra() {
                    log::error!("Failed to send RA: {err}");
                } else {
                    last_send = Instant::now()
                }
            }
        }
    }

    pub fn send_ra(&self) -> Result<(), Cow<str>> {
        let mut options = Vec::new();

        let mut any_available_prefix = false;

        for prefix_status in self.prefix_manager.get_prefix_status() {
            let mut info = prefix_status.info;
            if prefix_status.deprecated {
                info.prefered_lifetime = 0;
                info.valid_lifetime = 0;
            } else {
                info.prefered_lifetime = self.config.prefer_lft.unwrap_or(600) as u32be;
                info.valid_lifetime = self.config.valid_lft.unwrap_or(1800) as u32be;
                any_available_prefix = true;
            }
            info.flags = 0xe0;

            let mut buffer = [0u8; 1500];
            let mut ra_info = MutableRAPrefixInfomationPacket::new(&mut buffer).unwrap();
            ra_info.populate(&info);
            let length = ra_info.packet_size();

            let option = NdpOptionPacket::new(&buffer[0..length])
                .unwrap()
                .from_packet();
            options.push(option);
        }

        if !any_available_prefix {
            return Err("No available prefix".into());
        }

        // Construct Source Layer Address Option
        {
            let mut buffer = [0u8; 1500];
            let packet = LinkLayerAddress {
                typ: NdpOptionTypes::SourceLLAddr,
                length: 1,
                link_layer_addr: self.link_layer_addr.octets().to_vec(),
            };
            let mut mut_packet = MutableLinkLayerAddressPacket::new(&mut buffer).unwrap();
            mut_packet.populate(&packet);
            drop(mut_packet);

            let option = NdpOptionPacket::new(&buffer[0..8]).unwrap().from_packet();
            options.push(option);
        }

        let ra_packet = RouterAdvert {
            icmpv6_type: Icmpv6Types::RouterAdvert,
            icmpv6_code: ndp::Icmpv6Codes::NoCode,
            hop_limit: 64,
            flags: 0,
            lifetime: self.config.ra_router_lifetime.unwrap_or(1800) as u16be,
            reachable_time: self.config.ra_reachable_time.unwrap_or(0) as u32be,
            retrans_time: self.config.ra_ns_retrans_time.unwrap_or(0) as u32be,
            checksum: 0xffff,
            options,
            payload: vec![],
        };

        let link_local_ip = local_ip_address::list_afinet_netifas()
            .map_err(|err| err.to_string())?
            .into_iter()
            .filter_map(|(if_name, addr)| {
                if if_name == self.iface_name {
                    Some(addr)
                } else {
                    None
                }
            })
            .filter_map(|addr| match addr {
                IpAddr::V6(ip) => Some(ip),
                _ => None,
            })
            .find(|ip| (ip.segments()[0] & 0xffc0) == 0xfe80)
            .ok_or(format!("No link local ip on interface {}", self.iface_name))?;

        let multicast_addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

        let mut buffer = [0u8; 1500];
        let mut packet = MutableRouterAdvertPacket::new(&mut buffer).unwrap();
        packet.populate(&ra_packet);
        let checksum = calc_icmp_checksum(&packet, link_local_ip, multicast_addr)?;
        packet.set_checksum(checksum);

        let mut total_size = RouterAdvertPacket::minimum_packet_size();
        total_size += ra_packet
            .options
            .iter()
            .map(|option| option.length as usize * 8)
            .sum::<usize>();

        self.socket
            .send(&packet.packet()[..total_size], multicast_addr)
            .map_err(|err| err.to_string())?;

        log::info!("Sent RA to {}", self.iface_name);

        Ok(())
    }

    fn recv_rs(&self) {
        loop {
            let mut buf = [0u8; 1500];
            match self.socket.recv_from(&mut buf) {
                Err(err) => {
                    log::error!("Failed to receive: {err}");
                }
                Ok((size, addr)) => {
                    if let Err(err) = self.handle_icmpv6_packet(addr, &buf[..size]) {
                        log::error!("{err}");
                    }
                }
            }
        }
    }

    fn handle_icmpv6_packet(&self, remote_addr: Ipv6Addr, packet: &[u8]) -> Result<(), Cow<str>> {
        let icmpv6_packet = Icmpv6Packet::new(packet).ok_or("Invalid ICMPv6 packet")?;

        if icmpv6_packet.get_icmpv6_type() == Icmpv6Types::RouterSolicit {
            self.rs_received.store(true, Ordering::Release);

            log::info!("Received RS from {remote_addr}");
        }
        Ok(())
    }
}
