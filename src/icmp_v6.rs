use std::{
    ffi::CString,
    io,
    mem::{self},
    net::Ipv6Addr,
};

#[derive(Debug, Clone)]
pub struct ICMPv6Socket {
    fd: libc::c_int,
}

impl ICMPv6Socket {
    pub fn new(interface: &str) -> io::Result<Self> {
        let socket = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6) };
        if socket == -1 {
            return Err(io::Error::last_os_error());
        }

        let nic = CString::new(interface).unwrap();

        let result = unsafe {
            libc::setsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                nic.as_ptr() as *const libc::c_void,
                (interface.len() + 1) as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd: socket })
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Ipv6Addr)> {
        // let mut peer: libc::sockaddr = unsafe { std::mem::zeroed() };
        let mut peer: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let size = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
                0,
                &mut peer as *mut _ as *mut libc::sockaddr,
                &mut (mem::size_of_val(&peer) as libc::socklen_t),
            )
        };
        if size == -1 {
            return Err(io::Error::last_os_error());
        }

        let remote_addr = Ipv6Addr::from(peer.sin6_addr.s6_addr);

        Ok((size as usize, remote_addr))
    }

    #[allow(unused)]
    pub fn send(&self, buf: &[u8], remote: Ipv6Addr) -> io::Result<usize> {
        let addr = ipv6_addr_to_sock_addr(remote);
        let size = unsafe {
            libc::sendto(
                self.fd,
                buf.as_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
                0,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of_val(&addr) as libc::socklen_t,
            )
        };

        if size == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(size as usize)
    }
}

fn ipv6_addr_to_sock_addr(ipv6_addr: Ipv6Addr) -> libc::sockaddr_in6 {
    let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    addr.sin6_addr = unsafe { mem::zeroed() };
    addr.sin6_addr.s6_addr = ipv6_addr.octets();

    addr
}
