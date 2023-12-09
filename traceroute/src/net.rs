use crate::error_and_bail;
use anyhow::{bail, Result};
use libc::{
    addrinfo, freeaddrinfo, gai_strerror, getaddrinfo, getnameinfo, in_addr, sockaddr, sockaddr_in,
    socklen_t, AF_INET, NI_MAXHOST, NI_NUMERICHOST,
};
use pnet::packet::{
    icmp::{echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket, IcmpTypes},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{Ipv4Flags, MutableIpv4Packet},
    udp::MutableUdpPacket,
    Packet,
};
use raw_socket::{
    tokio::RawSocket,
    {Domain, Protocol, Type},
};
use std::{
    ffi::{CStr, CString},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
};
use tracing::error;

pub const IP_HDR_LEN: usize = 20;
pub const ICMP_HDR_LEN: usize = 8;
const UDP_HDR_LEN: usize = 8;

const TRACEROUTE_PORT: usize = 33434;

pub const NI_IDN: i32 = 32;
pub const IPPROTO_RAW: i32 = 255;

pub async fn dns_lookup(hostname: &str) -> Result<IpAddr> {
    /* prepare the hints for the getaddrinfo call */
    let hints = addrinfo {
        ai_family: AF_INET,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_flags: 0,
        ai_addrlen: 0,
        ai_canonname: std::ptr::null_mut(),
        ai_addr: std::ptr::null_mut(),
        ai_next: std::ptr::null_mut(),
    };
    let mut res: *mut addrinfo = std::ptr::null_mut();
    let c_hostname = CString::new(hostname)?;

    /* perform the DNS lookup */
    let err = unsafe { getaddrinfo(c_hostname.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if err != 0 {
        /* if the lookup failed, return the error */
        let err_str = unsafe { CStr::from_ptr(gai_strerror(err)).to_str()? };
        error_and_bail!("DNS lookup for host {hostname} failed: {err_str}");
    }

    /* res now points to a linked list of addrinfo structures */
    /* convert the IP address from the first addrinfo structure to a string */
    let addr = unsafe { (*res).ai_addr as *const sockaddr };
    let mut host: [libc::c_char; NI_MAXHOST as usize] = [0; NI_MAXHOST as usize];

    /* use getnameinfo to convert the address into a string */
    let s = unsafe {
        getnameinfo(
            addr,
            (*res).ai_addrlen,
            host.as_mut_ptr(),
            host.len() as socklen_t,
            /* not interested in service info */
            std::ptr::null_mut(),
            0,
            /* return the numeric form of the hostname */
            NI_NUMERICHOST,
        )
    };

    /* free the mem allocated by getaddrinfo */
    unsafe { freeaddrinfo(res) };

    if s != 0 {
        /* if the conversion failed, error_and_bail */
        let err_str = unsafe { CStr::from_ptr(gai_strerror(s)).to_str()? };
        error_and_bail!("address conversion for host {hostname} failed: {err_str}");
    }

    /* convert the C string to a Rust IpAddr and return it */
    let c_str = unsafe { CStr::from_ptr(host.as_ptr()) };
    Ok(c_str.to_str()?.to_string().parse::<IpAddr>()?)
}

pub async fn reverse_dns_lookup(ip_addr: SocketAddr) -> Result<String> {
    let ip = match ip_addr {
        SocketAddr::V4(ipv4_addr) => *ipv4_addr.ip(),
        SocketAddr::V6(_) => error_and_bail!("not implemented for ipv6"),
    };

    let sockaddr = SocketAddrV4::new(ip, 0); /* port is irrelevant for DNS */
    let sockaddr_in = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr: in_addr {
            /* native endianness */
            s_addr: u32::from_ne_bytes(sockaddr.ip().octets()),
        },
        /* padding to make the structure the same size as sock_addr */
        sin_zero: [0; 8],
    };

    tokio::task::spawn_blocking(move || {
        /* NI_MAXHOST is the maximum size of the buffer (in bytes)
         * that can hold a fully-qualified domain name */
        let mut host = [0; NI_MAXHOST as usize];

        let ret = unsafe {
            getnameinfo(
                /* cast the reference to a pointer, and then cast that pointer to *sock_addr */
                &sockaddr_in as *const _ as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as socklen_t,
                host.as_mut_ptr(),
                host.len() as socklen_t,
                /* not interested in retreiving the service name */
                std::ptr::null_mut(),
                0,
                /* Internationalized Domain Name
                 * (see https://en.wikipedia.org/wiki/Internationalized_domain_name) */
                NI_IDN,
            )
        };

        if ret != 0 {
            error_and_bail!("getnameinfo for {ip} failed: {ret}");
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
        Ok(c_str.to_str()?.to_string())
    })
    .await
    .unwrap()
}

pub fn build_ipv4_packet(
    buf: &mut [u8],
    dest: Ipv4Addr,
    size: u16,
    ttl: u8,
    id: u16,
    next_header: IpNextHeaderProtocol,
) -> MutableIpv4Packet {
    use pnet::packet::ipv4::checksum;

    let mut packet = MutableIpv4Packet::new(buf).unwrap();

    packet.set_version(4);
    packet.set_ttl(ttl);
    packet.set_header_length(5); /* n * 32 bits. */

    /* We are setting the identification field to the TTL
     * that we later use to map responses back to correct hops. */
    packet.set_identification(id);
    packet.set_next_level_protocol(next_header);
    packet.set_destination(dest);
    packet.set_flags(Ipv4Flags::DontFragment);
    packet.set_total_length(size);
    packet.set_checksum(checksum(&packet.to_immutable()));

    packet
}

pub fn build_icmp_packet(buf: &mut [u8], id: u16) -> NextPacket {
    use pnet::packet::icmp::checksum;

    let mut packet = MutableEchoRequestPacket::new(buf).unwrap();

    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(IcmpCode::new(0));

    /* a random seq_no is fine */
    packet.set_sequence_number(rand::random::<u16>());

    /* set the identifier to match up responses later on */
    packet.set_identifier(id);

    packet.set_checksum(checksum(&IcmpPacket::new(packet.packet()).unwrap()));

    NextPacket::Icmp(packet)
}

pub fn build_udp_packet(buf: &mut [u8]) -> NextPacket {
    let mut packet = MutableUdpPacket::new(buf).unwrap();

    packet.set_source(TRACEROUTE_PORT as u16);
    packet.set_destination(TRACEROUTE_PORT as u16);
    packet.set_length(UDP_HDR_LEN as u16);
    packet.set_checksum(0);

    NextPacket::Udp(packet)
}

pub async fn to_ipaddr(target: &str) -> Result<Ipv4Addr> {
    match target.parse::<Ipv4Addr>() {
        Ok(addr) => Ok(addr),
        Err(_) => match dns_lookup(target).await {
            Ok(ip_addr) => match ip_addr {
                IpAddr::V4(addr) => Ok(addr),
                IpAddr::V6(_) => error_and_bail!("not implemented for ipv6."),
            },
            Err(_) => error_and_bail!("couldn't resolve the hostname {target}"),
        },
    }
}

pub fn id_from_payload(payload: &[u8]) -> u16 {
    let identifier = &payload[0..2];
    let mut id = identifier[0] as u16;
    id <<= 8;
    id |= identifier[1] as u16;
    id
}

pub fn create_sock() -> Result<RawSocket> {
    match RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into()) {
        Ok(sock) => Ok(sock),
        Err(_) => error_and_bail!("couldn't create the socket"),
    }
}

#[derive(Debug, Copy, Clone)]
pub enum TracerouteProtocol {
    Icmp,
    Udp,
}

impl TracerouteProtocol {
    pub fn get_ipv4_buffer(&self) -> Vec<u8> {
        match self {
            TracerouteProtocol::Udp => vec![0u8; IP_HDR_LEN + UDP_HDR_LEN],
            TracerouteProtocol::Icmp => vec![0u8; IP_HDR_LEN + ICMP_HDR_LEN],
        }
    }

    pub fn get_ipv4_next_header_buffer(&self) -> Vec<u8> {
        match self {
            TracerouteProtocol::Udp => vec![0u8; UDP_HDR_LEN],
            TracerouteProtocol::Icmp => vec![0u8; ICMP_HDR_LEN],
        }
    }

    pub fn get_next_header_length(&self) -> usize {
        match self {
            TracerouteProtocol::Udp => UDP_HDR_LEN,
            TracerouteProtocol::Icmp => ICMP_HDR_LEN,
        }
    }

    pub fn get_next_header_protocol(&self) -> IpNextHeaderProtocol {
        match self {
            TracerouteProtocol::Udp => IpNextHeaderProtocols::Udp,
            TracerouteProtocol::Icmp => IpNextHeaderProtocols::Icmp,
        }
    }

    pub fn build_next_packet<'buffer>(
        &self,
        next_hdr_buf: &'buffer mut [u8],
        id: u16,
    ) -> NextPacket<'buffer> {
        match self {
            TracerouteProtocol::Udp => build_udp_packet(next_hdr_buf),
            TracerouteProtocol::Icmp => build_icmp_packet(next_hdr_buf, id),
        }
    }
}

impl FromStr for TracerouteProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "icmp" => Ok(TracerouteProtocol::Icmp),
            "udp" => Ok(TracerouteProtocol::Udp),
            _ => error_and_bail!("unsupported protocol: {s}"),
        }
    }
}

pub enum NextPacket<'buffer> {
    Udp(MutableUdpPacket<'buffer>),
    Icmp(MutableEchoRequestPacket<'buffer>),
}

impl<'buffer> NextPacket<'buffer> {
    pub fn packet(&self) -> &[u8] {
        match self {
            NextPacket::Udp(packet) => packet.packet(),
            NextPacket::Icmp(packet) => packet.packet(),
        }
    }
}
