use anyhow::{anyhow, Result};
use etherparse::{
    Ipv4Header, Ipv4HeaderSlice, Ipv6Header, Ipv6HeaderSlice, TcpHeaderSlice, TransportHeader,
    UdpHeaderSlice,
};

use std::{
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, OwnedFd},
    slice,
};

use crate::ebpf_prog::types::{
    iphdr, ipv6hdr, lnetwork_data, lnetwork_type, ltranposrt_type, ltransport_data, tcphdr, udphdr,
};
use regex::Regex;

use nix::sys::socket::{
    sendto, setsockopt, socket, sockopt, AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType,
    SockaddrIn, SockaddrIn6, SockaddrLike,
};

lazy_static::lazy_static! {
    static ref DOMAIN_REGEX: Regex =
        Regex::new(r"^[A-Za-z0-9.-]+$").unwrap();
}

#[derive(Debug, Clone)]
pub enum NetworkHeader {
    Ipv4(Ipv4Header),
    Ipv6(Ipv6Header),
}

impl NetworkHeader {
    pub fn from_lnetwork_data(lnd: &lnetwork_data) -> Result<Self> {
        match lnd.protocol_type {
            lnetwork_type::IPV4 => {
                let iph = unsafe { &lnd.__anon_lnetwork_data_2.iph };
                let ip_slice = unsafe {
                    slice::from_raw_parts(iph as *const iphdr as *const u8, mem::size_of::<iphdr>())
                };
                let iphdr = Ipv4HeaderSlice::from_slice(ip_slice)?.to_header();
                Ok(NetworkHeader::Ipv4(iphdr))
            }
            lnetwork_type::IPV6 => {
                let ip6h = unsafe { &lnd.__anon_lnetwork_data_2.ip6h };
                let ip6slice = unsafe {
                    slice::from_raw_parts(
                        ip6h as *const ipv6hdr as *const u8,
                        mem::size_of::<ipv6hdr>(),
                    )
                };
                let ip6hdr = Ipv6HeaderSlice::from_slice(ip6slice)?.to_header();
                Ok(NetworkHeader::Ipv6(ip6hdr))
            }
            _ => Err(anyhow!("NetworkHeader parse: invalid lnetwork_type")),
        }
    }

    pub fn saddr(&self) -> IpAddr {
        match &self {
            NetworkHeader::Ipv4(ip4h) => IpAddr::V4(Ipv4Addr::from_octets(ip4h.source)),
            NetworkHeader::Ipv6(ip6h) => IpAddr::V6(Ipv6Addr::from_octets(ip6h.source)),
        }
    }

    pub fn daddr(&self) -> IpAddr {
        match &self {
            NetworkHeader::Ipv4(ip4h) => IpAddr::V4(Ipv4Addr::from_octets(ip4h.destination)),
            NetworkHeader::Ipv6(ip6h) => IpAddr::V6(Ipv6Addr::from_octets(ip6h.destination)),
        }
    }
}

pub trait TransportHeaderParse {
    fn from_ltransport_data(ltd: &ltransport_data) -> Result<TransportHeader>;
    fn sport(&self) -> u16;
    fn dport(&self) -> u16;
}
impl TransportHeaderParse for TransportHeader {
    fn from_ltransport_data(ltd: &ltransport_data) -> Result<Self> {
        match ltd.transport_type {
            ltranposrt_type::TCP => {
                let tcph = unsafe { &ltd.__anon_ltransport_data_2.tcph };
                let tcph_slice = unsafe {
                    slice::from_raw_parts(
                        tcph as *const tcphdr as *const u8,
                        mem::size_of::<tcphdr>(),
                    )
                };
                let mut tcph_slice = Vec::from_iter(tcph_slice.iter().cloned());

                // Size of tcphdr without options
                tcph_slice[12] = (tcph_slice[12] & 0x0f) + (5 << 4);

                let tcphdr = TcpHeaderSlice::from_slice(&tcph_slice[..])?.to_header();
                Ok(TransportHeader::Tcp(tcphdr))
            }
            ltranposrt_type::UDP => {
                let udph = unsafe { &ltd.__anon_ltransport_data_2.udph };
                let udph_slice = unsafe {
                    slice::from_raw_parts(
                        udph as *const udphdr as *const u8,
                        mem::size_of::<udphdr>(),
                    )
                };
                let udphdr = UdpHeaderSlice::from_slice(udph_slice)?.to_header();
                Ok(TransportHeader::Udp(udphdr))
            }
            _ => Err(anyhow!("TransportHeader parse: invalid ltransport_type")),
        }
    }

    fn sport(&self) -> u16 {
        match &self {
            TransportHeader::Tcp(tcph) => tcph.source_port,
            TransportHeader::Udp(udph) => udph.source_port,
            _ => 0,
        }
    }

    fn dport(&self) -> u16 {
        match &self {
            TransportHeader::Tcp(tcph) => tcph.destination_port,
            TransportHeader::Udp(udph) => udph.destination_port,
            _ => 0,
        }
    }
}

pub struct RawSocket {
    fd_ipv4: OwnedFd,
    fd_ipv6: OwnedFd,
}

impl RawSocket {
    pub fn new(mark: u32) -> Result<Self> {
        let rawsocket_ipv4 = socket(
            AddressFamily::Inet,
            SockType::Raw,
            SockFlag::SOCK_NONBLOCK,
            SockProtocol::Raw,
        )?;
        let rawsocket_ipv6 = socket(
            AddressFamily::Inet6,
            SockType::Raw,
            SockFlag::SOCK_NONBLOCK,
            SockProtocol::Raw,
        )?;

        setsockopt(&rawsocket_ipv4, sockopt::Mark, &mark)?;
        setsockopt(&rawsocket_ipv6, sockopt::Mark, &mark)?;

        Ok(Self {
            fd_ipv4: rawsocket_ipv4,
            fd_ipv6: rawsocket_ipv6,
        })
    }

    pub fn send_ipv4(&self, iph: &Ipv4Header, pkt: &[u8]) -> Result<()> {
        let daddr = SockaddrIn::new(
            iph.destination[0],
            iph.destination[1],
            iph.destination[2],
            iph.destination[3],
            0,
        );

        let t = sendto(
            self.fd_ipv4.as_raw_fd(),
            pkt,
            &daddr,
            MsgFlags::MSG_DONTWAIT,
        )?;
        println!("Sent {t} bytes");

        Ok(())
    }

    pub fn send_ipv6(&self, ip6h: &Ipv6Header, pkt: &[u8]) -> Result<()> {
        let daddr = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as u16,
            /* Always 0 for raw socket */
            sin6_port: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: ip6h.destination,
            },
            sin6_flowinfo: unsafe { mem::zeroed() },
            sin6_scope_id: unsafe { mem::zeroed() },
        };

        let daddr = unsafe {
            SockaddrIn6::from_raw(
                &daddr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                None,
            )
        }
        .ok_or(anyhow!("SockaddrIn6 from_raw"))?;

        sendto(
            self.fd_ipv6.as_raw_fd(),
            pkt,
            &daddr,
            MsgFlags::MSG_DONTWAIT,
        )?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum NetworkActivityType {
    TcpSni,
    TcpSniOverwrite,
    None,
}
#[derive(Debug, Clone)]
pub enum NetworkActivityAction {
    Drop,
    Accept,
}

#[derive(Debug, Clone)]
pub struct NetworkActivityLogData {
    pub saddr: IpAddr,
    pub daddr: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub sni_name: Option<String>,
    pub atype: NetworkActivityType,
    pub action: NetworkActivityAction,
}

pub trait NetworkActivityLogger {
    fn post(&self, data: &NetworkActivityLogData) -> Result<()>;
}

pub struct NActStdoutLogger();

impl NetworkActivityLogger for NActStdoutLogger {
    fn post(&self, data: &NetworkActivityLogData) -> Result<()> {
        println!("{data:?}");
        Ok(())
    }
}
