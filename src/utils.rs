use anyhow::{anyhow, Result};
use etherparse::{
    Ipv4Header, Ipv4HeaderSlice, Ipv6Header, Ipv6HeaderSlice, TcpHeaderSlice, TransportHeader,
    UdpHeaderSlice,
};

use std::{mem, slice};

use crate::ebpf_prog::types::{
    iphdr, ipv6hdr, lnetwork_data, lnetwork_type, ltranposrt_type, ltransport_data, tcphdr, udphdr,
};
use regex::Regex;

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
}

pub trait TransportHeaderParse {
    fn from_ltransport_data(ltd: &ltransport_data) -> Result<TransportHeader>;
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
}
