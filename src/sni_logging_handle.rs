use anyhow::{anyhow, Result};
use etherparse::{IpNumber, Ipv4Header, Ipv6Header, TcpHeader, TransportHeader};
use nix::sys::socket::{sendto, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrLike};

use std::{mem, sync::Arc, thread::JoinHandle, time::Duration};

use crate::{
    ebpf_prog::{
        self,
        types::{chlo_tls_atype, sni_action, tls_sni_signaling},
    },
    utils::{NetworkHeader, TransportHeaderParse},
};
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use regex::Regex;

lazy_static::lazy_static! {
    static ref DOMAIN_REGEX: Regex =
        Regex::new(r"^[A-Za-z0-9.-]+$").unwrap();
}

unsafe impl Plain for tls_sni_signaling {}

fn sni_tls_get_domain(sni_tls_data: &tls_sni_signaling) -> Result<Option<String>> {
    let sni_type = sni_tls_data.sni_type;

    if let chlo_tls_atype::SNI_FOUND = sni_type {
        let sni_data = sni_tls_data.sni_data;
        let sni_buf = &sni_data.data;
        let sni_len = sni_data.prefixlen as usize;

        if sni_len > sni_buf.len() {
            return Err(anyhow!("sni_len is too large"));
        }

        let sni_buf = &sni_buf[..sni_len];
        let sni_rvbuf: Vec<u8> = sni_buf.iter().rev().cloned().collect();
        let s = std::str::from_utf8(&sni_rvbuf)?;
        if !DOMAIN_REGEX.is_match(s) {
            return Err(anyhow!("domain does not match regex"));
        }

        return Ok(Some(String::from(s)));
    }

    Ok(None)
}

struct PerfProcessContext {
    ip_rawsocket: RawSocket,
    ip6_rawsocket: RawSocket,
}

fn process_perf_signal(
    sni_tls_data: &tls_sni_signaling,
    ctx: Arc<PerfProcessContext>,
) -> Result<()> {
    let sni_type = sni_tls_data.sni_type;
    let act = sni_tls_data.act;

    let domain = sni_tls_get_domain(sni_tls_data)?;

    println!("Type: {:?}, Action: {:?}", sni_type, act);

    if let Some(domain) = &domain {
        println!("SNI found: {} of len {}", domain, domain.len());
    }

    if act == sni_action::SNI_BLOCK || act == sni_action::SNI_BLOCK_OVERWRITTEN {
        let network_header = NetworkHeader::from_lnetwork_data(&sni_tls_data.lnd)?;
        let transport_header = TransportHeader::from_ltransport_data(&sni_tls_data.ltd)?;

        if let TransportHeader::Tcp(tcph) = &transport_header {
            let _ = send_bi_tcp_rst(&network_header, tcph, ctx.as_ref());
        }
    }

    Ok(())
}

fn send_bi_tcp_rst(
    network_hdr: &NetworkHeader,
    otcph: &TcpHeader,
    ctx: &PerfProcessContext,
) -> Result<()> {
    let mut tcph = TcpHeader::new(
        otcph.source_port,
        otcph.destination_port,
        otcph.sequence_number,
        otcph.window_size,
    );
    tcph.rst = true;
    tcph.acknowledgment_number = otcph.acknowledgment_number;

    if let NetworkHeader::Ipv4(oiph) = network_hdr {
        let mut iph = Ipv4Header::new(
            tcph.header_len_u16(),
            128,
            IpNumber::TCP,
            oiph.source,
            oiph.destination,
        )?;

        iph.header_checksum = iph.calc_header_checksum();
        tcph.checksum = tcph.calc_checksum_ipv4(&iph, &[])?;

        let mut sent_packet = iph.to_bytes().to_vec();
        sent_packet.extend(tcph.to_bytes());

        ctx.ip_rawsocket.send_ipv4(&iph, &sent_packet[..])?;

        iph.destination = iph.source;
        iph.source = oiph.destination;

        tcph.destination_port = tcph.source_port;
        tcph.source_port = otcph.destination_port;

        tcph.sequence_number = tcph.acknowledgment_number;
        tcph.acknowledgment_number = otcph.sequence_number;

        iph.header_checksum = iph.calc_header_checksum();
        tcph.checksum = tcph.calc_checksum_ipv4(&iph, &[])?;

        let mut sent_packet = iph.to_bytes().to_vec();
        sent_packet.extend(tcph.to_bytes());

        ctx.ip_rawsocket.send_ipv4(&iph, &sent_packet[..])?;
    } else if let NetworkHeader::Ipv6(oiph) = network_hdr {
        let mut iph = oiph.clone();
        iph.hop_limit = 128;
        iph.next_header = IpNumber::TCP;
        iph.set_payload_length(tcph.header_len())?;

        tcph.checksum = tcph.calc_checksum_ipv6(&iph, &[])?;

        let mut sent_packet = iph.to_bytes().to_vec();
        sent_packet.extend(tcph.to_bytes());

        ctx.ip6_rawsocket.send_ipv6(&iph, &sent_packet[..])?;

        iph.destination = iph.source;
        iph.source = oiph.destination;

        tcph.destination_port = tcph.source_port;
        tcph.source_port = otcph.destination_port;

        tcph.sequence_number = tcph.acknowledgment_number;
        tcph.acknowledgment_number = otcph.sequence_number;

        tcph.checksum = tcph.calc_checksum_ipv6(&iph, &[])?;

        let mut sent_packet = iph.to_bytes().to_vec();
        sent_packet.extend(tcph.to_bytes());

        ctx.ip6_rawsocket.send_ipv6(&iph, &sent_packet[..])?;
    }

    Ok(())
}

#[derive(Copy, Clone, PartialEq)]
enum RawSocketType {
    AfInet = libc::AF_INET as isize,
    AfInet6 = libc::AF_INET6 as isize,
}
struct RawSocket {
    fd: libc::c_int,
    domain_type: RawSocketType,
}

impl RawSocket {
    pub fn new(skel: &ebpf_prog::DpitSkel, domain: RawSocketType) -> Result<Self> {
        let rawsocket =
            unsafe { libc::socket(domain as libc::c_int, libc::SOCK_RAW, libc::IPPROTO_RAW) };

        if rawsocket == -1 {
            return Err(anyhow!("Open rawsocket"));
        }
        let mark: libc::c_int = skel.maps.rodata_data.unwrap().RAWSOCKET_MARK as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                rawsocket,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&mark) as *const libc::c_int as *const libc::c_void,
                mem::size_of_val(&mark) as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(rawsocket) };
            return Err(anyhow!("setsockopt(SO_MARK, {}) failed", mark));
        }

        Ok(Self {
            fd: rawsocket,
            domain_type: domain,
        })
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }

    pub fn send_ipv4(&self, iph: &Ipv4Header, pkt: &[u8]) -> Result<()> {
        if RawSocketType::AfInet != self.domain_type {
            unreachable!();
        }

        let daddr = SockaddrIn::new(
            iph.destination[0],
            iph.destination[1],
            iph.destination[2],
            iph.destination[3],
            0,
        );

        let t = sendto(self.fd(), pkt, &daddr, MsgFlags::MSG_DONTWAIT)?;
        println!("Sent {t} bytes");

        Ok(())
    }

    pub fn send_ipv6(&self, ip6h: &Ipv6Header, pkt: &[u8]) -> Result<()> {
        if RawSocketType::AfInet6 != self.domain_type {
            unreachable!();
        }

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

        sendto(self.fd(), pkt, &daddr, MsgFlags::MSG_DONTWAIT)?;

        Ok(())
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
        self.fd = 0;
    }
}

pub fn init_sni_logging(skel: &ebpf_prog::DpitSkel) -> Result<JoinHandle<()>> {
    let ip_rawsocket = RawSocket::new(skel, RawSocketType::AfInet)?;
    let ip6_rawsocket = RawSocket::new(skel, RawSocketType::AfInet6)?;
    let perf_ctx = Arc::new(PerfProcessContext { ip_rawsocket, ip6_rawsocket });

    let handle_perf_event = move |_cpu: i32, data: &[u8]| {
        let mut sni_tls_data = tls_sni_signaling::default();
        let res = plain::copy_from_bytes(&mut sni_tls_data, data);
        if res.is_ok() {
            let perf_cl = perf_ctx.clone();
            if let Err(err) = process_perf_signal(&sni_tls_data, perf_cl) {
                eprintln!("handle_event error: {}", anyhow!(err));
            }
        } else {
            eprintln!("Data buffer was too short");
        }
    };

    let handle_perf_lost_event = |cpu: i32, count: u64| {
        eprintln!("Lost {count} events on CPU {cpu}");
    };

    let perf = PerfBufferBuilder::new(&skel.maps.tls_sni_signaling_map)
        .sample_cb(handle_perf_event)
        .lost_cb(handle_perf_lost_event)
        .build()?;

    let _thread = std::thread::spawn(move || loop {
        if let Err(err) = perf.poll(Duration::from_millis(1000)) {
            println!("Poll error {}", anyhow!(err));
        }
    });

    Ok(_thread)
}
