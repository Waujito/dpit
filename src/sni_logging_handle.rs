use anyhow::{anyhow, Result};
use etherparse::{IpNumber, Ipv4Header, TcpHeader, TransportHeader};

use std::{
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Duration,
};

use crate::{
    ebpf_prog::{
        self,
        types::{chlo_tls_atype, dpit_action_type, tls_sni_signaling},
    },
    postgres_logger::NActPostgresLogger,
    utils::{
        NActStdoutLogger, NetworkActivityAction, NetworkActivityLogData, NetworkActivityLogger,
        NetworkActivityType, NetworkHeader, RawSocket, TransportHeaderParse,
    },
};
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use regex::Regex;

lazy_static::lazy_static! {
    static ref DOMAIN_REGEX: Regex =
        Regex::new(r"^[A-Za-z0-9.-]+$").unwrap();
}

pub struct SniLoggingCtx<'a> {
    pub skel: &'a ebpf_prog::DpitSkel<'a>,
    pub postgres_logger: Option<NActPostgresLogger>,
}

struct PerfProcessContext {
    rawsocket: Mutex<RawSocket>,
    loggers: Vec<Mutex<Box<dyn NetworkActivityLogger>>>,
}

unsafe impl Send for PerfProcessContext {}
unsafe impl Sync for PerfProcessContext {}

pub fn init_sni_logging(ctx: SniLoggingCtx) -> Result<JoinHandle<()>> {
    let skel = ctx.skel;

    let rawsocket = RawSocket::new(skel.maps.rodata_data.unwrap().RAWSOCKET_MARK)?;
    let stdout_logger: Box<dyn NetworkActivityLogger> = Box::new(NActStdoutLogger {});

    let mut perf_ctx = PerfProcessContext {
        rawsocket: Mutex::new(rawsocket),
        loggers: vec![Mutex::new(stdout_logger)],
    };

    if let Some(pgs) = ctx.postgres_logger {
        perf_ctx.loggers.push(Mutex::new(Box::new(pgs)));
    }

    let perf_ctx = Arc::new(perf_ctx);

    let handle_perf_event = move |_cpu: i32, data: &[u8]| {
        let mut sni_tls_data = tls_sni_signaling::default();
        let res = plain::copy_from_bytes(&mut sni_tls_data, data);

        if res.is_ok() {
            if let Err(err) = process_perf_signal(&sni_tls_data, perf_ctx.as_ref()) {
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

fn process_perf_signal(sni_tls_data: &tls_sni_signaling, ctx: &PerfProcessContext) -> Result<()> {
    let sni_type = sni_tls_data.sni_type;
    let act = sni_tls_data.act;
    let network_header = NetworkHeader::from_lnetwork_data(&sni_tls_data.lnd)?;
    let transport_header = TransportHeader::from_ltransport_data(&sni_tls_data.ltd)?;
    let domain = sni_tls_get_domain(sni_tls_data)?;

    let log_data = NetworkActivityLogData {
        saddr: network_header.saddr(),
        daddr: network_header.daddr(),
        sport: transport_header.sport(),
        dport: transport_header.dport(),
        sni_name: domain.clone(),
        atype: if sni_type == chlo_tls_atype::SNI_FOUND {
            NetworkActivityType::TcpSni
        } else if act.r#type == dpit_action_type::DPIT_ACT_BLOCK_OVERWRITTEN {
            NetworkActivityType::TcpSniOverwrite
        } else {
            NetworkActivityType::None
        },
        action: match act.r#type {
            dpit_action_type::DPIT_ACT_BLOCK | dpit_action_type::DPIT_ACT_BLOCK_OVERWRITTEN => {
                NetworkActivityAction::Drop
            }
            dpit_action_type::DPIT_ACT_APPROVE => NetworkActivityAction::Accept,
            _ => NetworkActivityAction::Accept,
        },
    };

    if act.r#type == dpit_action_type::DPIT_ACT_BLOCK
        || act.r#type == dpit_action_type::DPIT_ACT_BLOCK_OVERWRITTEN
    {
        if let TransportHeader::Tcp(tcph) = &transport_header {
            let _ = send_bi_tcp_rst(&network_header, tcph, ctx);
        }
    }

    for logger in &ctx.loggers {
        logger.lock().unwrap().post(&log_data)?;
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
    let rawsocket = ctx.rawsocket.lock().unwrap();

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

        rawsocket.send_ipv4(&iph, &sent_packet[..])?;

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

        rawsocket.send_ipv4(&iph, &sent_packet[..])?;
    } else if let NetworkHeader::Ipv6(oiph) = network_hdr {
        let mut iph = oiph.clone();
        iph.hop_limit = 128;
        iph.next_header = IpNumber::TCP;
        iph.set_payload_length(tcph.header_len())?;

        tcph.checksum = tcph.calc_checksum_ipv6(&iph, &[])?;

        let mut sent_packet = iph.to_bytes().to_vec();
        sent_packet.extend(tcph.to_bytes());

        rawsocket.send_ipv6(&iph, &sent_packet[..])?;

        iph.destination = iph.source;
        iph.source = oiph.destination;

        tcph.destination_port = tcph.source_port;
        tcph.source_port = otcph.destination_port;

        tcph.sequence_number = tcph.acknowledgment_number;
        tcph.acknowledgment_number = otcph.sequence_number;

        tcph.checksum = tcph.calc_checksum_ipv6(&iph, &[])?;

        let mut sent_packet = iph.to_bytes().to_vec();
        sent_packet.extend(tcph.to_bytes());

        rawsocket.send_ipv6(&iph, &sent_packet[..])?;
    }

    Ok(())
}
