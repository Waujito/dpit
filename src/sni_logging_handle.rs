use anyhow::{anyhow, Result};

use std::{mem, thread::JoinHandle, time::Duration};

use libbpf_rs::PerfBufferBuilder;
use crate::ebpf_prog::{self, types::{tls_sni_signaling, chlo_tls_atype}};
use regex::Regex;
use plain::Plain;
use libc;

lazy_static::lazy_static! {
    static ref DOMAIN_REGEX: Regex = 
        Regex::new(r"^[A-Za-z0-9.-]+$").unwrap();
}

unsafe impl Plain for tls_sni_signaling {}

fn sni_tls_get_domain(sni_tls_data: &tls_sni_signaling) -> 
    Result<Option<String>> {
    let sni_type = unsafe { sni_tls_data.sni_type.assume_init() };
    
    if let chlo_tls_atype::SNI_FOUND = sni_type  {
        let sni_data = sni_tls_data.sni_data;
        let sni_buf = &sni_data.data;
        let sni_len = sni_data.prefixlen as usize;

        if sni_len > sni_buf.len() {
            return Err(anyhow!("sni_len is too large")); 
        }

        let sni_buf = &sni_buf[..sni_len as usize];
        let sni_rvbuf: Vec<u8> = sni_buf.iter().rev().cloned().collect();
        let s = std::str::from_utf8(&sni_rvbuf)?;
        if !DOMAIN_REGEX.is_match(s) {
            return Err(anyhow!("domain does not match regex"));
        }

        return Ok(Some(String::from(s)));
    }

    Ok(None)
}

fn process_perf_signal(sni_tls_data: &tls_sni_signaling) -> Result<()> {
    let sni_type = unsafe { sni_tls_data.sni_type.assume_init() };
    let act = unsafe { sni_tls_data.act.assume_init() };

    let domain = sni_tls_get_domain(sni_tls_data)?;

    println!("Type: {:?}, Action: {:?}", sni_type, act); 

    if let Some(domain) = &domain {
        println!("SNI found: {} of len {}", domain, domain.len());
    }

    Ok(())
}

#[derive(Copy, Clone)]
enum RawSocketType {
    AfInet = libc::AF_INET as isize,
    AfInet6 = libc::AF_INET6 as isize
}
struct RawSocket {
    fd: libc::c_int,
    domain_type: RawSocketType
}

impl RawSocket {
    fn new(skel: &ebpf_prog::DpitSkel, domain: RawSocketType) -> Result<Self> {
        let rawsocket = unsafe { 
            libc::socket(domain as libc::c_int, libc::SOCK_RAW, libc::IPPROTO_RAW) 
        };

        if rawsocket == -1 {
            return Err(anyhow!("Open rawsocket"));
        }
        let mark: libc::c_int = skel.maps.rodata_data.RAWSOCKET_MARK as libc::c_int;
        let ret = unsafe { libc::setsockopt(
                rawsocket, libc::SOL_SOCKET, libc::SO_MARK, 
                (&mark) as *const libc::c_int as *const libc::c_void, 
                mem::size_of_val(&mark) as libc::socklen_t
        )};
        if ret < 0 {
            unsafe { libc::close(rawsocket) };
            return Err(anyhow!("setsockopt(SO_MARK, {}) failed", mark));
        }

        Ok(Self {
            fd: rawsocket,
            domain_type: domain
        })
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
        self.fd = 0;
    }
}

pub fn init_sni_logging(skel: &ebpf_prog::DpitSkel) -> Result<JoinHandle<()>> {
    let handle_perf_event = move |_cpu: i32, data: &[u8]| {
        let mut sni_tls_data = tls_sni_signaling::default();
        let res = plain::copy_from_bytes(&mut sni_tls_data, data);
        if let Ok(_) = res {
            if let Err(err) = process_perf_signal(&sni_tls_data) {
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

    let _thread = std::thread::spawn(move || {
        loop {
            if let Err(err) = perf.poll(Duration::from_millis(1000)) {
                println!("Poll error {}", anyhow!(err));
            }
        }
    });

    Ok(_thread)
}
