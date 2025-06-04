#![feature(ip_from)]

pub mod utils;
pub mod ebpf_prog {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/dpit.skel.rs"));
}
pub mod sni_logging_handle;

use anyhow::{anyhow, Context, Result};
use ebpf_prog::{types::sni_action, DpitSkel};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags, OpenObject, TcHook, Xdp, XdpFlags, TC_EGRESS,
};
use nix::net::if_::if_nametoindex;
use std::{
    cell::{Cell, RefCell},
    mem::{self, MaybeUninit},
    os::fd::BorrowedFd,
};

pub trait DpitSkelLib {
    fn sni_lpm_add_entry(&self, domain: &str, action: sni_action) -> Result<()>;
}

impl<'obj> DpitSkelLib for DpitSkel<'obj> {
    /// Adds SNI LPM entry to the TRIE map.
    /// For more detailed description see sni_lpm_map definition in eBPF code.
    /// Note, that Point-terminator is specified explicitly by user if needed.
    ///
    /// This function also implicitly reverses the destination string,
    /// so user should pass the domain normally, like `.google.com`
    fn sni_lpm_add_entry(&self, domain: &str, action: sni_action) -> Result<()> {
        if domain.len() != domain.len() {
            return Err(anyhow!(
                "The domain MUST NOT contain Unicode. Use normal form, in ASCII"
            ));
        }

        let mut ks = ebpf_prog::types::sni_buf::default();
        let srev: String = domain.chars().rev().collect::<String>();
        let bytes_string = srev.as_bytes();
        // One for NULL-terminator and point-terminator
        if bytes_string.len() > ks.data.len() + 2 {
            return Err(anyhow!("Map SNI string length exceeds the limit."));
        };
        for (i, c) in bytes_string.iter().enumerate() {
            ks.data[i] = *c;
        }
        // NULL-terminator
        ks.data[bytes_string.len()] = b'\0';

        ks.prefixlen = bytes_string.len() as u32 * 8;

        let key = &ks as *const ebpf_prog::types::sni_buf as *const u8;
        let size = mem::size_of::<ebpf_prog::types::sni_buf>();
        let key = unsafe { std::slice::from_raw_parts(key, size) };

        let value = &action as *const ebpf_prog::types::sni_action as *const u8;
        let size = mem::size_of::<ebpf_prog::types::sni_action>();
        let value = unsafe { std::slice::from_raw_parts(value, size) };
        self.maps
            .sni_lpm_map
            .update(key, value, MapFlags::ANY)
            .context("Error while updating the trie map")?;

        Ok(())
    }
}

pub fn init_skel<'obj>(
    open_object: &'obj mut MaybeUninit<OpenObject>,
) -> Result<ebpf_prog::DpitSkel<'obj>> {
    let builder = ebpf_prog::DpitSkelBuilder::default();
    let open = builder.open(open_object)?;
    let skel = open.load()?;

    Ok(skel)
}

pub struct TcController<'obj> {
    pub _fd: BorrowedFd<'obj>,
    pub tc_eggress: RefCell<TcHook>,
    created: Cell<bool>,
}

impl<'obj> TcController<'obj> {
    pub fn new(fd: BorrowedFd<'obj>, iface: &str) -> Result<Self> {
        let ifidx = if_nametoindex(iface)? as i32;

        let mut tc_eggress = TcHook::new(fd);
        tc_eggress
            .ifindex(ifidx)
            .replace(true)
            .handle(1)
            .priority(1)
            .attach_point(TC_EGRESS);

        Ok(Self {
            _fd: fd,
            tc_eggress: RefCell::new(tc_eggress),
            created: Cell::new(false),
        })
    }

    pub fn create(&self) -> Result<()> {
        if let Err(err) = self.tc_eggress.borrow_mut().create() {
            eprintln!("Failed to create eggress hook: {err}");
            eprintln!("Attempting to destroy the eggress hook");

            self.created.set(true);
            let _ = self.tc_eggress.borrow_mut().destroy();

            return Err(anyhow!(err));
        }

        self.created.set(true);

        Ok(())
    }

    pub fn attach(&self) -> Result<()> {
        if !self.created.get() {
            self.create()?;
        }

        if let Err(err) = self.tc_eggress.borrow_mut().attach() {
            eprintln!("Failed to attach egress hook {err}");
            return Err(anyhow!(err));
        }

        Ok(())
    }

    pub fn destroy(&self) {
        if !self.created.get() {
            return;
        }

        if let Err(e) = self.tc_eggress.borrow_mut().detach() {
            println!("Failed to detach egress hook {e}");
        }

        if let Err(e) = self.tc_eggress.borrow_mut().destroy() {
            println!("Failed to destroy eggress hook {e}");
        }

        self.created.set(false);
    }
}

impl<'obj> Drop for TcController<'obj> {
    fn drop(&mut self) {
        self.destroy();
    }
}

pub struct XdpController<'obj> {
    pub xdp: Xdp<'obj>,
    ifidx: i32,
}

impl<'obj> XdpController<'obj> {
    pub fn new(fd: BorrowedFd<'obj>, iface: &str) -> Result<Self> {
        let ifidx = if_nametoindex(iface)? as i32;
        let xdp = Xdp::new(fd);

        Ok(Self { xdp, ifidx })
    }

    pub fn attach(&self) -> Result<()> {
        self.xdp
            .attach(self.ifidx, XdpFlags::NONE)
            .context("Failed to attach xdp")
    }

    pub fn destroy(&mut self) -> Result<()> {
        self.xdp
            .detach(self.ifidx, XdpFlags::NONE)
            .context("Failed to detach xdp")
    }
}

impl<'obj> Drop for XdpController<'obj> {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}
