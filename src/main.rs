#![allow(clippy::let_unit_value)]

use std::cell::Cell;
use std::cell::RefCell;
use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;
use std::os::unix::io::AsFd as _;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;

use libbpf_rs::OpenObject;
use libbpf_rs::XdpFlags;
use tokio::signal;

use clap::Parser;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::TcHook;
use libbpf_rs::Xdp;
use libbpf_rs::TC_EGRESS;

use nix::net::if_::if_nametoindex;

mod ebpf_prog {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/dpit.skel.rs"));
}

#[derive(Debug, Parser)]
struct Command {
    /// interface to attach to
    #[arg(short = 'i', long = "interface")]
    iface: String,
}

fn init_skel<'obj>(open_object: &'obj mut MaybeUninit<OpenObject>) -> Result<ebpf_prog::DpitSkel<'obj>> {
    let builder = ebpf_prog::DpitSkelBuilder::default();
    let open = builder.open(open_object)?;
    let skel = open.load()?;

    Ok(skel)
}

struct TcController<'obj> {
    pub _fd: BorrowedFd<'obj>,
    pub tc_eggress: RefCell<TcHook>,
    created: Cell<bool>,
}

impl<'obj> TcController<'obj> {
    fn new(fd: BorrowedFd<'obj>, iface: &str) -> Result<Self> {
        let ifidx = if_nametoindex(iface)? as i32;

        let mut tc_eggress = TcHook::new(fd.clone());
        tc_eggress
            .ifindex(ifidx)
            .replace(true)
            .handle(1)
            .priority(1)
            .attach_point(TC_EGRESS);

        Ok(Self {
            _fd: fd,
            tc_eggress: RefCell::new(tc_eggress),
            created: Cell::new(false)
        })
    }

    fn create(&self) -> Result<()> {
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

struct XdpController<'obj> {
    pub xdp: Xdp<'obj>,
    ifidx: i32
}

impl<'obj> XdpController<'obj> {
    fn new(fd: BorrowedFd<'obj>, iface: &str) -> Result<Self> {
        let ifidx = if_nametoindex(iface)? as i32;
        let xdp = Xdp::new(fd);

        Ok(Self {
            xdp,
            ifidx
        })
    }

    pub fn attach(&self) -> Result<()> {
        self.xdp.attach(self.ifidx, XdpFlags::NONE).context("Failed to attach xdp")
    }

    pub fn destroy(&mut self) -> Result<()> {
        self.xdp.detach(self.ifidx, XdpFlags::NONE).context("Failed to detach xdp")
    }
}

impl<'obj> Drop for XdpController<'obj> {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Command::parse();

    let mut open_object = MaybeUninit::uninit();
    let skel = init_skel(&mut open_object)?;

    let tc_controller = TcController::new(skel.progs.handle_tc.as_fd(), opts.iface.as_str())?;
    let xdp_prog = XdpController::new(skel.progs.handle_xdp.as_fd(), opts.iface.as_str())?;

    tc_controller.attach()?;
    println!("TC eggress hook started");
    xdp_prog.attach()?;
    println!("XDP hook started");

    println!("Awaiting for Ctrl-C");
    signal::ctrl_c().await?;
    println!("Exiting... Bye!");

    Ok(())
}
