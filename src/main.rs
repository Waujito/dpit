#![allow(clippy::let_unit_value)]

use std::mem::MaybeUninit;
use std::os::unix::io::AsFd as _;

use anyhow::{Context, Result};

use ebpf_dpit::{
    ebpf_prog, init_skel,
    postgres_logger::NActPostgresLogger,
    sni_logging_handle::{self, SniLoggingCtx},
    DpitSkelLib, TcController, XdpController,
};

use ebpf_prog::types::sni_action;
use sni_logging_handle::init_sni_logging;
use tokio::signal;

use clap::Parser;

#[derive(Debug, Parser)]
struct Command {
    /// interface to attach to
    #[arg(short = 'i', long = "interface")]
    iface: String,

    /// List of domains to block.
    /// Pass the domains in either normal or point-prefixed form.
    /// The mapping is performed by suffix. If the specified domain matches
    /// the suffix of SNI domain, it will be triggered. Pass point-terminator
    /// if you want to escape miss-matching (like `google.com` will be matched to
    /// `gle.com` by default. If you pass .gle.com, it will map only `*.gle.com`
    /// `gle.com` including)
    #[arg(default_value = "", short = 'd', long = "block-domains")]
    block_domains: String,

    /// Postgresql logger connection URI
    /// The table network_acitivity with following types is created
    /// on the first run by default.
    #[arg(long = "postgres")]
    postgres_connstring: Option<String>,

    /// Same as --postgres, but reads connection string from POSTGRES_URI environment variable
    #[arg(long = "postgres_env")]
    postgres_toggler: bool,

    /// Disable xdp
    #[arg(long="no-xdp")]
    no_xdp: bool,

    /// Disable tc
    #[arg(long="no-tc")]
    no_tc: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Command::parse();

    let mut open_object = MaybeUninit::uninit();
    let skel = init_skel(&mut open_object)?;

    let mut ifaces = Vec::<String>::new();
    for iface in opts.iface.split(',') {
        if iface.is_empty() {
            continue;
        }

        ifaces.push(String::from(iface));
    }

    let mut postgres_connstring = opts.postgres_connstring;
    if opts.postgres_toggler {
        let postgres_uri = std::env::var("POSTGRES_URI").context("POSTGRES_URI env")?;
        postgres_connstring = Some(postgres_uri);
    }

    let postgres = if let Some(postgres_connstring) = postgres_connstring {
        let postgres_logger = tokio::task::spawn_blocking(move || -> Result<NActPostgresLogger> {
            let pgs = NActPostgresLogger::new(postgres_connstring.as_ref())?;
            pgs.init_database_tables()?;

            Ok(pgs)
        })
        .await??;

        Some(postgres_logger)
    } else {
        None
    };

    let tc_controllers: Vec<(Result<TcController>, String)> = ifaces
        .iter()
        .map(|iface| {
            (
                TcController::new(skel.progs.handle_tc.as_fd(), iface.as_str()),
                iface.clone(),
            )
        })
        .collect();

    let xdp_progs: Vec<(Result<XdpController>, String)> = ifaces
        .iter()
        .map(|iface| {
            (
                XdpController::new(skel.progs.handle_xdp.as_fd(), iface.as_str()),
                iface.clone(),
            )
        })
        .collect();

    for domain in opts.block_domains.split(',') {
        if domain.is_empty() {
            continue;
        }

        println!("Register blocking domain {domain}");

        skel.sni_lpm_add_entry(domain, sni_action::SNI_BLOCK)?;
    }

    if !opts.no_tc {
        for tc_controller in &tc_controllers {
            let tcc = tc_controller.0.as_ref().unwrap();
            let tc_iface = &tc_controller.1;

            println!("Attaching TC hook to {tc_iface}");
            tcc.attach()?;
        }
    }
    if !opts.no_xdp {
        for xdp_prog in &xdp_progs {
            let xdpp = xdp_prog.0.as_ref().unwrap();
            let xdp_iface = &xdp_prog.1;

            println!("Attaching XDP hook to {xdp_iface}");
            xdpp.attach()?;
        }
    }

    let _logging_thr = init_sni_logging(SniLoggingCtx {
        skel: &skel,
        postgres_logger: postgres,
    })
    .context("Init SNI logging")?;

    println!("Awaiting for Ctrl-C");
    signal::ctrl_c().await?;
    println!("Exiting... Bye!");

    Ok(())
}
