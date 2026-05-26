use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{TcHookBuilder, TC_EGRESS};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[path = "../bpf/aidt.skel.rs"]
mod aidt;
mod proc;
mod events;

use aidt::*;

#[derive(Parser)]
struct Opts {
    /// Enable verbose logging (debug mode)
    #[arg(short, long)]
    verbose: bool,

    /// Interface to attach TC egress hook to
    #[arg(short, long)]
    iface: String,
}

fn setup_logging(verbose: bool) -> Result<()> {
    let level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    let base_config = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(level);

    let stdout_config = fern::Dispatch::new()
        .chain(std::io::stdout());

    let file_config = fern::Dispatch::new()
        .chain(fern::log_file("aidet.log")?);

    base_config
        .chain(stdout_config)
        .chain(file_config)
        .apply()?;

    Ok(())
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    setup_logging(opts.verbose)?;

    log::info!("Starting ai-detector...");

    let skel_builder = AidtSkelBuilder::default();
    let mut open_obj = std::mem::MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_obj)?;
    let mut skel = open_skel.load()?;

    log::info!("Attaching BPF hooks...");
    skel.attach()?;


    let ifindex = unsafe {
        let ifname = std::ffi::CString::new(opts.iface.clone())?;
        libc::if_nametoindex(ifname.as_ptr())
    };

    if ifindex == 0 {
        bail!("Failed to find interface: {}", opts.iface);
    }

    log::info!("Attaching TC egress hook to {}, ifindex: {}", opts.iface, ifindex);
    let mut tc_builder = TcHookBuilder::new(skel.progs.aidt_sni_egress.as_fd());
    tc_builder
        .ifindex(ifindex as i32)
        .replace(true)
        .handle(1)
        .priority(1);

    let mut tc_hook = tc_builder.hook(TC_EGRESS);
    tc_hook.create()?;
    tc_hook.attach()?;

    log::info!("open rb_events ring buffer...");
    let mut rb_builder = libbpf_rs::RingBufferBuilder::new();
    rb_builder.add(&skel.maps.rb_events, events::handle_event)?;
    let rb = rb_builder.build()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    log::info!("Waiting for events (Ctrl+C to stop)...");
    while running.load(Ordering::SeqCst) && rb.poll(std::time::Duration::from_millis(100)).is_ok() {}

    log::info!("Shutting down...");

    log::info!("Detaching and unloading BPF program...");
    let _ = tc_hook.detach();
    let _ = tc_hook.destroy();

    log::info!("Exiting..");
    Ok(())
}
