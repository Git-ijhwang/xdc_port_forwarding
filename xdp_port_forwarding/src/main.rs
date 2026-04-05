use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
mod tui;

use std::sync::Arc;
use xdp_port_forwarding_common::{ForwardRule, InterfaceState};
use aya::maps::{HashMap, PerCpuHashMap};
use aya::maps::perf::{AsyncPerfEventArray, Events};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use bytes::BytesMut;
use std::hash::Hash;
use std::io::{stdin, stdout, BufRead };
// use std::time::Duration;
use std::{net::Ipv4Addr, os::linux::raw::stat};
use tokio::time::{self, Duration};
// use tokio::io::{self, AsyncBufReadExt, BufReader};
use aya::maps::MapData; // 상단에 추가
// use tokio::io::{stdin, BufReader};
use tokio::io::{self, AsyncBufReadExt, BufReader};
use crossterm::{event::{self, Event, KeyCode},
    terminal::{
        disable_raw_mode,
        enable_raw_mode,
        LeaveAlternateScreen,
        EnterAlternateScreen
    }
};
use ratatui::{Terminal, backend::CrosstermBackend};

// use tokio::io::Stdout;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp3s0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(
        // concat!( env!("OUT_DIR"), "/xdp_port_forwarding")
        "../../target/bpfel-unknown-none/release/xdp_port_forwarding"
    ))?;
    // match aya_log::EbpfLogger::init(&mut ebpf) {
    //     Err(e) => {
    //         // This can happen if you remove all log statements from your eBPF program.
    //         warn!("failed to initialize eBPF logger: {e}");
    //     }
    //     Ok(logger) => {
    //         let mut logger =
    //             tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
    //         tokio::task::spawn(async move {
    //             loop {
    //                 let mut guard = logger.readable_mut().await.unwrap();
    //                 guard.get_inner_mut().flush();
    //                 guard.clear_ready();
    //             }
    //         });
    //     }
    // }
    aya_log::EbpfLogger::init(&mut ebpf).context("failed to initialize eBPF logger")?;

    let Opt { ref iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("xdp_port_forwarding").unwrap().try_into()?;
    program.load()?;
    // program.attach(&iface, XdpFlags::default()).context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    program.attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach XDP program")?;

    //Test code start
    {
        let mut rules: HashMap<_, u16, ForwardRule> = HashMap::try_from(ebpf.map_mut("RULES").unwrap())?;
        let test_rule = ForwardRule {
            target_ip: [192, 168, 1, 100],
            target_port: 9000,
            action: 1,
            packets: 0,
            bytes: 0,
        };
        let _ = rules.insert(8080, test_rule, 0);
    }

    // let program: &mut Xdp = ebpf.program_mut("xdp_port_forwarding").expect("???").try_into()?;
    // program.load()?;

    // let interface = "wlp3s0";
    // program.attach(interface, XdpFlags::default())
    //     .expect(&format!("failed to attache to {}", interface));
    // println!("start");
    //Test code end

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;


        let iface_stats_map: HashMap<_, u32, InterfaceState> = HashMap::try_from(ebpf.map("IFACE_STATS").unwrap())?;
        let rules_map: HashMap<_, u16, ForwardRule> = HashMap::try_from(ebpf.map("RULES").unwrap())?;

    loop {
        let if_vec: Vec<(u32, InterfaceState)> = iface_stats_map.iter().filter_map(|r| r.ok()).collect();
        let rule_vec: Vec<(u16, ForwardRule)> = rules_map.iter().filter_map(|r| r.ok()).collect();

        tui::render_ui(&mut terminal, &if_vec, &rule_vec)?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {

                    disable_raw_mode()?;
                    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
                    break;
                }
            }
        }
    }


    // let ctrl_c = signal::ctrl_c();
    // println!("Waiting for Ctrl-C...");
    // ctrl_c.await?;
    // println!("Exiting...");

    crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen)?;
    Ok(())
}
