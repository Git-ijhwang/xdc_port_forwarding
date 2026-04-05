#![no_std]
#![no_main]

mod parsing;
use aya_ebpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    programs::XdpContext,
    maps::HashMap,
};
use crate::parsing::{L4Protocol, verify_headers};
use xdp_port_forwarding_common::{ForwardRule, InterfaceState};

use aya_log_ebpf::info;
use core::mem;
use network_types:: {
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    udp::UdpHdr,
    tcp::TcpHdr,
};

#[map]
static RULES: HashMap<u16, ForwardRule> = HashMap::with_max_entries(1024, 0);

#[map]
static IFACE_STATS: HashMap<u32, InterfaceState> = HashMap::with_max_entries(16, 0);

#[xdp]
pub fn xdp_port_forwarding(ctx: XdpContext) -> u32 {
    match try_xdp_port_forwarding(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_xdp_port_forwarding(ctx: XdpContext) -> Result<u32, ()> {

    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex};
    let len = (ctx.data_end() - ctx.data()) as u64;

    // Interface stats update
    let stat_ptr = IFACE_STATS.get_ptr_mut(&ifindex).ok_or(())?;

    unsafe {
        (*stat_ptr).rx_packets += 1;
        (*stat_ptr).rx_bytes += len;
    }

    let packet = unsafe { verify_headers(&ctx)? };

    let rule_ptr = RULES.get_ptr_mut(&packet.dport).ok_or(())?;
    unsafe {
        if (*rule_ptr).action == 1 {
            (*rule_ptr).packets += 1;
            (*rule_ptr).bytes += len;

            match packet.proto {
                L4Protocol::Tcp => {
                },
                L4Protocol::Udp => {
                },
            }
        }
        return Ok(xdp_action::XDP_PASS);
    }
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
