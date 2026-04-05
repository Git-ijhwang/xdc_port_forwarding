use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, tcp::TcpHdr, udp::UdpHdr};
use core::mem;

pub enum L4Protocol {
    Tcp, Udp
}

#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &aya_ebpf::programs::XdpContext, offset: usize)
    -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset+ len > end {
        return Err(());
    }

    Ok((start+offset) as *const T)
}


pub struct PacketContext {
    pub ip_hdr: *const Ipv4Hdr,
    pub proto: L4Protocol,
    pub dport: u16,
    pub l4_hdr_start: usize,
}

#[inline(always)]
pub unsafe fn verify_headers(ctx: &aya_ebpf::programs::XdpContext)
-> Result<PacketContext, ()> {
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    if u16::from_be((*eth).ether_type) != EtherType::Ipv4 as u16 {
        return Err(());
    }

    let ip = ptr_at::<Ipv4Hdr>(ctx, mem::size_of::<EthHdr>())?;
    // let ip_len = mem::size_of::<Ipv4Hdr>();
    let ip_len = ((*ip).ihl() * 4) as usize;
    let l4_offset = mem::size_of::<EthHdr>() + ip_len as usize;

    match (*ip).proto {
        IpProto::Tcp  => {
            let tcp = ptr_at::<TcpHdr>(ctx, l4_offset)?;
            return Ok( PacketContext {
                ip_hdr: ip,
                proto: L4Protocol::Tcp,
                dport: u16::from_be_bytes(unsafe {(*tcp).dest }),
                l4_hdr_start: l4_offset,
            });
        },

        IpProto::Udp => {
            let udp = ptr_at::<UdpHdr>(ctx, l4_offset)?;

            return Ok( PacketContext {
                ip_hdr: ip,
                proto: L4Protocol::Udp,
                dport: u16::from_be_bytes((*udp).dst),
                l4_hdr_start: l4_offset,
            })
        }
        _ => return Err(()),
    }

    // Ok (context)
}