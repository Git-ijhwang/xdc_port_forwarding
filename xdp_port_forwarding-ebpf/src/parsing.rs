use aya_ebpf::binding::{ethhdr, iphdr, udphdr, tcphdr};
use network_types::{eth::EtherType, ip::IpHdr};

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
    pub ip_hdr: *const iphdr,
    pub proto: L4Protocol,
    pub dport: u16,
    pub l4_hdr_start: usize,
}

#[inline(always)]
pub unsafe fn verify_headers(ctx: &aya_ebpf::programs::XdpContext)
-> Result<PacketContext, ()> {
    let eth = ptr_at::<ethhdr>(ctx, 0)?;
    if u16::from_be((*eth).h_proto) != EtherType::Ipv4 as u16 {
        return Err(());
    }

    let ip = ptr_at::<iphdr>(ctx, mem::size_of::<ethhdr>())?;
    let ip_len = ((*ip).ihl() * 4) as usize;
    let l4_offset = mem::size_of::<ethhdr>() + ip_len as usize;

    match (*ip).protocol {
        6 => {
            let tcp = ptr_at::<tcphdr>(ctx, l4_offset);
            return Ok( PacketContext {
                ip_hdr: ip,
                proto: L4Protocol::Tcp,
                dport: u16::from(*tcp).dest,
                l4_hdr_start: l4_offset,
            });
        },
        17 => {
            let udp = ptr_at::<udphdr>(ctx, l4_offset);

            return Ok( PacketContext {
                ip_hdr: ip,
                proto: L4Protocol::Udp,
                dport: u16::from(*udp).dest,
                l4_hdr_start: l4_offset,
            })
        }
        _ => return Err(()),
    }

    Ok (context)
}