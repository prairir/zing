#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
};

const ICMP_PING_TYPE: u8 = 08;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp(name = "zing")]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] //
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    match unsafe { (*ipv4hdr).proto } {
        IpProto::Icmp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let icmphdr: *mut IcmpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let icmp_type = match u8::from_be(unsafe { (*icmphdr).type_ }) {
        ICMP_PING_TYPE => 08,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    info!(
        &ctx,
        "SRC IP: {:ipv4}, DST IP: {:ipv4}, ICMP type: {}", source_addr, dest_addr, icmp_type
    );

    let src_mac = unsafe { (*ethhdr).src_addr.clone() };

    unsafe { (*ethhdr).src_addr = (*ethhdr).dst_addr }

    unsafe { (*ethhdr).dst_addr = src_mac }

    unsafe {
        (*ipv4hdr).src_addr = (*ipv4hdr).dst_addr;
    }

    unsafe {
        (*ipv4hdr).dst_addr = u32::to_be(source_addr);
    }

    unsafe {
        (*icmphdr).type_ = 0;
    }

    // recompute checksum by literally just undoing the compliment,
    // subtracting the type change(8), and recomplimenting it
    unsafe {
        let mut check = !(*icmphdr).checksum;

        check -= ICMP_PING_TYPE;

        (*icmphdr).checksum = !(check as u16);
    }

    Ok(xdp_action::XDP_TX)
}
