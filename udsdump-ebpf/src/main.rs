#![no_std]
#![no_main]

use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid};

#[kprobe]
pub fn udsdump(ctx: ProbeContext) -> u32 {
    match try_udsdump(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_udsdump(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "unix_xxx_sendmsg called");
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    let pid = bpf_get_current_pid_tgid() >> 32;
    info!(&ctx, "command name: {}, pid: {}", comm_str, pid);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
