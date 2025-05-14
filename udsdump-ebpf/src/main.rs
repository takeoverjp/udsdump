#![no_std]
#![no_main]

mod binding;

use crate::binding::{sock, socket, unix_sock, unix_address, sockaddr_un, __IncompleteArrayField};

use aya_ebpf::bindings::path;
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes};
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe]
pub fn udsdump(ctx: ProbeContext) -> u32 {
    match unsafe { try_unix_stream_sendmsg(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

#[repr(C)]
struct SockaddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

unsafe fn try_unix_stream_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
    info!(&ctx, "unix_xxx_sendmsg called");

    // Get socket path    
    let sock_: *const u8 = ctx.arg(0).ok_or(1i64)?;
    let sock_ = sock_ as *const socket;
    let sk =
        unsafe { bpf_probe_read_kernel(&(*sock_).sk as *const *mut sock) }? as *const unix_sock;
    let addr = unsafe { bpf_probe_read_kernel(&(*sk).addr as *const *mut unix_address) }?
        as *const unix_address;
    let addr_len =
        unsafe { bpf_probe_read_kernel(&(*addr).len as *const i32) }?;
    info!(&ctx, "sock->sk->addr->len: {}", addr_len);

    if addr_len > 0{
        let addr_path =
        unsafe { bpf_probe_read_kernel(&(*addr).name as *const __IncompleteArrayField<sockaddr_un>) }?;
        let addr_path = addr_path.as_ptr() as *const sockaddr_un;

        let path_ = unsafe { bpf_probe_read_kernel(&(*addr_path).sun_path as *const [::aya_ebpf::cty::c_char; 108usize]) }?;
        let path_ptr = path_.as_ptr() as *const u8;
        let mut buf = [0u8; 108];
        unsafe { bpf_probe_read_kernel_str_bytes(path_ptr, &mut buf)? };
        let path_str = core::str::from_utf8_unchecked(&buf);
        info!(&ctx, "sock->sk->addr->sun_path: {}, {:x}, {:x}, {:x}", path_str, path_[0], path_[1], path_[2]);
    
    }

    // let comm = bpf_get_current_comm().map_err(|_| 2i64)?;
    // let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    // let pid = bpf_get_current_pid_tgid() >> 32;

    // // Get message length
    // let msg_len: u64 = unsafe { ctx.arg(2).ok_or(3i64)? };

    // info!(
    //     &ctx,
    //     "command name: {}, pid: {}, msg_len: {}", comm_str, pid, msg_len
    // );
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
