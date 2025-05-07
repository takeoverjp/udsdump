#![no_std]
#![no_main]

use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes};

#[kprobe]
pub fn udsdump(ctx: ProbeContext) -> u32 {
    match unsafe {try_unix_stream_sendmsg(ctx)} {
        Ok(ret) => 0,
        Err(ret) => 1,
    }
}

#[repr(C)]
pub struct Iovec {
    pub iov_base: *mut core::ffi::c_void,
    pub iov_len: usize,
}

#[repr(C)]
pub struct Msghdr {
    pub msg_name: *mut core::ffi::c_void, // 送信先アドレス
    pub msg_namelen: u32,                 // msg_name のサイズ
    pub msg_iov: *mut Iovec,              // データ本体へのポインタ
    pub msg_iovlen: usize,                // iovec の数
    pub msg_control: *mut core::ffi::c_void, // control data (ancillary data)
    pub msg_controllen: usize,
    pub msg_flags: u32,
}

#[repr(C)]
struct SockaddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

unsafe fn try_unix_stream_sendmsg(ctx: ProbeContext) -> Result<(), ()> {
    let msg_ptr: *const u8 = ctx.arg(1).ok_or(())?;
    let msg_ptr = msg_ptr as *const Msghdr;

    // Read msg_name pointer
    let name_ptr: *const SockaddrUn = core::ptr::read(msg_ptr).msg_name as *const SockaddrUn;

    // Read sockaddr_un from user memory
    // let sockaddr: SockaddrUn = bpf_probe_read_user(name_ptr).map_err(|_| ())?;

    // Convert sun_path to str
    // let path_len = sockaddr.sun_path.iter().position(|&c| c == 0).unwrap_or(108);
    // let sun_path = &sockaddr.sun_path[..path_len];

    // info!(&ctx, "sendmsg to {:?}", sun_path);

    info!(&ctx, "unix_xxx_sendmsg called");
    let comm = bpf_get_current_comm().map_err(|_| ())?;
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    let pid = bpf_get_current_pid_tgid() >> 32;

    // メッセージサイズを取得
    let msg_len: u64 = unsafe { ctx.arg(2).ok_or(())? };

    info!(&ctx, "command name: {}, pid: {}, msg_len: {}", 
          comm_str, pid, msg_len);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
