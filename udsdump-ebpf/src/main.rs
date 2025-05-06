#![no_std]
#![no_main]

use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;
use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user};

#[kprobe]
pub fn udsdump(ctx: ProbeContext) -> u32 {
    match try_udsdump(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_udsdump(ctx: ProbeContext) -> Result<u32, u32> {
    // ソケットのアドレス情報を取得
    let sock: *const u8 = unsafe { ctx.arg(0).ok_or(1u32)? };
    let msg: *const u8 = unsafe { ctx.arg(1).ok_or(1u32)? };

    // ソケットのパス名を取得
    let unix_sock = unsafe { bpf_probe_read_user(sock as *const u8).map_err(|_| 1u32)? };
    let addr = unsafe { bpf_probe_read_user((unix_sock as *const u8).offset(8)).map_err(|_| 1u32)? };
    
    // パス名の長さをチェック
    let addr_len = unsafe { bpf_probe_read_user(addr as *const u32).map_err(|_| 1u32)? };
    if addr_len > 0 {
        let sock_path = unsafe { bpf_probe_read_user((addr as *const u8).offset(16)).map_err(|_| 1u32)? };
        
        // 抽象ソケットの場合は先頭の\0をスキップ
        let path_offset = if sock_path == 0 { 1 } else { 0 };
        // let mut path = [0u8; 108]; // UNIX_PATH_MAX
        // unsafe {
        //     if addr_len > 0 {
        //         let path_ptr = (sock_path as *const u8).offset(path_offset);
        //         let mut i = 0;
        //         while i < 108 && i < addr_len as usize {
        //             if let Ok(byte) = bpf_probe_read_user(path_ptr.add(i) as *const u8) {
        //                 path[i] = byte;
        //                 if byte == 0 {
        //                     break;
        //                 }
        //             } else {
        //                 break;
        //             }
        //             i += 1;
        //         }
        //     }
        // };
        // info!(&ctx, "path: {}", core::str::from_utf8(&path).unwrap_or("invalid utf8"));
    }

    // // ピアのアドレス情報も同様に取得
    // let peer = unsafe { bpf_probe_read_user((unix_sock as *const u8).offset(16)).map_err(|_| 1u32)? };
    // let peer_addr = unsafe { bpf_probe_read_user((peer as *const u8).offset(8)).map_err(|_| 1u32)? };

    // let peer_addr_len = unsafe { bpf_probe_read_user(peer_addr as *const u32).map_err(|_| 1u32)? };
    // if peer_addr_len > 0 {
    //     let peer_sock_path = unsafe { bpf_probe_read_user((peer_addr as *const u8).offset(16)).map_err(|_| 1u32)? };
        
    //     let peer_path_offset = if peer_sock_path == 0 { 1 } else { 0 };
    //     let peer_path = unsafe {
    //         bpf_probe_read_user(
    //             (peer_sock_path as *const u8).offset(peer_path_offset)
    //         ).map_err(|_| 1u32)?
    //     };
    // }

    // // メッセージの内容を取得
    // let msg_iter = unsafe { bpf_probe_read_user((msg as *const u8).offset(32)).map_err(|_| 1u32)? };
    // let iter_type = unsafe { bpf_probe_read_user(msg_iter as *const u32).map_err(|_| 1u32)? };
    // let iov_offset = unsafe { bpf_probe_read_user((msg_iter as *const u8).offset(8)).map_err(|_| 1u32)? };

    // if iter_type == 0 && iov_offset == 0 { // ITER_IOVEC && offset == 0
    //     let nr_segs = unsafe { bpf_probe_read_user((msg_iter as *const u8).offset(16)).map_err(|_| 1u32)? };
    //     let iov = unsafe { bpf_probe_read_user((msg_iter as *const u8).offset(24)).map_err(|_| 1u32)? };

    //     for i in 0..nr_segs.min(8) { // SS_MAX_SEGS_PER_MSG = 8
    //         let iov_base = unsafe { bpf_probe_read_user((iov as *const u8).offset((i * 16) as isize)).map_err(|_| 1u32)? };
    //         let iov_len = unsafe { bpf_probe_read_user((iov as *const u8).offset((i * 16 + 8) as isize)).map_err(|_| 1u32)? };

    //         let data = unsafe {
    //             bpf_probe_read_user(
    //                 iov_base as *const u8
    //             ).map_err(|_| 1u32)?
    //         };
    //     }
    // }
    info!(&ctx, "unix_xxx_sendmsg called");
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    let pid = bpf_get_current_pid_tgid() >> 32;

    // メッセージサイズを取得
    let msg_len: u64 = unsafe { ctx.arg(2).ok_or(1u32)? };

    info!(&ctx, "command name: {}, pid: {}, msg_len: {}", 
          comm_str, pid, msg_len);
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
