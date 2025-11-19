use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsFd;
use std::fs;
use std::ffi::CString;

use crate::bpf::{self, FilterSkel};
use libbpf_rs::{Xdp, XdpFlags};
use nix::libc;

fn is_ipv6_disabled() -> bool {
    // Check if IPv6 is disabled system-wide
    if let Ok(content) = fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6") {
        return content.trim() == "1";
    }
    false
}

fn try_enable_ipv6() -> Result<(), Box<dyn std::error::Error>> {
    // Try to enable IPv6 temporarily for XDP attachment
    if is_ipv6_disabled() {
        log::debug!("IPv6 is disabled, attempting to enable it for XDP attachment");
        std::fs::write("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0")?;
        log::info!("Temporarily enabled IPv6 for XDP attachment");
        Ok(())
    } else {
        Ok(())
    }
}

pub fn bpf_attach_to_xdp(
    skel: &mut FilterSkel<'_>,
    ifindex: i32,
) -> Result<(), Box<dyn std::error::Error>> {
    // Try hardware mode first, fall back to driver mode if not supported
    let xdp = Xdp::new(skel.progs.arxignis_xdp_filter.as_fd());

    // Try hardware offload mode first
    if let Ok(()) = xdp.attach(ifindex, XdpFlags::HW_MODE) {
        log::info!("XDP program attached in hardware offload mode");
        return Ok(());
    }

    // Fall back to driver mode if hardware mode fails
    match xdp.attach(ifindex, XdpFlags::DRV_MODE) {
        Ok(()) => {
            log::info!("XDP program attached in driver mode");
            return Ok(());
        }
        Err(e) => {
            // Check if error is EEXIST (error 17) - XDP program already attached
            let error_msg = e.to_string();
            if error_msg.contains("17") || error_msg.contains("File exists") {
                log::debug!("Driver mode failed: XDP program already attached, trying to replace with REPLACE flag");
                // Try to replace existing XDP program
                match xdp.attach(ifindex, XdpFlags::DRV_MODE | XdpFlags::REPLACE) {
                    Ok(()) => {
                        log::info!("XDP program replaced existing program in driver mode");
                        return Ok(());
                    }
                    Err(e2) => {
                        log::debug!("Replace in driver mode failed: {}, trying generic SKB mode", e2);
                    }
                }
            } else {
                log::debug!("Driver mode failed, trying generic SKB mode: {}", e);
            }
        }
    }

    // Try SKB mode (should work on all interfaces, including IPv4-only)
    match xdp.attach(ifindex, XdpFlags::SKB_MODE) {
        Ok(()) => {
            log::info!("XDP program attached in generic SKB mode");
            Ok(())
        }
        Err(e) => {
            // Check if error is EEXIST (error 17) first
            let error_msg = e.to_string();
            if error_msg.contains("17") || error_msg.contains("File exists") {
                log::debug!("SKB mode failed: XDP program already attached, trying to replace");
                // Try to replace existing XDP program in SKB mode
                match xdp.attach(ifindex, XdpFlags::SKB_MODE | XdpFlags::REPLACE) {
                    Ok(()) => {
                        log::info!("XDP program replaced existing program in generic SKB mode");
                        return Ok(());
                    }
                    Err(e2) => {
                        log::debug!("Replace in SKB mode failed: {}, continuing with other fallbacks", e2);
                    }
                }
            }
            // If SKB mode fails with EAFNOSUPPORT (error 97), it's likely due to IPv6 being disabled
            if error_msg.contains("97") || error_msg.contains("Address family not supported") {
                log::debug!("SKB mode failed with EAFNOSUPPORT, IPv6 might be disabled");

                // Try to enable IPv6 and retry attachment
                if try_enable_ipv6().is_ok() {
                    log::debug!("Retrying XDP attachment after enabling IPv6");

                    // Retry SKB mode after enabling IPv6
                    match xdp.attach(ifindex, XdpFlags::SKB_MODE) {
                        Ok(()) => {
                            log::info!("XDP program attached in generic SKB mode (IPv6 re-enabled)");
                            return Ok(());
                        }
                        Err(e2) => {
                            log::debug!("SKB mode still failed after enabling IPv6: {}", e2);
                        }
                    }
                } else {
                    log::debug!("Failed to enable IPv6 or no permission");
                }

                // Try with UPDATE_IF_NOEXIST flag as last resort
                match xdp.attach(ifindex, XdpFlags::SKB_MODE | XdpFlags::UPDATE_IF_NOEXIST) {
                    Ok(()) => {
                        log::info!("XDP program attached in generic SKB mode (with UPDATE_IF_NOEXIST)");
                        return Ok(());
                    }
                    Err(e2) => {
                        log::debug!("SKB mode with UPDATE_IF_NOEXIST also failed: {}", e2);
                    }
                }
            }

            Err(Box::new(e))
        }
    }
}

pub fn ipv4_to_u32_be(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

pub fn convert_ip_into_bpf_map_key_bytes(ip: Ipv4Addr, prefixlen: u32) -> Box<[u8]> {
    let ip_u32: u32 = ip.into();
    let ip_be = ip_u32.to_be();

    let my_ip_key: bpf::types::lpm_key = bpf::types::lpm_key {
        prefixlen,
        addr: ip_be,
    };

    let my_ip_key_bytes = unsafe { plain::as_bytes(&my_ip_key) };
    my_ip_key_bytes.to_vec().into_boxed_slice()
}

pub fn convert_ipv6_into_bpf_map_key_bytes(ip: Ipv6Addr, prefixlen: u32) -> Box<[u8]> {
    let ip_bytes = ip.octets();

    let my_ip_key: bpf::types::lpm_key_v6 = bpf::types::lpm_key_v6 {
        prefixlen,
        addr: ip_bytes,
    };

    let my_ip_key_bytes = unsafe { plain::as_bytes(&my_ip_key) };
    my_ip_key_bytes.to_vec().into_boxed_slice()
}

pub fn bpf_detach_from_xdp(ifindex: i32) -> Result<(), Box<dyn std::error::Error>> {
    // Create a dummy XDP instance for detaching
    // We need to query first to get the existing program ID
    let path = CString::new("/dev/null").expect("CString::new failed");
    let dummy_fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    if dummy_fd < 0 {
        return Err("Failed to create dummy file descriptor".into());
    }

    let xdp = Xdp::new(unsafe { std::os::fd::BorrowedFd::borrow_raw(dummy_fd) });

    // Try to detach using different modes
    let modes = [XdpFlags::HW_MODE, XdpFlags::DRV_MODE, XdpFlags::SKB_MODE];

    for mode in modes {
        if let Ok(()) = xdp.detach(ifindex, mode) {
            log::info!("XDP program detached from interface");
            unsafe { libc::close(dummy_fd); }
            return Ok(());
        }
    }

    unsafe { libc::close(dummy_fd); }
    Err("Failed to detach XDP program from interface".into())
}
