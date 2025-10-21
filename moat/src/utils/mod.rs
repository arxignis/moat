pub mod bpf_utils {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::AsFd;

    use crate::bpf::{self, FilterSkel};
    use libbpf_rs::{Xdp, XdpFlags};
    use nix::libc;

    pub fn bpf_attach_to_xdp(
        skel: &mut FilterSkel<'_>,
        ifindex: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Try hardware mode first, fall back to driver mode if not supported
        let xdp = Xdp::new(skel.progs.arxignis_xdp_filter.as_fd().into());

        // Try hardware offload mode first
        if let Ok(()) = xdp.attach(ifindex, XdpFlags::HW_MODE) {
            log::info!("XDP program attached in hardware offload mode");
            return Ok(());
        }

        // Fall back to driver mode if hardware mode fails
        match xdp.attach(ifindex, XdpFlags::DRV_MODE) {
            Ok(()) => {
                log::info!("XDP program attached in driver mode");
                Ok(())
            }
            Err(e) => {
                log::debug!("Driver mode failed, trying generic SKB mode: {}", e);
                // Final fallback to SKB mode
                match xdp.attach(ifindex, XdpFlags::SKB_MODE) {
                    Ok(()) => {
                        log::info!("XDP program attached in generic SKB mode");
                        Ok(())
                    }
                    Err(e) => Err(Box::new(e)),
                }
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
        let dummy_fd = unsafe { libc::open("/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDONLY) };
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
}

pub mod http_utils {}
