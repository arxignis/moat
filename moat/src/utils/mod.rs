pub mod bpf_utils {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::bpf::{self, FilterSkel};

    pub fn bpf_attach_to_xdp(
        skel: &mut FilterSkel<'_>,
        ifindex: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match skel.progs.firewall.attach_xdp(ifindex) {
            Ok(link) => {
                skel.links = bpf::FilterLinks {
                    firewall: Some(link),
                };

                Ok(())
            }
            Err(e) => Err(Box::new(e)),
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
}

pub mod http_utils {}
