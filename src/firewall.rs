use std::{error::Error, net::{Ipv4Addr, Ipv6Addr}};

use libbpf_rs::{MapCore, MapFlags};

use crate::utils::bpf_utils;

pub trait Firewall {
    fn ban_ip_with_notice(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn ban_ip(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn unban_ip(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn check_if_notice(&mut self, ip: Ipv4Addr) -> Result<bool, Box<dyn Error>>;

    // IPv6 methods
    fn ban_ipv6_with_notice(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn ban_ipv6(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn unban_ipv6(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn check_if_notice_ipv6(&mut self, ip: Ipv6Addr) -> Result<bool, Box<dyn Error>>;
}

pub struct MOATFirewall<'a> {
    skel: &'a crate::bpf::FilterSkel<'a>,
}

impl<'a> MOATFirewall<'a> {
    pub fn new(skel: &'a crate::bpf::FilterSkel<'a>) -> Self {
        Self { skel }
    }
}

impl<'a> Firewall for MOATFirewall<'a> {
    fn ban_ip_with_notice(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, prefixlen);
        let flag = 1_u8;

        self.skel
            .maps
            .recently_banned_ips
            .update(ip_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        Ok(())
    }

    fn ban_ip(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, prefixlen);
        let flag = 1_u8;

        self.skel
            .maps
            .banned_ips
            .update(ip_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        Ok(())
    }

    fn check_if_notice(&mut self, ip: Ipv4Addr) -> Result<bool, Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, 32);

        if let Some(val) = self
            .skel
            .maps
            .recently_banned_ips
            .lookup(ip_bytes, MapFlags::ANY)?
        {
            if val[0] == 1_u8 {
                return Ok(true);
            } else {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn unban_ip(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, prefixlen);

        self.skel.maps.banned_ips.delete(ip_bytes)?;

        Ok(())
    }

    // IPv6 implementations
    fn ban_ipv6_with_notice(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ipv6_into_bpf_map_key_bytes(ip, prefixlen);
        let flag = 1_u8;

        self.skel
            .maps
            .recently_banned_ips_v6
            .update(ip_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        Ok(())
    }

    fn ban_ipv6(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ipv6_into_bpf_map_key_bytes(ip, prefixlen);
        let flag = 1_u8;

        self.skel
            .maps
            .banned_ips_v6
            .update(ip_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        Ok(())
    }

    fn check_if_notice_ipv6(&mut self, ip: Ipv6Addr) -> Result<bool, Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ipv6_into_bpf_map_key_bytes(ip, 128);

        if let Some(val) = self
            .skel
            .maps
            .recently_banned_ips_v6
            .lookup(ip_bytes, MapFlags::ANY)?
        {
            if val[0] == 1_u8 {
                return Ok(true);
            } else {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn unban_ipv6(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ipv6_into_bpf_map_key_bytes(ip, prefixlen);

        self.skel.maps.banned_ips_v6.delete(ip_bytes)?;

        Ok(())
    }
}
