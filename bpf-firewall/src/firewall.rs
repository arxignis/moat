use std::{error::Error, net::Ipv4Addr};

use libbpf_rs::{MapCore, MapFlags, MapImpl};

use crate::utils;

pub trait Firewall {
    fn ban_ip_with_notice(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;

    fn ban_ip(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;

    fn unban_ip(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;

    fn check_if_notice(&mut self, ip: Ipv4Addr) -> Result<bool, Box<dyn Error>>;
}

#[derive(Debug)]
pub struct MOATFirewall<'a> {
    recently_banned_ips_bpf_map: &'a mut MapImpl<'a>,
    banned_ips_bpf_map: &'a mut MapImpl<'a>,
}

impl<'a> MOATFirewall<'a> {
    pub fn new(
        recently_banned_ips_bpf_map: &'a mut MapImpl<'a>,
        banned_ips_bpf_map: &'a mut MapImpl<'a>,
    ) -> Self {
        Self {
            recently_banned_ips_bpf_map,
            banned_ips_bpf_map,
        }
    }
}

impl<'a> Firewall for MOATFirewall<'a> {
    fn ban_ip_with_notice(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &utils::bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, prefixlen);
        let flag = 1_u8;

        self.recently_banned_ips_bpf_map
            .update(ip_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        Ok(())
    }

    fn ban_ip(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &utils::bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, prefixlen);
        let flag = 1_u8;

        self.banned_ips_bpf_map
            .update(ip_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        Ok(())
    }

    fn check_if_notice(&mut self, ip: Ipv4Addr) -> Result<bool, Box<dyn Error>> {
        let ip_bytes = &utils::bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, 32);

        if let Some(val) = self
            .recently_banned_ips_bpf_map
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
        let ip_bytes = &utils::bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, prefixlen);

        self.banned_ips_bpf_map.delete(ip_bytes)?;

        Ok(())
    }
}
