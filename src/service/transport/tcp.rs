use crate::util::serial::*;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Copy, Clone, AsBytes, FromBytes)]
#[repr(C)]
pub struct IPv4TcpAddress {
    pub options: u32be,
    ipv4_addr: [u8; 4], // Ipv4Addr
    t4_port: u16be,
}

impl IPv4TcpAddress {
    pub fn address(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.ipv4_addr)
    }

    pub fn port(&self) -> u16 {
        self.t4_port.get()
    }
}

impl fmt::Display for IPv4TcpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.address(), self.port())
    }
}

#[derive(Copy, Clone, AsBytes, FromBytes)]
#[repr(C)]
pub struct IPv6TcpAddress {
    pub options: u32be,
    ipv6_addr: [u8; 16], // Ipv6Addr
    t6_port: u16be,
}

impl IPv6TcpAddress {
    pub fn address(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.ipv6_addr)
    }

    pub fn port(&self) -> u16 {
        self.t6_port.get()
    }
}

impl fmt::Display for IPv6TcpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.address(), self.port())
    }
}
