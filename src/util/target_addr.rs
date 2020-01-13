use crate::read_exact;
use crate::consts;
use anyhow::Context;
use async_std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use futures::{AsyncRead, AsyncReadExt};
use std::io;
use thiserror::Error;

/// SOCKS5 reply code
#[derive(Error, Debug)]
pub enum AddrError {
    #[error("DNS Resolution failed")]
    DNSResolutionFailed,
    #[error("Can't read IPv4")]
    IPv4Unreadable,
    #[error("Can't read IPv6")]
    IPv6Unreadable,
    #[error("Can't read port number")]
    PortNumberUnreadable,
    #[error("Can't read domain len")]
    DomainLenUnreadable,
    #[error("Can't read Domain content")]
    DomainContentUnreadable,
    #[error("Malformed UTF-8")]
    Utf8,
    #[error("Unknown address type")]
    IncorrectAddressType,
    #[error("{0}")]
    Custom(String),
}

/// A description of a connection target.
#[derive(Debug, Clone)]
pub enum TargetAddr {
    /// Connect to an IP address.
    Ip(SocketAddr),
    /// Connect to a fully qualified domain name.
    ///
    /// The domain name will be passed along to the proxy server and DNS lookup
    /// will happen there.
    Domain(String, u16),
}

/// A trait for objects that can be converted to `TargetAddr`.
pub trait ToTargetAddr {
    /// Converts the value of `self` to a `TargetAddr`.
    fn to_target_addr(&self) -> io::Result<TargetAddr>;
}

impl<'a> ToTargetAddr for (&'a str, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        // try to parse as an IP first
        if let Ok(addr) = self.0.parse::<Ipv4Addr>() {
            return (addr, self.1).to_target_addr();
        }

        if let Ok(addr) = self.0.parse::<Ipv6Addr>() {
            return (addr, self.1).to_target_addr();
        }

        Ok(TargetAddr::Domain(self.0.to_owned(), self.1))
    }
}

impl ToTargetAddr for SocketAddr {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        Ok(TargetAddr::Ip(*self))
    }
}

impl ToTargetAddr for SocketAddrV4 {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddr::V4(*self).to_target_addr()
    }
}

impl ToTargetAddr for SocketAddrV6 {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddr::V6(*self).to_target_addr()
    }
}

impl ToTargetAddr for (Ipv4Addr, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddrV4::new(self.0, self.1).to_target_addr()
    }
}

impl ToTargetAddr for (Ipv6Addr, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddrV6::new(self.0, self.1, 0, 0).to_target_addr()
    }
}

#[derive(Debug)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(String), // Vec<[u8]> or Box<[u8]> or String ?
}

/// This function is used by the client & the server
pub async fn read_address<T: AsyncRead + Unpin>(
    stream: &mut T,
    atyp: u8,
) -> anyhow::Result<SocketAddr> {
    let addr = match atyp {
        consts::SOCKS5_ADDR_TYPE_IPV4 => {
            debug!("Address type `IPv4`");
            Addr::V4(read_exact!(stream, [0u8; 4]).context(AddrError::IPv4Unreadable)?)
        }
        consts::SOCKS5_ADDR_TYPE_IPV6 => {
            debug!("Address type `IPv6`");
            Addr::V6(read_exact!(stream, [0u8; 16]).context(AddrError::IPv6Unreadable)?)
        }
        consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            debug!("Address type `domain`");
            let len = read_exact!(stream, [0]).context(AddrError::DomainLenUnreadable)?[0];
            let domain = read_exact!(stream, vec![0u8; len as usize])
                .context(AddrError::DomainContentUnreadable)?;
            // make sure the bytes are correct utf8 string
            let domain = String::from_utf8(domain).context(AddrError::Utf8)?;

            Addr::Domain(domain)
        }
        _ => return Err(anyhow::anyhow!(AddrError::IncorrectAddressType))?,
    };

    // Find port number
    let port = read_exact!(stream, [0u8; 2]).context(AddrError::PortNumberUnreadable)?;
    // Convert (u8 * 2) into u16
    let port = (port[0] as u16) << 8 | port[1] as u16;

    // Merge ADDRESS + PORT into a SocketAddr that can be use by TCP Connect
    let addr: SocketAddr = match addr {
        Addr::V4([a, b, c, d]) => SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port).into(),
        Addr::V6(x) => SocketAddrV6::new(Ipv6Addr::from(x), port, 0, 0).into(),
        Addr::Domain(domain) => {
            debug!("Attempt to DNS resolve the domain {}...", &domain);
            // DNS resolution for domain names
            (&domain[..], port)
                .to_socket_addrs()
                .await
                .context(AddrError::DNSResolutionFailed)?
                .next()
                .ok_or(AddrError::Custom(
                    "Can't fetch DNS to the domain.".to_string(),
                ))?
        }
    };

    Ok(addr)
}
