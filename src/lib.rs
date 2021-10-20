#[forbid(unsafe_code)]
#[macro_use]
extern crate log;

pub mod client;
pub mod server;
pub mod util;

use std::fmt;
use std::io;
use thiserror::Error;

#[rustfmt::skip]
pub mod consts {
    pub const SOCKS5_VERSION:                          u8 = 0x05;

    pub const SOCKS5_AUTH_METHOD_NONE:                 u8 = 0x00;
    pub const SOCKS5_AUTH_METHOD_GSSAPI:               u8 = 0x01;
    pub const SOCKS5_AUTH_METHOD_PASSWORD:             u8 = 0x02;
    pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE:       u8 = 0xff;

    pub const SOCKS5_CMD_TCP_CONNECT:                  u8 = 0x01;
    pub const SOCKS5_CMD_TCP_BIND:                     u8 = 0x02;
    pub const SOCKS5_CMD_UDP_ASSOCIATE:                u8 = 0x03;

    pub const SOCKS5_ADDR_TYPE_IPV4:                   u8 = 0x01;
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME:            u8 = 0x03;
    pub const SOCKS5_ADDR_TYPE_IPV6:                   u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED:                  u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE:            u8 = 0x01;
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:     u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE:        u8 = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE:           u8 = 0x04;
    pub const SOCKS5_REPLY_CONNECTION_REFUSED:         u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED:                u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:      u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[derive(Debug, PartialEq)]
pub enum AuthenticationMethod {
    None,
    Password { username: String, password: String },
}

impl AuthenticationMethod {
    #[inline]
    #[rustfmt::skip]
    fn as_u8(&self) -> u8 {
        match self {
            AuthenticationMethod::None => consts::SOCKS5_AUTH_METHOD_NONE,
            AuthenticationMethod::Password {..} =>
                consts::SOCKS5_AUTH_METHOD_PASSWORD
        }
    }

    #[inline]
    #[rustfmt::skip]
    fn from_u8(code: u8) -> Option<AuthenticationMethod> {
        match code {
            consts::SOCKS5_AUTH_METHOD_NONE     => Some(AuthenticationMethod::None),
            consts::SOCKS5_AUTH_METHOD_PASSWORD => Some(AuthenticationMethod::Password { username: "test".to_string(), password: "test".to_string()}),
            _                                   => None,
        }
    }
}

impl fmt::Display for AuthenticationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            AuthenticationMethod::None => f.write_str("AuthenticationMethod::None"),
            AuthenticationMethod::Password { .. } => f.write_str("AuthenticationMethod::Password"),
        }
    }
}

//impl Vec<AuthenticationMethod> {
//    pub fn as_bytes(&self) -> &[u8] {
//        self.iter().map(|l| l.as_u8()).collect()
//    }
//}
//
//impl From<&[AuthenticationMethod]> for &[u8] {
//    fn from(_: Vec<AuthenticationMethod>) -> Self {
//        &[0x00]
//    }
//}

#[derive(Error, Debug)]
pub enum SocksError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("the data for key `{0}` is not available")]
    Redaction(String),
    #[error("invalid header (expected {expected:?}, found {found:?})")]
    InvalidHeader { expected: String, found: String },

    #[error("Auth method unacceptable `{0:?}`.")]
    AuthMethodUnacceptable(Vec<u8>),
    #[error("Unsupported SOCKS version `{0}`.")]
    UnsupportedSocksVersion(u8),
    #[error("Domain exceeded max sequence length")]
    ExceededMaxDomainLen(usize),
    #[error("Authentication failed `{0}`")]
    AuthenticationFailed(String),
    #[error("Authentication rejected `{0}`")]
    AuthenticationRejected(String),

    #[error("Error with reply: {0}.")]
    ReplyError(#[from] ReplyError),

    #[error("Argument input error: `{0}`.")]
    ArgumentInputError(&'static str),

    //    #[error("Other: `{0}`.")]
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T, E = SocksError> = core::result::Result<T, E>;

/// SOCKS5 reply code
#[derive(Error, Debug, Copy, Clone)]
pub enum ReplyError {
    #[error("General failure")]
    GeneralFailure,
    #[error("Connection not allowed by ruleset")]
    ConnectionNotAllowed,
    #[error("Network unreachable")]
    NetworkUnreachable,
    #[error("Host unreachable")]
    HostUnreachable,
    #[error("Connection refused")]
    ConnectionRefused,
    #[error("TTL expired")]
    TtlExpired,
    #[error("Command not supported")]
    CommandNotSupported,
    #[error("Address type not supported")]
    AddressTypeNotSupported,
    //    OtherReply(u8),
}

impl ReplyError {
    #[inline]
    #[rustfmt::skip]
    pub fn as_u8(self) -> u8 {
        match self {
            ReplyError::GeneralFailure          => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            ReplyError::ConnectionNotAllowed    => consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            ReplyError::NetworkUnreachable      => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            ReplyError::HostUnreachable         => consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            ReplyError::ConnectionRefused       => consts::SOCKS5_REPLY_CONNECTION_REFUSED,
            ReplyError::TtlExpired              => consts::SOCKS5_REPLY_TTL_EXPIRED,
            ReplyError::CommandNotSupported     => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            ReplyError::AddressTypeNotSupported => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
//            ReplyError::OtherReply(c)           => c,
        }
    }

    #[inline]
    #[rustfmt::skip]
    pub fn from_u8(code: u8) -> ReplyError {
        match code {
            consts::SOCKS5_REPLY_GENERAL_FAILURE            => ReplyError::GeneralFailure,
            consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED     => ReplyError::ConnectionNotAllowed,
            consts::SOCKS5_REPLY_NETWORK_UNREACHABLE        => ReplyError::NetworkUnreachable,
            consts::SOCKS5_REPLY_HOST_UNREACHABLE           => ReplyError::HostUnreachable,
            consts::SOCKS5_REPLY_CONNECTION_REFUSED         => ReplyError::ConnectionRefused,
            consts::SOCKS5_REPLY_TTL_EXPIRED                => ReplyError::TtlExpired,
            consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED      => ReplyError::CommandNotSupported,
            consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => ReplyError::AddressTypeNotSupported,
//            _                                               => ReplyError::OtherReply(code),
            _                                               => unreachable!("ReplyError code unsupported."),
        }
    }
}
