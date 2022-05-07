use thiserror::Error;

#[rustfmt::skip]
pub mod consts {
    pub const SOCKS4_VERSION:                          u8 = 0x04;

    pub const SOCKS4_CMD_CONNECT:                      u8 = 0x01;
    pub const SOCKS4_CMD_BIND:                         u8 = 0x02;

    pub const SOCKS4_REPLY_SUCCEEDED:                  u8 = 0x5a;
    pub const SOCKS4_REPLY_FAILED:                     u8 = 0x5b;
    pub const SOCKS4_REPLY_HOST_UNREACHABLE:           u8 = 0x5c;
    pub const SOCKS4_REPLY_INVALID_USER:               u8 = 0x5d;
}

/// SOCKS4 reply code
#[derive(Error, Debug, Copy, Clone)]
pub enum ReplyError {
    #[error("Succeeded")]
    Succeeded,
    #[error("General failure")]
    GeneralFailure,
    #[error("Host unreachable")]
    HostUnreachable,
    #[error("Address type not supported")]
    AddressTypeNotSupported,
    #[error("Invalid user")]
    InvalidUser,

    #[error("Unknown response")]
    UnknownResponse(u8),
}

#[derive(Debug, PartialEq)]
pub enum Socks4Command {
    Connect,
    Bind,
}

#[allow(dead_code)]
impl Socks4Command {
    #[inline]
    #[rustfmt::skip]
    pub fn as_u8(&self) -> u8 {
        match self {
            Socks4Command::Connect   => consts::SOCKS4_CMD_CONNECT,
            Socks4Command::Bind      => consts::SOCKS4_CMD_BIND,
        }
    }

    #[inline]
    #[rustfmt::skip]
    pub fn from_u8(code: u8) -> Option<Socks4Command> {
        match code {
            consts::SOCKS4_CMD_CONNECT      => Some(Socks4Command::Connect),
            consts::SOCKS4_CMD_BIND         => Some(Socks4Command::Bind),
            _ => None,
        }
    }
}

impl ReplyError {
    #[inline]
    #[rustfmt::skip]
    pub fn as_u8(self) -> u8 {
        match self {
            ReplyError::Succeeded                 => consts::SOCKS4_REPLY_SUCCEEDED,
            ReplyError::GeneralFailure            => consts::SOCKS4_REPLY_FAILED,
            ReplyError::HostUnreachable           => consts::SOCKS4_REPLY_HOST_UNREACHABLE,
            ReplyError::InvalidUser               => consts::SOCKS4_REPLY_INVALID_USER,
            reply                       => panic!("Unsupported ReplyStatus: {:?}", reply)
        }
    }

    #[inline]
    #[rustfmt::skip]
    pub fn from_u8(code: u8) -> ReplyError {
        match code {
            consts::SOCKS4_REPLY_SUCCEEDED         => ReplyError::Succeeded,
            consts::SOCKS4_REPLY_FAILED            => ReplyError::GeneralFailure,
            consts::SOCKS4_REPLY_HOST_UNREACHABLE  => ReplyError::HostUnreachable,
            consts::SOCKS4_REPLY_INVALID_USER      => ReplyError::InvalidUser,
            _                                      => ReplyError::UnknownResponse(code),
        }
    }
}