use crate::ReplyError;
use std::io;
use std::time::Duration;
use tokio::io::ErrorKind as IOErrorKind;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::time::timeout;

/// Easy to destructure bytes buffers by naming each fields:
///
/// # Examples (before)
///
/// ```ignore
/// let mut buf = [0u8; 2];
/// stream.read_exact(&mut buf).await?;
/// let [version, method_len] = buf;
///
/// assert_eq!(version, 0x05);
/// ```
///
/// # Examples (after)
///
/// ```ignore
/// let [version, method_len] = read_exact!(stream, [0u8; 2]);
///
/// assert_eq!(version, 0x05);
/// ```
#[macro_export]
macro_rules! read_exact {
    ($stream: expr, $array: expr) => {{
        let mut x = $array;
        //        $stream
        //            .read_exact(&mut x)
        //            .await
        //            .map_err(|_| io_err("lol"))?;
        $stream.read_exact(&mut x).await.map(|_| x)
    }};
}

#[macro_export]
macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

#[derive(thiserror::Error, Debug)]
pub enum ConnectError {
    #[error("Connection timed out")]
    ConnectionTimeout,
    #[error("Connection refused: {0}")]
    ConnectionRefused(#[source] io::Error),
    #[error("Connection aborted: {0}")]
    ConnectionAborted(#[source] io::Error),
    #[error("Connection reset: {0}")]
    ConnectionReset(#[source] io::Error),
    #[error("Not connected: {0}")]
    NotConnected(#[source] io::Error),
    #[error("Other i/o error: {0}")]
    Other(#[source] io::Error),
}

impl ConnectError {
    pub fn to_reply_error(&self) -> ReplyError {
        match self {
            ConnectError::ConnectionTimeout => ReplyError::ConnectionTimeout,
            ConnectError::ConnectionRefused(_) => ReplyError::ConnectionRefused,
            ConnectError::ConnectionAborted(_) | ConnectError::ConnectionReset(_) => {
                ReplyError::ConnectionNotAllowed
            }
            ConnectError::NotConnected(_) => ReplyError::NetworkUnreachable,
            ConnectError::Other(_) => ReplyError::GeneralFailure,
        }
    }
}

pub async fn tcp_connect_with_timeout<T>(
    addr: T,
    request_timeout_s: u64,
) -> Result<TcpStream, ConnectError>
where
    T: ToSocketAddrs,
{
    let fut = tcp_connect(addr);
    match timeout(Duration::from_secs(request_timeout_s), fut).await {
        Ok(result) => result,
        Err(_) => Err(ConnectError::ConnectionTimeout),
    }
}

pub async fn tcp_connect<T>(addr: T) -> Result<TcpStream, ConnectError>
where
    T: ToSocketAddrs,
{
    match TcpStream::connect(addr).await {
        Ok(o) => Ok(o),
        Err(e) => match e.kind() {
            IOErrorKind::ConnectionRefused => Err(ConnectError::ConnectionRefused(e)),
            IOErrorKind::ConnectionAborted => Err(ConnectError::ConnectionAborted(e)),
            IOErrorKind::ConnectionReset => Err(ConnectError::ConnectionReset(e)),
            IOErrorKind::NotConnected => Err(ConnectError::NotConnected(e)),
            _ => Err(ConnectError::Other(e)),
        },
    }
}
