# SOCKS5 client/server library using async/.await

## Features

- Built on-top of `async-std` library
- Ultra lightweight and scalable
- No system dependencies
- Cross-platform
- Authentication methods:
  - No-Auth method
  - Username/Password auth method
  - Custom auth methods can be implemented via the Authentication Trait
- All SOCKS5 errors (replies) should be mapped
- AsyncRead + AsyncWrite traits are implemented on Socks5Stream
- IPv4, IPv6, and Domains types are supported
- Config helper for Socks5Server
- Helpers to run a Socks5Server à la *"async-std's TcpStream"*-like via `incoming.next().await`
- Examples come with real cases commands scenarios

## Examples

Please check ./examples/ directory.

```bash
# Run client
cargo run --example client

# Run server
cargo run --example server
```

## TODO
- Tests have to be implemented
- Better Rust doc

## Inspired by

Thanks to all these SOCKS5 projects

- https://github.com/sfackler/rust-socks/blob/master/src/v5.rs
- https://github.com/shadowsocks/shadowsocks-rust/blob/master/src/relay/socks5.rs
- https://github.com/ylxdzsw/v2socks/blob/master/src/socks.rs

## Further consideration

- Implementation made with Tokio-codec https://github.com/yfaming/yimu-rs/blob/master/src/socks5.rs