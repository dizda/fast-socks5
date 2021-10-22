# SOCKS5 client/server library using async/.await
[![License](https://img.shields.io/github/license/dizda/fast-socks5.svg)](https://github.com/dizda/fast-socks5)
[![crates.io](https://img.shields.io/crates/v/fast-socks5.svg)](https://crates.io/crates/fast-socks5)
[![dependency status](https://deps.rs/repo/github/dizda/fast-socks5/status.svg)](https://deps.rs/repo/github/dizda/fast-socks5)
[![Release](https://img.shields.io/github/release/dizda/fast-socks5.svg)](https://github.com/dizda/fast-socks5/releases)

## Features

- An `async`/`.await` [SOCKS5](https://tools.ietf.org/html/rfc1928) implementation.
- No **unsafe** code
- Built on-top of `tokio` library
- Ultra lightweight and scalable
- No system dependencies
- Cross-platform
- Authentication methods:
  - No-Auth method
  - Username/Password auth method
  - Custom auth methods can be implemented via the Authentication Trait
- All SOCKS5 RFC errors (replies) should be mapped
- `AsyncRead + AsyncWrite` traits are implemented on Socks5Stream & Socks5Socket
- `IPv4`, `IPv6`, and `Domains` types are supported
- Config helper for Socks5Server
- Helpers to run a Socks5Server à la *"std's TcpStream"* via `incoming.next().await`
- Examples come with real cases commands scenarios
- Can disable `DNS resolving`
- Can skip the authentication/handshake process, which will directly handle command's request (useful to save useless round-trips in a current authenticated environment)
- Can disable command execution (useful if you just want to forward the request to a different server)


## Install

Open in [crates.io](https://crates.io/crates/fast-socks5).


## Examples

Please check [`examples`](https://github.com/dizda/fast-socks5/tree/master/examples) directory.

```bash
# Run client
RUST_LOG=debug cargo run --example client -- --socks-server 127.0.0.1:1337 --username admin --password password -a perdu.com -p 80

# Run server
RUST_LOG=debug cargo run --example server -- --listen-addr 127.0.0.1:1337 password -u admin -p password

# Test it with cURL
curl -v --proxy socks5://admin:password@127.0.0.1:1337 https://ipapi.co/json/
```

## TODO
- Tests have to be implemented
- Better Rust doc
- Bind command not implemented
- UDP command not implemented

## Inspired by

Thanks to all these SOCKS5 projects

- https://github.com/sfackler/rust-socks/blob/master/src/v5.rs
- https://github.com/shadowsocks/shadowsocks-rust/blob/master/src/relay/socks5.rs
- https://github.com/ylxdzsw/v2socks/blob/master/src/socks.rs

## Further consideration

- Implementation made with Tokio-codec https://github.com/yfaming/yimu-rs/blob/master/src/socks5.rs