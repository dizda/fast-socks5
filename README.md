# SOCKS5 client/server library using async/.await
[![License](https://img.shields.io/github/license/dizda/fast-socks5.svg)](https://github.com/dizda/fast-socks5)
[![crates.io](https://img.shields.io/crates/v/fast-socks5.svg)](https://crates.io/crates/fast-socks5)
[![dependency status](https://deps.rs/repo/github/dizda/fast-socks5/status.svg)](https://deps.rs/repo/github/dizda/fast-socks5)
[![Release](https://img.shields.io/github/release/dizda/fast-socks5.svg)](https://github.com/dizda/fast-socks5/releases)

This library is maintained by [anyip.io](https://anyip.io/) a residential and mobile socks5 proxy provider.

## Features

- An `async`/`.await` [SOCKS5](https://tools.ietf.org/html/rfc1928) implementation.
- An `async`/`.await` [SOCKS4 Client](https://www.openssh.com/txt/socks4.protocol) implementation.
- An `async`/`.await` [SOCKS4a Client](https://www.openssh.com/txt/socks4a.protocol) implementation.
- No **unsafe** code
- Built on top of the [Tokio](https://tokio.rs/) runtime
- Ultra lightweight and scalable
- No system dependencies
- Cross-platform
- Infinitely extensible, explicit server API based on typestates for safety
  - You control the request handling, the library only ensures you follow the proper protocol flow
  - Can skip DNS resolution
  - Can skip the authentication/handshake process (not RFC-compliant, for private use, to save on useless round-trips)
  - Instead of proxying in-process, swap out `run_tcp_proxy` for custom handling to build a router or to use a custom accelerated proxying method
- Authentication methods:
  - No-Auth method (`0x00`)
  - Username/Password auth method (`0x02`)
  - Custom auth methods can be implemented on the server side via the `AuthMethod` Trait
    - Multiple auth methods with runtime negotiation can be supported, with fast *static* dispatch (enums can be generated with the `auth_method_enums` macro)
- UDP is supported
- All SOCKS5 RFC errors (replies) should be mapped
- `IPv4`, `IPv6`, and `Domains` types are supported


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

## Benchmarks
`proxychains`, `iperf3` and rust toolchain must be installed

tested on Ubuntu 22.04 LTS
### run simple benchmark
```bash
cd bench
./bench.sh
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
