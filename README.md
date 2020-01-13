# SOCKS5 async/.await Rust implementation

Using async-std library.

## Examples

- Run client `cargo run --example client`
- Run server `cargo run --example server`

## TODO
- Tests have to be implemented

## Inspired by

Thanks to all these SOCKS5 projects

- https://github.com/sfackler/rust-socks/blob/master/src/v5.rs
- https://github.com/shadowsocks/shadowsocks-rust/blob/master/src/relay/socks5.rs
- https://github.com/ylxdzsw/v2socks/blob/master/src/socks.rs

## Further consideration

- Implementation made with Tokio-codec https://github.com/yfaming/yimu-rs/blob/master/src/socks5.rs