# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-20

### Breaking Changes

- **Timeout parameters now use `std::time::Duration` instead of `u64`**
  - `server::Config::set_request_timeout()` now takes `Duration` instead of `u64`
  - `client::Config::set_connect_timeout()` now takes `Duration` instead of `u64`
  - `server::run_tcp_proxy()` parameter changed from `request_timeout_s: u64` to `request_timeout: Duration`
  - `util::stream::tcp_connect_with_timeout()` parameter changed from `request_timeout_s: u64` to `request_timeout: Duration`

  **Migration:** Replace `config.set_request_timeout(10)` with `config.set_request_timeout(Duration::from_secs(10))`

- **New type-safe server protocol API** - The server API has been completely redesigned with a type-state pattern for safer authentication and command handling.

### Added

- `Socks5ServerProtocol` - New type-safe protocol handler with compile-time state tracking
- `server::run_udp_proxy_custom()` - Allows customizing UDP proxy transfer logic
- `server::ErrorContext` trait - Now public for custom error handling
- `impl ToTargetAddr for TargetAddr` - Convenience implementation
- DNS resolution helper (`DnsResolveHelper` trait)
- New examples: `custom_auth_server`, `router`

### Changed

- Downgraded client/server info-level logs to debug level for less noisy output
- UDP bind now ensures dualstack (IPv6+IPv4) or IPv4 fallback by default
- Improved UDP proxy reliability - no longer stops on single packet errors
- IPv6-mapped IPv4 addresses are now properly reversed in server responses

### Fixed

- UDP proxy now correctly terminates when the TCP control connection closes
- Fixed authentication method prioritization
- Fixed IPv6-mapping of IPv4 addresses in server replies

### Removed

- Deprecated `simple_tcp_server` example (replaced by new API examples)

## [1.0.0-rc.0] - 2025-xx-xx

Release candidate for 1.0.0.

## [1.0.0-beta.2] - 2025-xx-xx

Beta release with UDP improvements.

## [1.0.0-beta.1] - 2025-xx-xx

Initial beta release with new type-safe API.

## [0.10.0] and earlier

See git history for previous releases.
