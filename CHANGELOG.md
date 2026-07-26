# Changelog

## [Unreleased]

## [1.0.0] - 2026-07-26

### Breaking changes

- Fallible SID operations now return the crate-defined `safe_sid::Error` instead of `windows_core::Error`.
- Removed the `windows-full` feature and public API implementations for `windows::Win32::Security` types. Use the raw-pointer API for interoperability.
- Replaced the public `WELL_KNOWN_SID_TYPE = i32` alias with the opaque `WellKnownSidType` wrapper.
- `Ord` and `PartialOrd` now compare SIDs by identifier authority and then by sub-authorities instead of comparing their raw bytes.
- `FromStr` parsing is now strict and implemented entirely in Rust. It round-trips `Display` output, reports the new `SidParseError` type instead of `ParseError`, and no longer calls Windows.
- Replaced `SidBuf::from_cstr_with_alias` with `SidBuf::from_string_sid`, which takes `&str`, still accepts Windows aliases such as `BA`, and also reports `SidParseError`.
- Removed `Sid::as_psid`. Use `Sid::as_ptr` instead.

### Added

- Added `safe_sid::Result`, `Error::win32_code`, and conversions from `SidParseError` to `Error` and from `Error` to `std::io::Error`.
- Added the `authority` module with the Windows `SECURITY_*_AUTHORITY` constants.
- `SidBuf::new` now accepts an `authority` constant or any primitive integer that fits in 48 bits through the sealed `IntoAuthority` trait.
- Added `SidBuf::from_bytes` for copying a SID from its raw, possibly unaligned, byte representation.
- Added `Sid::rid` and `Sid::authority_bytes`.
- Added `#[must_use]` to side-effect-free accessors.

### Changed

- Removed `windows-core` from the default dependency tree.
- Vendored the Windows bindings and well-known SID constants so downstream builds no longer run `windows-bindgen`.

## [0.2.0] - 2026-07-24

### Breaking changes

- Removed all free functions. Use the methods on `Sid` or `SidBuf` instead.

### Added

- Re-exported well-known SID constants.

### Changed

- Removed the `windows-full` feature requirement from most functions by using `windows-bindgen`.
- Improved documentation.
- Declared the existing minimum supported Rust version of 1.88.

[1.0.0]: https://github.com/austinwagner/safe-sid-rs/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/austinwagner/safe-sid-rs/compare/v0.1.1...v0.2.0
