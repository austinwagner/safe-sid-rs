# Changelog

## [0.2.0] - 2026-07-24

### Breaking changes

* Removed all free functions. Use the methods on `Sid` or `SidBuf` instead.

### Added

* Re-exported well-known SID constants.

### Changed

* Removed requirement for `windows-full` feature from most functions by using `windows-bindgen`.
* Improved documentation.
* Set MSRV to v1.88 (not breaking, this is the same minimum version as before, just properly indicated now)

**Full Changelog**: https://github.com/austinwagner/safe-sid-rs/compare/v0.1.1...v0.2.0
