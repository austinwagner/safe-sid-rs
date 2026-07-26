# safe-sid

Safe borrowed and owned wrappers for Windows security identifiers (SIDs).

The crate provides the borrowed and owned pair `&Sid` and `SidBuf`. Both use
the in-memory layout of the Windows `SID` structure and support equality,
ordering, hashing, and formatting.

The crate only depends on `windows-link`. It deliberately uses raw pointers at
its API boundary so it is not coupled to any version of the `windows` crate.
It supports Windows targets and requires Rust 1.88 or newer.

## Usage

```toml
[dependencies]
safe-sid = "0.2"
```

```rust
use safe_sid::SidBuf;
use safe_sid::authority::SECURITY_NT_AUTHORITY;

let admins = SidBuf::new(SECURITY_NT_AUTHORITY, &[32, 544]).unwrap();
assert_eq!(admins.to_string(), "S-1-5-32-544");

let parsed: SidBuf = "S-1-5-32-544".parse().unwrap();
assert_eq!(parsed, admins);
```

`SidBuf::new` also accepts a plain integer that fits in 48 bits or the raw
six-byte authority. `SidBuf::well_known` creates Windows well-known SIDs, and
`SidBuf::from_string_sid` accepts Windows aliases such as `BA`.

The `Win*Sid` constants in the `well_known` module use the opaque
`WellKnownSidType` wrapper, so arbitrary integer values cannot be passed to the
well-known SID APIs.

## Windows API interoperability

Applications using the `windows` crate can construct a `PSID` from
`Sid::as_ptr()` at the call site without requiring `safe-sid` to track the
same `windows` version. For APIs that fill a caller-provided buffer, use
`SidBuf::with_capacity` and `SidBuf::as_mut_ptr`. The
[`SidBuf::as_mut_ptr` documentation](https://docs.rs/safe-sid/latest/safe_sid/struct.SidBuf.html#method.as_mut_ptr)
includes the complete two-call pattern and its safety requirements.

## Development

Repository maintenance commands are exposed through `cargo xtask`. Run
`cargo xtask --help` to list them. To refresh the vendored Windows bindings and
well-known SID constants:

```text
cargo xtask regenerate-bindings
```

## License

Licensed under the [ISC License](LICENSE).
