# safe-sid

Safe wrapper for working with SIDs from the Windows API.

Provides the borrowed/owned pair `&Sid` and `SidBuf` along with safe helper functions. Byte-compatible with the Windows `SID` struct. Defines equality and ordering traits so they can be compared and keyed on.

The crate only depends on `windows-link`. It deliberately uses raw pointers at
its API boundary so it is not coupled to any version of the `windows` crate.

## Usage

```toml
[dependencies]
safe-sid = "0.2"
```

Applications using the `windows` crate can construct a `PSID` from
`Sid::as_ptr()` at the call site, without requiring `safe-sid` to track the
same `windows` version.

### Build a SID by hand

The identifier authority can be one of the constants in the `authority`
module, a plain integer that fits in 48 bits, or the raw six-byte form.

```rust
use safe_sid::authority::SECURITY_NT_AUTHORITY;

let admins = SidBuf::new(SECURITY_NT_AUTHORITY, &[32, 544]).unwrap();
assert_eq!(admins.to_string(), "S-1-5-32-544");

let same = SidBuf::new(5, &[32, 544]).unwrap();
assert_eq!(same, admins);
```

### Build a well-known SID

```rust
use safe_sid::well_known::WinLocalSystemSid;

let local_system = SidBuf::well_known(WinLocalSystemSid, None).unwrap();
assert_eq!(local_system.to_string(), "S-1-5-18");
```

The `Win*Sid` constants in the `well_known` module use the opaque
`WellKnownSidType` wrapper, so arbitrary integer values cannot be passed to the
well-known SID APIs.

### Pass a SID to a Windows API

```rust
// Just an example, use Sid::to_string() normally 
fn sid_to_string(sid: &Sid) -> Result<String> {
    let mut hlocal_str = PSTR::null();
    unsafe {
        ConvertSidToStringSidA(PSID(sid.as_ptr().cast_mut()), &mut hlocal_str)?;
        let string_sid = CStr::from_ptr(hlocal_str.0 as *const _).to_str().unwrap().to_owned();
        LocalFree(Some(HLOCAL(hlocal_str.0 as *mut _)));
        Ok(string_sid)
    }
}
```

### Fill a `SidBuf` from a Windows API

Sometimes a SID comes from a Windows API that expects the caller to provide a buffer. You can unsafely acquire a mutable pointer, and are responsible for ensuring it is filled with a valid SID with a correctly matching length. 

Note that even if the SID is malformed, dropping `SidBuf` will still be safe.

```rust
fn lookup_account_name(name: &CStr) -> Result<SidBuf> {
    let mut sid_use = SID_NAME_USE::default();
    let mut sid_len = 0u32;
    let mut domain_len = 0u32;

    unsafe {
        if let Err(e) = LookupAccountNameA(
            PCSTR::null(), PCSTR(name.as_ptr() as *const _), None, &mut sid_len,
            None, &mut domain_len, &mut sid_use,
        ) && e.code() != HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0)
        {
            return Err(e);
        }

        // Create the SidBuf with enough space to receive the SID
        let mut sid = SidBuf::with_capacity(sid_len as usize);
        let mut domain = vec![0u8; domain_len as usize];
        LookupAccountNameA(
            PCSTR::null(), PCSTR(name.as_ptr() as *const _), Some(PSID(sid.as_mut_ptr())), &mut sid_len,
            Some(PSTR(domain.as_mut_ptr())), &mut domain_len, &mut sid_use,
        )?;
        Ok(sid)
    }
}
```


## Development

Repository maintenance commands are exposed through `cargo xtask`. Run
`cargo xtask --help` to list them. To refresh the vendored Windows bindings and
well-known SID constants:

```text
cargo xtask regenerate-bindings
```

## License

Licensed under the [ISC License](LICENSE).
