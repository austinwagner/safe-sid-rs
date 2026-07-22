# safe-sid

Safe wrapper for working with SIDs from the Windows API.

Provides the borrowed/owned pair `&Sid` and `SidBuf` along with safe helper functions. Byte-compatible with the Windows `SID` struct. Defines equality and ordering traits so they can be compared and keyed on.

Depends on the `windows` crate by default, but this can be reduced down to just `windows-core` by turning off default features.

## Usage

```toml
[dependencies]
safe-sid = "0.1"
```

Or for just the `windows-core` dependency:

```toml
[dependencies]
safe-sid = { version = "0.1", default-features = false }
```

### Build a SID by hand

```rust
let admins = SidBuf::new([0, 0, 0, 0, 0, 5], &[32, 544]).unwrap();
assert_eq!(admins.to_string(), "S-1-5-32-544");
```

### Build a well-known SID

```rust
let local_system = SidBuf::well_known(WinLocalSystemSid, None).unwrap();
assert_eq!(local_system.to_string(), "S-1-5-18");
```

### Pass a SID to a Windows API

```rust
// Just an example, use Sid::to_string() normally 
fn sid_to_string(sid: &Sid) -> Result<String> {
    let mut hlocal_str = PSTR::null();
    unsafe {
        ConvertSidToStringSidA(sid.as_psid(), &mut hlocal_str)?;
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


## License

Licensed under the [ISC License](LICENSE).
