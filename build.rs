fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_file = std::path::Path::new(&out_dir).join("bindings.rs");
    let out_file = out_file.to_str().unwrap();

    windows_bindgen::bindgen([
        "--out",
        out_file,
        "--flat",
        "--sys",
        "--no-deps",
        "--no-allow",
        "--filter",
        "CreateWellKnownSid",
        "ConvertStringSidToSidA",
        "EqualDomainSid",
        "GetWindowsAccountDomainSid",
        "IsWellKnownSid",
        "LocalFree",
        "ERROR_INSUFFICIENT_BUFFER",
        "WELL_KNOWN_SID_TYPE",
        "WinBuiltinAdministratorsSid",
        "WinLocalSystemSid",
        "WinNullSid",
        "WinWorldSid",
    ])
    .unwrap();
}
