fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let bindings_file = std::path::Path::new(&out_dir).join("bindings.rs");
    let bindings_file = bindings_file.to_str().unwrap();

    windows_bindgen::bindgen([
        "--out",
        bindings_file,
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
    ])
    .unwrap();

    let well_known_file = std::path::Path::new(&out_dir).join("well_known.rs");
    let well_known_file = well_known_file.to_str().unwrap();

    windows_bindgen::bindgen([
        "--out",
        well_known_file,
        "--flat",
        "--sys",
        "--no-deps",
        "--no-allow",
        "--filter",
        "WELL_KNOWN_SID_TYPE",
        "Windows.Win32.Security.Win*",
    ])
    .unwrap();
}
