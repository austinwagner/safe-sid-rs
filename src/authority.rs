/// The authority for the null SID (`S-1-0`), whose only member is the
/// "Nobody" SID `S-1-0-0`.
pub const SECURITY_NULL_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 0];

/// The authority for the world SID (`S-1-1`), whose only member is the
/// "Everyone" SID `S-1-1-0`.
pub const SECURITY_WORLD_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 1];

/// The authority for local SIDs (`S-1-2`), such as `S-1-2-0`, the group of
/// users logged on at a local terminal.
pub const SECURITY_LOCAL_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 2];

/// The authority for creator SIDs (`S-1-3`), such as `S-1-3-0`,
/// CREATOR OWNER.
pub const SECURITY_CREATOR_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 3];

/// The non-unique authority (`S-1-4`).
pub const SECURITY_NON_UNIQUE_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 4];

/// The Windows NT authority (`S-1-5`), which contains most account, group,
/// and logon-session SIDs, such as `S-1-5-18`, LOCAL SYSTEM.
pub const SECURITY_NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

/// The resource manager authority (`S-1-9`), for SIDs defined by third-party
/// resource managers.
pub const SECURITY_RESOURCE_MANAGER_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 9];

/// The application package authority (`S-1-15`), which contains app container
/// and capability SIDs.
pub const SECURITY_APP_PACKAGE_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 15];

/// The mandatory label authority (`S-1-16`), which contains integrity-level
/// SIDs such as `S-1-16-12288`, the high mandatory level.
pub const SECURITY_MANDATORY_LABEL_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 16];

/// The scoped policy identifier authority (`S-1-17`), for SIDs used by
/// central access policies.
pub const SECURITY_SCOPED_POLICY_ID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 17];

/// The authentication authority (`S-1-18`), which contains SIDs describing
/// how an identity was asserted, such as `S-1-18-1`, Authentication Authority
/// Asserted Identity.
pub const SECURITY_AUTHENTICATION_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 18];

/// The process trust authority (`S-1-19`), which contains protected-process
/// trust-level SIDs.
pub const SECURITY_PROCESS_TRUST_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 19];
