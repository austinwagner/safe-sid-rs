#![cfg_attr(docsrs, feature(doc_cfg))]

//! Safe borrowed and owned wrappers for Windows security identifiers (SIDs).
//!
//! A SID identifies a user, group, logon session, or other security principal.
//! This crate represents one with the same in-memory layout used by Windows:
//!
//! - [`Sid`] is a dynamically sized, borrowed SID, analogous to `str`.
//! - [`SidBuf`] owns a SID, analogous to [`String`].
//!
//! `SidBuf` dereferences to `Sid`, and both types implement equality, ordering,
//! hashing, and formatting. This makes owned SIDs suitable as map and set keys
//! while still allowing lookup with a borrowed `&Sid`.
//!
//! # Creating SIDs
//!
//! Build a SID from its identifier authority and its sub-authorities. The
//! authority can be one of the constants in [`authority`], its raw six-byte
//! form, or a plain integer:
//!
//! ```
//! use safe_sid::SidBuf;
//! use safe_sid::authority::SECURITY_NT_AUTHORITY;
//!
//! // S-1-5-32-544 is the BUILTIN\Administrators SID.
//! let administrators = SidBuf::new(SECURITY_NT_AUTHORITY, &[32, 544])?;
//! assert_eq!(administrators.to_string(), "S-1-5-32-544");
//! # Ok::<(), safe_sid::Error>(())
//! ```
//!
//! Or ask Windows to create a [well-known SID](well_known):
//!
//! ```
//! use safe_sid::SidBuf;
//! use safe_sid::well_known::WinLocalSystemSid;
//!
//! let local_system = SidBuf::well_known(WinLocalSystemSid, None)?;
//! assert_eq!(local_system.to_string(), "S-1-5-18");
//! # Ok::<(), safe_sid::Error>(())
//! ```
//!
//! Numeric SID strings can be parsed without calling Windows:
//!
//! ```
//! use safe_sid::SidBuf;
//!
//! let sid: SidBuf = "S-1-5-18".parse()?;
//! assert_eq!(sid.authority(), 5);
//! assert_eq!(sid.sub_authorities(), [18]);
//! # Ok::<(), safe_sid::SidParseError>(())
//! ```
//!
//! [`SidBuf::from_string_sid`] additionally accepts Windows aliases such
//! as `BA` (BUILTIN\Administrators).
//!
//! # Windows API interoperability
//!
//! This crate does not depend on the `windows` crate. [`Sid::as_ptr`] and
//! [`Sid::from_psid`] use raw `c_void` pointers so applications can choose
//! their own Windows bindings and versions.
//!
//! A borrowed SID can be passed to an API for the duration of the call:
//!
//! ```
//! use safe_sid::SidBuf;
//! use windows::Win32::Security::{GetLengthSid, PSID};
//!
//! let sid: SidBuf = "S-1-5-18".parse().unwrap();
//! // The API must not retain or mutate the borrowed pointer.
//! let byte_len = unsafe { GetLengthSid(PSID(sid.as_ptr().cast_mut())) };
//! assert_eq!(byte_len as usize, sid.as_bytes().len());
//! ```
//!
//! Use [`SidBuf::with_capacity`] and [`SidBuf::as_mut_ptr`] for APIs that fill
//! a caller-supplied SID buffer. The usual Windows two-call pattern is:
//!
//! 1. Call the API with no buffer to obtain the required byte count.
//! 2. Allocate that many bytes with [`SidBuf::with_capacity`].
//! 3. Pass [`SidBuf::as_mut_ptr`] to the API.
//! 4. Read the buffer only after the API has successfully written a valid SID.
//!
//! See [`SidBuf::as_mut_ptr`] for a complete buffer-filling example.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::ffi::c_void;
use std::fmt::{Debug, Display};
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::str::FromStr;

#[allow(non_snake_case, non_camel_case_types, dead_code, clippy::all)]
mod bindings;

#[allow(non_upper_case_globals)]
/// Constants for the SID types accepted by [`SidBuf::well_known`] and
/// [`Sid::is_well_known`].
///
/// The names and values correspond to Windows'
/// `WELL_KNOWN_SID_TYPE` enumeration.
pub mod well_known;

/// Constants for the identifier authorities defined by Windows, for use with
/// [`SidBuf::new`].
///
/// The names and values correspond to Windows'
/// `SECURITY_*_AUTHORITY` constants.
pub mod authority;

/// A Windows well-known SID type.
///
/// Values of this type are exposed as the named constants in [`well_known`],
/// such as [`well_known::WinLocalSystemSid`]. The integer accepted by the
/// underlying Windows APIs is intentionally not part of this crate's public
/// API, so arbitrary integers cannot be used as well-known SID types.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct WellKnownSidType(i32);

const SID_REVISION: u8 = 1;
const SID_MAX_SUB_AUTHORITIES: u8 = 15;
const SID_HEADER_WORDS: usize = 2;
const ERROR_INVALID_SID: u32 = 0x0539;
const MAX_AUTHORITY: u64 = 0xFFFF_FFFF_FFFF;

/// An error reported while creating, validating, or querying a SID.
///
/// Failures detected by this crate are reported as descriptive variants, while
/// failures reported by a Windows API carry the Win32 error code in
/// [`Error::Windows`]. [`Error::win32_code`] maps any variant to a Win32 error
/// code, and the [`From`] conversion to [`std::io::Error`] does the same for
/// I/O-based error handling.
///
/// This type is owned by `safe-sid`, so it remains stable independently of the
/// version of `windows-core` used by an application. String parsing reports
/// [`SidParseError`] instead, which converts into this type via [`From`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// More than 15 sub-authorities were supplied.
    TooManySubAuthorities,
    /// An integer identifier authority does not fit in 48 bits.
    AuthorityOutOfRange,
    /// The bytes, string, or pointer do not describe a valid SID.
    InvalidSid,
    /// A Windows API call failed with this Win32 error code.
    Windows(u32),
}

impl Error {
    /// Returns the Win32 error code equivalent of this error.
    ///
    /// Failures detected by this crate map to `ERROR_INVALID_SID`. Failures
    /// reported by Windows return their original code.
    #[must_use]
    pub const fn win32_code(&self) -> u32 {
        match self {
            Error::TooManySubAuthorities | Error::AuthorityOutOfRange | Error::InvalidSid => {
                ERROR_INVALID_SID
            }
            Error::Windows(code) => *code,
        }
    }

    /// Captures the calling thread's last Win32 error code.
    fn from_last_win32_error() -> Self {
        // SAFETY: GetLastError has no preconditions.
        Error::Windows(unsafe { bindings::GetLastError() })
    }
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TooManySubAuthorities => write!(f, "a SID holds at most 15 sub-authorities"),
            Error::AuthorityOutOfRange => {
                write!(f, "the identifier authority does not fit in 48 bits")
            }
            Error::InvalidSid => write!(f, "not a valid SID"),
            Error::Windows(code) => {
                Display::fmt(&std::io::Error::from_raw_os_error(*code as i32), f)
            }
        }
    }
}

impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        std::io::Error::from_raw_os_error(error.win32_code() as i32)
    }
}

/// A result returned by fallible `safe-sid` operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Converts a supported pointer wrapper to the raw pointer used by SID APIs.
///
/// This trait lets [`Sid::from_psid`] and [`SidBuf::from_psid`] work with raw
/// `c_void` pointers and user-defined pointer wrappers without depending on a
/// particular Windows bindings crate.
pub trait AsSidPtr {
    /// Returns the wrapped SID pointer.
    fn as_sid_ptr(&self) -> *const c_void;
}

/// Converts a well-known SID type to the value expected by Windows.
///
/// The crate's constants, such as [`well_known::WinLocalSystemSid`], implement
/// this trait.
pub trait AsWellKnownSidType {
    /// Returns the wrapped well-known SID type.
    fn as_well_known_sid_type(&self) -> WellKnownSidType;
}

impl AsWellKnownSidType for WellKnownSidType {
    fn as_well_known_sid_type(&self) -> WellKnownSidType {
        *self
    }
}

impl AsSidPtr for *const c_void {
    fn as_sid_ptr(&self) -> *const c_void {
        *self
    }
}

impl AsSidPtr for *mut c_void {
    fn as_sid_ptr(&self) -> *const c_void {
        *self
    }
}

mod sealed {
    /// Prevents implementations of [`IntoAuthority`](super::IntoAuthority)
    /// outside of this crate.
    pub trait Sealed {}
}

/// Converts a value into a SID's six-byte identifier authority.
///
/// This trait is implemented for `[u8; 6]`, the authority's raw big-endian
/// form used by the constants in [`authority`], and for every primitive
/// integer type. Integer values must fit in 48 bits.
///
/// The trait is sealed and cannot be implemented outside of `safe-sid`.
pub trait IntoAuthority: sealed::Sealed {
    /// Returns the value as a big-endian six-byte identifier authority.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthorityOutOfRange`] if the value cannot be
    /// represented in 48 bits.
    fn try_into_authority(self) -> Result<[u8; 6]>;
}

impl sealed::Sealed for [u8; 6] {}

impl IntoAuthority for [u8; 6] {
    fn try_into_authority(self) -> Result<[u8; 6]> {
        Ok(self)
    }
}

macro_rules! impl_into_authority {
    ($($t:ty)*) => {$(
        impl sealed::Sealed for $t {}

        impl IntoAuthority for $t {
            #[allow(clippy::useless_conversion)] // the u64 expansion converts u64 to u64
            fn try_into_authority(self) -> Result<[u8; 6]> {
                match u64::try_from(self) {
                    Ok(value) if value <= MAX_AUTHORITY => {
                        Ok(value.to_be_bytes()[2..].try_into().unwrap())
                    }
                    _ => Err(Error::AuthorityOutOfRange),
                }
            }
        }
    )*};
}

// i32 is required in this list: with multiple integer impls, an unsuffixed
// literal in `SidBuf::new(5, ...)` resolves through the compiler's i32
// fallback, so removing i32 breaks such calls. The list deliberately covers
// every primitive integer type so it never needs to grow, which keeps that
// fallback (and therefore inference) stable.
impl_into_authority!(u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize);

/// A borrowed SID.
///
/// `Sid` is byte-compatible with the Windows `SID` structure but represented as
/// a dynamically sized type. It is normally obtained by dereferencing a
/// [`SidBuf`] or, when borrowing memory owned elsewhere, by calling
/// [`Sid::from_psid`].
///
/// Use [`ToOwned::to_owned`] to copy a borrowed SID into a [`SidBuf`].
#[repr(C)]
pub struct Sid {
    revision: u8,
    sub_authority_count: u8,
    identifier_authority: [u8; 6],
    sub_authority: [u32],
}

impl Sid {
    /// Reinterpret already-validated SID words as a `&Sid`.
    ///
    /// `words` must be the two header words followed by the sub-authority words.
    fn from_words_unchecked(words: &[u32]) -> &Sid {
        debug_assert!(
            words.len() >= SID_HEADER_WORDS,
            "a SID has at least the two header words"
        );
        let sub_count = words.len() - SID_HEADER_WORDS;
        let ptr = std::ptr::slice_from_raw_parts(words.as_ptr(), sub_count) as *const Sid;
        // SAFETY: ptr is 4-byte aligned, see SidBuf::from_boxed_words for explanation on length validity
        unsafe { &*ptr }
    }

    /// See [`Sid::from_words_unchecked`].
    fn from_words_unchecked_mut(words: &mut [u32]) -> &mut Sid {
        debug_assert!(
            words.len() >= SID_HEADER_WORDS,
            "a SID has at least the two header words"
        );
        let sub_count = words.len() - SID_HEADER_WORDS;
        let ptr = std::ptr::slice_from_raw_parts_mut(words.as_mut_ptr(), sub_count) as *mut Sid;
        // SAFETY: ptr is 4-byte aligned, see SidBuf::from_boxed_words for explanation on length validity
        unsafe { &mut *ptr }
    }

    /// Returns the number of sub-authorities that fit in the backing buffer.
    #[inline]
    fn logical_sub_count(&self) -> usize {
        (self.sub_authority_count as usize).min(self.sub_authority.len())
    }

    /// The SID's words, independent of any extra buffer capacity
    /// (see [`with_capacity`](SidBuf::with_capacity)).
    #[inline]
    fn words(&self) -> &[u32] {
        // SAFETY: logical_sub_count() is limited to our actual buffer size, so
        // even if sub_authority_count is oversized, the returned slice cannot
        // allow out-of-bounds reads.
        unsafe {
            std::slice::from_raw_parts(
                self as *const Sid as *const u32,
                SID_HEADER_WORDS + self.logical_sub_count(),
            )
        }
    }

    /// Returns the logical SID as raw bytes.
    ///
    /// The slice contains the eight-byte header followed by four bytes for each
    /// sub-authority. Spare capacity in a [`SidBuf::with_capacity`] allocation
    /// is not included.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        let words = self.words();
        // SAFETY: [u32] has a stronger alignment requirement than [u8], size is computed accurately
        unsafe { std::slice::from_raw_parts(words.as_ptr() as *const u8, size_of_val(words)) }
    }

    /// The entire backing allocation, including any capacity beyond the logical SID.
    /// Exposed for testing to validate allocations.
    #[cfg(test)]
    fn buffer_bytes(&self) -> &[u8] {
        let word_len = SID_HEADER_WORDS + self.sub_authority.len();
        // SAFETY: we know we have a 2 word header and sub_authority gives the allocated length,
        // so this is an accurate representation of the bytes that can be accessed
        unsafe {
            std::slice::from_raw_parts(self as *const Sid as *const u8, word_len * size_of::<u32>())
        }
    }

    /// Returns a raw pointer to this SID for use with Windows APIs.
    ///
    /// The pointer remains valid only while `self` is alive and has not been
    /// mutably borrowed. The called API must not mutate the SID through it.
    #[must_use]
    pub fn as_ptr(&self) -> *const c_void {
        self as *const Sid as *const c_void
    }

    /// Borrows a raw `PSID` as `&'a Sid`, validating its structure.
    ///
    /// # Safety
    ///
    /// `psid` must be non-null and point to a readable, 4-byte-aligned SID that
    /// remains valid for `'a`. Its sub-authority count must accurately describe
    /// the allocation. SIDs allocated by Windows meet these requirements.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSid`] if the revision or sub-authority count is
    /// outside the range allowed by Windows.
    pub unsafe fn from_psid<'a>(psid: impl AsSidPtr) -> Result<&'a Sid> {
        let psid = psid.as_sid_ptr();

        // SAFETY: the safety rules stated to the caller apply here
        let p = psid as *const u8;
        let (revision, sub_count) = unsafe { (*p, *p.add(1)) };
        if revision != SID_REVISION || sub_count > SID_MAX_SUB_AUTHORITIES {
            return Err(Error::InvalidSid);
        }

        // Validate 4-byte alignment in debug mode
        debug_assert!(
            (psid as usize).is_multiple_of(align_of::<u32>()),
            "SID pointer is not 4-byte aligned",
        );

        // Header + sub-authorities
        let word_len = SID_HEADER_WORDS + sub_count as usize;

        // SAFETY: the safety rules stated to the caller apply here
        let words = unsafe { std::slice::from_raw_parts(psid as *const u32, word_len) };
        Ok(Sid::from_words_unchecked(words))
    }

    /// Returns the SID revision.
    ///
    /// Valid Windows SIDs currently have revision 1.
    #[inline]
    #[must_use]
    pub fn revision(&self) -> u8 {
        self.revision
    }

    /// Returns the number of sub-authorities recorded in the SID header.
    #[inline]
    #[must_use]
    pub fn sub_authority_count(&self) -> u8 {
        self.sub_authority_count
    }

    /// Returns the 48-bit identifier authority as an integer.
    #[inline]
    #[must_use]
    pub fn authority(&self) -> u64 {
        let [a0, a1, a2, a3, a4, a5] = self.identifier_authority;
        u64::from_be_bytes([0, 0, a0, a1, a2, a3, a4, a5])
    }

    /// Returns the identifier authority in its big-endian six-byte form.
    ///
    /// This is the representation used by the constants in [`authority`] and
    /// accepted by [`SidBuf::new`].
    #[inline]
    #[must_use]
    pub fn authority_bytes(&self) -> [u8; 6] {
        self.identifier_authority
    }

    /// Returns the sub-authority at `idx`, or `None` if it is out of bounds.
    #[inline]
    #[must_use]
    pub fn sub_authority(&self, idx: u8) -> Option<u32> {
        self.sub_authorities().get(idx as usize).copied()
    }

    /// Returns the SID's relative identifier (RID).
    ///
    /// A RID is the final sub-authority. Returns `None` when the SID has no
    /// sub-authorities.
    #[inline]
    #[must_use]
    pub fn rid(&self) -> Option<u32> {
        self.sub_authorities().last().copied()
    }

    /// Returns all of the SID's sub-authorities.
    #[inline]
    #[must_use]
    pub fn sub_authorities(&self) -> &[u32] {
        &self.sub_authority[..self.logical_sub_count()]
    }

    /// Tests whether this SID and `other` have equal prefixes.
    ///
    /// A SID prefix contains the revision, identifier authority, sub-authority
    /// count, and every sub-authority except the last.
    #[inline]
    #[must_use]
    pub fn equal_prefix(&self, other: &Sid) -> bool {
        self.revision == other.revision
            && self.identifier_authority == other.identifier_authority
            && self.sub_authority_count == other.sub_authority_count
            && match (
                self.sub_authorities().split_last(),
                other.sub_authorities().split_last(),
            ) {
                (Some((_, prefix1)), Some((_, prefix2))) => prefix1 == prefix2,
                (None, None) => true,
                _ => false,
            }
    }

    /// Tests whether this SID and `other` belong to the same Windows account
    /// domain.
    ///
    /// Calls the Windows `EqualDomainSid` function.
    ///
    /// Both SIDs must be account-domain SIDs or BUILTIN SIDs.
    ///
    /// # Errors
    ///
    /// Returns the error reported by `EqualDomainSid`.
    #[inline]
    pub fn equal_domain(&self, other: &Sid) -> Result<bool> {
        let mut equal = 0;
        // SAFETY: both pointers refer to valid SIDs and equal is a valid output pointer
        if unsafe {
            bindings::EqualDomainSid(
                self.as_ptr().cast_mut(),
                other.as_ptr().cast_mut(),
                &mut equal,
            )
        } == 0
        {
            return Err(Error::from_last_win32_error());
        }
        Ok(equal != 0)
    }

    /// Returns the Windows account-domain SID containing this SID.
    ///
    /// Calls the Windows `GetWindowsAccountDomainSid` function.
    ///
    /// # Errors
    ///
    /// Returns the error reported by `GetWindowsAccountDomainSid`.
    #[inline]
    pub fn account_domain_sid(&self) -> Result<SidBuf> {
        unsafe {
            let mut len = 0u32;
            if bindings::GetWindowsAccountDomainSid(
                self.as_ptr().cast_mut(),
                std::ptr::null_mut(),
                &mut len,
            ) == 0
            {
                let error = Error::from_last_win32_error();
                if error.win32_code() != bindings::ERROR_INSUFFICIENT_BUFFER {
                    return Err(error);
                }
            }

            let mut domain_sid = SidBuf::with_capacity(len as usize);
            if bindings::GetWindowsAccountDomainSid(
                self.as_ptr().cast_mut(),
                domain_sid.as_mut_ptr(),
                &mut len,
            ) == 0
            {
                return Err(Error::from_last_win32_error());
            }
            Ok(domain_sid)
        }
    }

    /// Tests whether this SID has the specified well-known SID type.
    ///
    /// Calls the Windows `IsWellKnownSid` function.
    #[inline]
    #[must_use]
    pub fn is_well_known(&self, well_known_type: impl AsWellKnownSidType) -> bool {
        let well_known_type = well_known_type.as_well_known_sid_type();
        // SAFETY: self supplies a valid SID pointer
        unsafe { bindings::IsWellKnownSid(self.as_ptr().cast_mut(), well_known_type.0) != 0 }
    }
}

impl ToOwned for Sid {
    type Owned = SidBuf;
    fn to_owned(&self) -> SidBuf {
        SidBuf::from_boxed_words(self.words().to_vec().into_boxed_slice())
    }
}

impl Eq for Sid {}

impl PartialEq for Sid {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Hash for Sid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.as_bytes());
    }
}

impl PartialOrd for Sid {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Sid {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.authority()
            .cmp(&other.authority())
            .then_with(|| self.sub_authorities().cmp(other.sub_authorities()))
    }
}

impl Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("S-1-")?;
        let authority = self.authority();
        if authority <= 0xFFFFFFFF {
            write!(f, "{}", authority)?;
        } else {
            // 12 byte hex display for authorities that don't fit in 8 bytes
            write!(f, "0x{:012X}", authority)?;
        }

        for sa in self.sub_authorities() {
            write!(f, "-{}", sa)?;
        }

        Ok(())
    }
}

impl Debug for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

/// An owned copy of a SID's bytes.
///
/// `SidBuf` dereferences to [`Sid`], so all borrowed-SID operations are
/// available directly on an owned value. Clone a `SidBuf` to duplicate its
/// bytes, or borrow it as `&Sid` without allocating.
pub struct SidBuf {
    sid: Box<Sid>,
}

impl Clone for SidBuf {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

/// The error returned when a string is not a valid SID.
///
/// Both [`SidBuf::from_str`](FromStr::from_str) and
/// [`SidBuf::from_string_sid`] report this error; see those functions for the
/// formats they accept. The [`From`] conversion to [`Error`] lets `?`
/// propagate a parse failure from a function returning [`Result`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SidParseError {
    kind: SidParseErrorKind,
}

/// The private detail behind [`SidParseError`], following the pattern of
/// [`std::num::ParseIntError`]. Kept private so the cases can be refined
/// without a breaking change; visible through `Debug` output only.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SidParseErrorKind {
    /// The string does not match the SID grammar.
    Invalid,
    /// The string contains an interior NUL byte, so it cannot be passed to
    /// Windows.
    InteriorNul,
    /// `ConvertStringSidToSid` rejected the string with this Win32 error code.
    Windows(u32),
}

impl SidParseError {
    fn invalid() -> Self {
        Self {
            kind: SidParseErrorKind::Invalid,
        }
    }
}

impl std::error::Error for SidParseError {}

impl Display for SidParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            SidParseErrorKind::Invalid => write!(f, "invalid SID string"),
            SidParseErrorKind::InteriorNul => {
                write!(f, "SID string contains an interior NUL byte")
            }
            SidParseErrorKind::Windows(code) => {
                write!(
                    f,
                    "invalid SID string: {}",
                    std::io::Error::from_raw_os_error(code as i32)
                )
            }
        }
    }
}

impl From<SidParseError> for Error {
    fn from(_: SidParseError) -> Error {
        Error::InvalidSid
    }
}

/// Parses a numeric SID string such as `S-1-5-32-544`.
///
/// The format is `S-1-<authority>` followed by zero to fifteen `-<sub-authority>`
/// components: the literal `S` (case-insensitive), the revision `1`, an
/// identifier authority of at most 48 bits in decimal or `0x`/`0X`-prefixed
/// hexadecimal, and decimal sub-authorities. Parsing is pure Rust and never
/// calls Windows; use [`SidBuf::from_string_sid`] for Windows-defined
/// aliases such as `BA`.
///
/// Every string produced by the [`Display`] implementation parses back to an
/// equal SID. The parser also accepts equivalent spellings that [`Display`]
/// never produces: a lowercase `s`, leading zeros, and hexadecimal
/// authorities small enough to be displayed in decimal. Signs, whitespace,
/// empty components, and non-ASCII digits are rejected.
///
/// # Examples
///
/// ```
/// use safe_sid::SidBuf;
///
/// let sid: SidBuf = "S-1-5-32-544".parse()?;
/// assert_eq!(sid.authority(), 5);
/// assert_eq!(sid.sub_authorities(), [32, 544]);
///
/// assert!("S-1-5-".parse::<SidBuf>().is_err());
/// assert!("BA".parse::<SidBuf>().is_err()); // aliases need from_string_sid
/// # Ok::<(), safe_sid::SidParseError>(())
/// ```
impl FromStr for SidBuf {
    type Err = SidParseError;

    /// Parses a numeric SID string.
    ///
    /// # Errors
    ///
    /// Returns [`SidParseError`] if the string does not match the format
    /// described [above](#impl-FromStr-for-SidBuf).
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut parts = s.split('-');

        // Leading "S", case-insensitive
        match parts.next() {
            Some(p) if p.eq_ignore_ascii_case("S") => {}
            _ => return Err(SidParseError::invalid()),
        }

        // Revision (only 1 is allowed)
        if parts.next() != Some("1") {
            return Err(SidParseError::invalid());
        }

        // Identifier authority: decimal or 0x-prefixed hex, 48 bits max
        let authority_str = parts.next().ok_or_else(SidParseError::invalid)?;
        let authority = match authority_str
            .strip_prefix("0x")
            .or_else(|| authority_str.strip_prefix("0X"))
        {
            Some(hex) if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
                u64::from_str_radix(hex, 16).map_err(|_| SidParseError::invalid())?
            }
            Some(_) => return Err(SidParseError::invalid()),
            None if !authority_str.is_empty()
                && authority_str.bytes().all(|b| b.is_ascii_digit()) =>
            {
                authority_str
                    .parse::<u64>()
                    .map_err(|_| SidParseError::invalid())?
            }
            None => return Err(SidParseError::invalid()),
        };
        // Remaining fields are decimal sub-authorities
        let sub_authorities = parts
            .map(|p| {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(SidParseError::invalid());
                }
                p.parse::<u32>().map_err(|_| SidParseError::invalid())
            })
            .collect::<std::result::Result<Vec<u32>, _>>()?;

        // new() rejects authorities over 48 bits and more than 15 sub-authorities
        SidBuf::new(authority, &sub_authorities).map_err(|_| SidParseError::invalid())
    }
}

impl SidBuf {
    /// Takes ownership of already-validated SID data as a `Box<Sid>`.
    ///
    /// `words` must be the two header words followed by the sub-authority words.
    fn from_boxed_words(words: Box<[u32]>) -> SidBuf {
        debug_assert!(
            words.len() >= SID_HEADER_WORDS,
            "a SID has at least the two header words"
        );
        let sub_count = words.len() - SID_HEADER_WORDS;
        // A DST pointer tracks only the trailing slice length. The input box is
        // entirely an array, while Sid has two header words before its slice,
        // so the pointer metadata excludes those header words.
        let data = Box::into_raw(words).cast::<u32>();
        let ptr = std::ptr::slice_from_raw_parts_mut(data, sub_count) as *mut Sid;
        // SAFETY: We are reboxing a pointer with the same alignment as the one it was detached from
        SidBuf {
            sid: unsafe { Box::from_raw(ptr) },
        }
    }

    /// Builds a SID from its identifier authority and sub-authorities.
    ///
    /// The authority may be one of the constants in [`authority`], the raw
    /// big-endian `[u8; 6]` form, or any primitive integer that fits in
    /// 48 bits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooManySubAuthorities`] if more than 15 sub-authorities
    /// are given, or [`Error::AuthorityOutOfRange`] if the authority cannot be
    /// represented in 48 bits.
    ///
    pub fn new(identifier_authority: impl IntoAuthority, sub_authorities: &[u32]) -> Result<Self> {
        let identifier_authority = identifier_authority.try_into_authority()?;
        let count = sub_authorities.len();
        if count > SID_MAX_SUB_AUTHORITIES as usize {
            return Err(Error::TooManySubAuthorities);
        }

        let mut words = vec![0u32; SID_HEADER_WORDS + count].into_boxed_slice();
        let sid = Sid::from_words_unchecked_mut(&mut words);
        sid.revision = SID_REVISION;
        sid.sub_authority_count = count as u8;
        sid.identifier_authority = identifier_authority;
        sid.sub_authority.copy_from_slice(sub_authorities);

        Ok(Self::from_boxed_words(words))
    }

    /// Copies a SID from its raw byte representation.
    ///
    /// The input does not need to be aligned. Its length must exactly match the
    /// sub-authority count recorded in the SID header; trailing capacity is not
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSid`] if the input is too short, has an
    /// unsupported revision or sub-authority count, or does not have the exact
    /// length required by its header.
    ///
    /// # Examples
    ///
    /// ```
    /// use safe_sid::SidBuf;
    ///
    /// let bytes = [
    ///     1, 2, 0, 0, 0, 0, 0, 5, // revision, count, NT authority
    ///     32, 0, 0, 0,             // BUILTIN
    ///     32, 2, 0, 0,             // Administrators
    /// ];
    /// let administrators = SidBuf::from_bytes(&bytes)?;
    /// assert_eq!(administrators.to_string(), "S-1-5-32-544");
    /// # Ok::<(), safe_sid::Error>(())
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<SidBuf> {
        let header_len = SID_HEADER_WORDS * size_of::<u32>();
        if bytes.len() < header_len || bytes[0] != SID_REVISION {
            return Err(Error::InvalidSid);
        }

        let count = bytes[1] as usize;
        if count > SID_MAX_SUB_AUTHORITIES as usize
            || bytes.len() != header_len + count * size_of::<u32>()
        {
            return Err(Error::InvalidSid);
        }

        let identifier_authority: [u8; 6] = bytes[2..header_len].try_into().unwrap();
        let sub_authorities = bytes[header_len..]
            .chunks_exact(size_of::<u32>())
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();

        SidBuf::new(identifier_authority, &sub_authorities)
    }

    /// Allocates a `SidBuf` of `len` bytes for a Windows API to fill.
    ///
    /// The buffer initially contains the null SID (`S-1-0-0`). `len` is the
    /// total requested size of the SID structure in bytes. It is rounded up to
    /// the next four-byte boundary, with a minimum allocation of 12 bytes.
    ///
    /// Extra capacity is not exposed by [`Sid::as_bytes`]; the logical length is
    /// determined by [`Sid::sub_authority_count`].
    #[must_use]
    pub fn with_capacity(len: usize) -> SidBuf {
        let word_len = len.div_ceil(size_of::<u32>()).max(SID_HEADER_WORDS + 1);

        let mut words = vec![0u32; word_len].into_boxed_slice();
        let sid = Sid::from_words_unchecked_mut(&mut words);
        sid.revision = SID_REVISION;
        sid.sub_authority_count = 1;

        SidBuf::from_boxed_words(words)
    }

    /// Returns a mutable pointer to this SID's bytes for a Windows API to fill.
    ///
    /// This is intended for the second call of Windows APIs that first report a
    /// required buffer length. Allocate that length with
    /// [`SidBuf::with_capacity`], then pass this pointer to the API.
    ///
    /// # Safety
    ///
    /// Writing through the pointer can leave the buffer holding bytes that are
    /// not a valid SID. The caller must not write past the length supplied to
    /// [`SidBuf::with_capacity`] and must leave a valid SID behind before
    /// accessing the buffer through `&Sid`. Dropping the buffer remains safe
    /// even if the API fails or writes malformed data.
    ///
    /// # Examples
    ///
    /// This example uses the standard two-call pattern to look up an account
    /// name. The first call obtains the two buffer lengths, and the second fills
    /// the allocated SID and domain-name buffers.
    ///
    /// ```no_run
    /// use safe_sid::SidBuf;
    /// use std::ffi::CStr;
    /// use windows::Win32::Security::{LookupAccountNameA, PSID, SID_NAME_USE};
    /// use windows::core::{HRESULT, PCSTR, PSTR, Result};
    ///
    /// fn lookup_account_name(name: &CStr) -> Result<SidBuf> {
    ///     let mut sid_use = SID_NAME_USE::default();
    ///     let mut sid_len = 0u32;
    ///     let mut domain_len = 0u32;
    ///
    ///     unsafe {
    ///         if let Err(error) = LookupAccountNameA(
    ///             PCSTR::null(),
    ///             PCSTR(name.as_ptr().cast()),
    ///             None,
    ///             &mut sid_len,
    ///             None,
    ///             &mut domain_len,
    ///             &mut sid_use,
    ///         ) && error.code() != HRESULT::from_win32(122) // ERROR_INSUFFICIENT_BUFFER
    ///         {
    ///             return Err(error);
    ///         }
    ///
    ///         let mut sid = SidBuf::with_capacity(sid_len as usize);
    ///         let mut domain = vec![0u8; domain_len as usize];
    ///         LookupAccountNameA(
    ///             PCSTR::null(),
    ///             PCSTR(name.as_ptr().cast()),
    ///             Some(PSID(sid.as_mut_ptr())),
    ///             &mut sid_len,
    ///             Some(PSTR(domain.as_mut_ptr())),
    ///             &mut domain_len,
    ///             &mut sid_use,
    ///         )?;
    ///         Ok(sid)
    ///     }
    /// }
    ///
    /// # let _ = lookup_account_name;
    /// ```
    #[must_use]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut c_void {
        let sid: &mut Sid = &mut self.sid;
        sid as *mut Sid as *mut c_void
    }

    /// Builds a well-known SID with `CreateWellKnownSid`.
    ///
    /// `domain_sid` is required for well-known types whose value depends on a
    /// Windows domain and should otherwise be `None`.
    ///
    /// # Errors
    ///
    /// Returns the error reported by `CreateWellKnownSid`.
    ///
    pub fn well_known(
        well_known_type: impl AsWellKnownSidType,
        domain_sid: Option<&Sid>,
    ) -> Result<SidBuf> {
        unsafe {
            let well_known_type = well_known_type.as_well_known_sid_type();
            let domain_psid = domain_sid
                .map(|sid| sid.as_ptr().cast_mut())
                .unwrap_or(std::ptr::null_mut());
            let mut len = 0u32;
            if bindings::CreateWellKnownSid(
                well_known_type.0,
                domain_psid,
                std::ptr::null_mut(),
                &mut len,
            ) == 0
            {
                let error = Error::from_last_win32_error();
                if error.win32_code() != bindings::ERROR_INSUFFICIENT_BUFFER {
                    return Err(error);
                }
            }

            let word_len = (len as usize)
                .div_ceil(size_of::<u32>())
                .max(SID_HEADER_WORDS);
            let mut words: Box<[u32]> = vec![0u32; word_len].into_boxed_slice();
            if bindings::CreateWellKnownSid(
                well_known_type.0,
                domain_psid,
                words.as_mut_ptr().cast(),
                &mut len,
            ) == 0
            {
                return Err(Error::from_last_win32_error());
            }

            Ok(SidBuf::from_boxed_words(words))
        }
    }

    /// Converts a string SID to a SID with `ConvertStringSidToSidA`.
    ///
    /// Unlike [`FromStr`], this accepts string constants such as `BA` and `AU`
    /// in addition to numeric SIDs. Windows performs the parsing and may clamp
    /// overflowing numeric components instead of rejecting them.
    ///
    /// String SIDs and their constants are ASCII. This method converts the
    /// input to a C string before passing it to the ANSI Windows API.
    ///
    /// # Errors
    ///
    /// Returns [`SidParseError`] if `s` contains an interior NUL byte or is
    /// rejected by `ConvertStringSidToSidA`.
    ///
    pub fn from_string_sid(s: &str) -> std::result::Result<SidBuf, SidParseError> {
        let s = std::ffi::CString::new(s).map_err(|_| SidParseError {
            kind: SidParseErrorKind::InteriorNul,
        })?;

        unsafe {
            let mut sid = std::ptr::null_mut();
            if bindings::ConvertStringSidToSidA(s.as_ptr().cast(), &mut sid) == 0 {
                return Err(SidParseError {
                    kind: SidParseErrorKind::Windows(bindings::GetLastError()),
                });
            }
            let res = SidBuf::from_psid(sid).map_err(|_| SidParseError::invalid());
            bindings::LocalFree(sid);
            res
        }
    }

    /// Validates and copies the SID pointed to by `psid` into an owned buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSid`] if the pointer does not reference a valid
    /// SID.
    ///
    /// # Safety
    ///
    /// `psid` must be non-null and point to a readable, 4-byte-aligned SID for
    /// the duration of this call. Its sub-authority count must accurately
    /// describe the allocation. The data is copied, so the pointer need not
    /// remain valid after this function returns.
    pub unsafe fn from_psid(psid: impl AsSidPtr) -> Result<Self> {
        // SAFETY: safety requirements noted to the caller in the doc comment
        let src = unsafe { Sid::from_psid(psid) }?;
        Ok(src.to_owned())
    }
}

impl Deref for SidBuf {
    type Target = Sid;
    #[inline]
    fn deref(&self) -> &Sid {
        &self.sid
    }
}

impl Borrow<Sid> for SidBuf {
    #[inline]
    fn borrow(&self) -> &Sid {
        self
    }
}

impl AsRef<Sid> for SidBuf {
    #[inline]
    fn as_ref(&self) -> &Sid {
        self
    }
}

impl Eq for SidBuf {}

impl PartialEq for SidBuf {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        (**self).eq(&**other)
    }
}

impl Hash for SidBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state);
    }
}

impl PartialOrd for SidBuf {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SidBuf {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        (**self).cmp(&**other)
    }
}

impl Display for SidBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&**self, f)
    }
}

impl Debug for SidBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&**self, f)
    }
}

impl Default for SidBuf {
    fn default() -> Self {
        SidBuf::new(authority::SECURITY_NULL_SID_AUTHORITY, &[0]).unwrap()
    }
}

impl PartialEq<SidBuf> for Sid {
    #[inline]
    fn eq(&self, other: &SidBuf) -> bool {
        self == &**other
    }
}

impl PartialEq<Sid> for SidBuf {
    #[inline]
    fn eq(&self, other: &Sid) -> bool {
        &**self == other
    }
}

impl PartialEq<&Sid> for SidBuf {
    #[inline]
    fn eq(&self, other: &&Sid) -> bool {
        &**self == *other
    }
}

impl PartialEq<SidBuf> for &Sid {
    #[inline]
    fn eq(&self, other: &SidBuf) -> bool {
        *self == &**other
    }
}

#[cfg(test)]
mod tests {
    use super::authority::*;
    use super::well_known::*;
    use super::*;

    fn nt_sid(sub_authorities: &[u32]) -> SidBuf {
        SidBuf::new(SECURITY_NT_AUTHORITY, sub_authorities).unwrap()
    }

    #[test]
    fn from_psid_rejects_invalid_headers() {
        for header in [[0, 0], [SID_REVISION, SID_MAX_SUB_AUTHORITIES + 1]] {
            let words = [u32::from_ne_bytes([header[0], header[1], 0, 0]), 0];
            let psid = words.as_ptr() as *const c_void;

            assert!(unsafe { Sid::from_psid(psid) }.is_err());
            assert!(unsafe { SidBuf::from_psid(psid) }.is_err());
        }
    }

    #[test]
    fn new_enforces_the_sub_authority_limit() {
        assert_eq!(
            SidBuf::new([0; 6], &[7; 15]).unwrap().sub_authority_count(),
            15
        );
        assert_eq!(
            SidBuf::new([0; 6], &[0; 16]).unwrap_err(),
            Error::TooManySubAuthorities
        );
    }

    #[test]
    fn from_bytes_copies_aligned_and_unaligned_sids() {
        let expected = nt_sid(&[32, 544]);
        let bytes = expected.as_bytes();

        assert_eq!(SidBuf::from_bytes(bytes).unwrap(), expected);

        let mut unaligned = vec![0xFF];
        unaligned.extend_from_slice(bytes);
        assert_eq!(SidBuf::from_bytes(&unaligned[1..]).unwrap(), expected);
    }

    #[test]
    fn from_bytes_validates_the_complete_structure() {
        let no_sub_authorities = [SID_REVISION, 0, 0, 0, 0, 0, 0, 5];
        assert_eq!(
            SidBuf::from_bytes(&no_sub_authorities)
                .unwrap()
                .sub_authorities(),
            &[]
        );

        let mut too_many_sub_authorities =
            vec![0; SID_HEADER_WORDS * size_of::<u32>() + 16 * size_of::<u32>()];
        too_many_sub_authorities[0] = SID_REVISION;
        too_many_sub_authorities[1] = SID_MAX_SUB_AUTHORITIES + 1;

        for bytes in [
            &[][..],
            &[0, 0, 0, 0, 0, 0, 0, 0],
            &[SID_REVISION, 1, 0, 0, 0, 0, 0, 5],
            &[SID_REVISION, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0],
            &too_many_sub_authorities,
        ] {
            assert_eq!(SidBuf::from_bytes(bytes).unwrap_err(), Error::InvalidSid);
        }
    }

    #[test]
    fn rid_returns_the_final_sub_authority() {
        assert_eq!(nt_sid(&[21, 1, 2, 3, 1000]).rid(), Some(1000));
        assert_eq!(SidBuf::new(5, &[]).unwrap().rid(), None);
    }

    #[test]
    fn new_accepts_every_authority_form() {
        let from_const = SidBuf::new(SECURITY_NT_AUTHORITY, &[18]).unwrap();
        // Each of these forms must keep compiling: the unsuffixed literal
        // resolves through the i32 fallback and the unsuffixed array through
        // the sole [u8; 6] impl
        let from_array = SidBuf::new([0, 0, 0, 0, 0, 5], &[18]).unwrap();
        let from_literal = SidBuf::new(5, &[18]).unwrap();
        let from_u8 = SidBuf::new(5u8, &[18]).unwrap();
        let from_u64 = SidBuf::new(5u64, &[18]).unwrap();
        let from_usize = SidBuf::new(5usize, &[18]).unwrap();
        let from_i128 = SidBuf::new(5i128, &[18]).unwrap();

        for sid in [
            from_array,
            from_literal,
            from_u8,
            from_u64,
            from_usize,
            from_i128,
        ] {
            assert_eq!(sid, from_const);
        }
    }

    #[test]
    fn new_enforces_the_authority_range() {
        assert_eq!(
            SidBuf::new(MAX_AUTHORITY, &[]).unwrap().authority(),
            MAX_AUTHORITY
        );

        for result in [
            SidBuf::new(-1, &[]),
            SidBuf::new(1u64 << 48, &[]),
            SidBuf::new(u128::MAX, &[]),
            SidBuf::new(i64::MIN, &[]),
        ] {
            assert_eq!(result.unwrap_err(), Error::AuthorityOutOfRange);
        }
    }

    #[test]
    fn authority_getters_round_trip_through_new() {
        let sid = nt_sid(&[32, 544]);
        assert_eq!(sid.authority(), 5);
        assert_eq!(sid.authority_bytes(), SECURITY_NT_AUTHORITY);
        assert_eq!(
            SidBuf::new(sid.authority(), sid.sub_authorities()).unwrap(),
            sid
        );

        let large = SidBuf::new(1u64 << 32, &[1]).unwrap();
        assert_eq!(large.authority_bytes(), [0, 1, 0, 0, 0, 0]);
        assert_eq!(
            SidBuf::new(large.authority_bytes(), large.sub_authorities()).unwrap(),
            large
        );
    }

    #[test]
    fn errors_map_to_win32_codes() {
        assert_eq!(Error::TooManySubAuthorities.win32_code(), ERROR_INVALID_SID);
        assert_eq!(Error::AuthorityOutOfRange.win32_code(), ERROR_INVALID_SID);
        assert_eq!(Error::InvalidSid.win32_code(), ERROR_INVALID_SID);
        assert_eq!(Error::Windows(5).win32_code(), 5);

        let io_error: std::io::Error = Error::Windows(5).into();
        assert_eq!(io_error.raw_os_error(), Some(5));

        assert_eq!(Error::from(SidParseError::invalid()), Error::InvalidSid);

        for error in [Error::TooManySubAuthorities, Error::Windows(5)] {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn well_known_sids_construct() {
        for (kind, expected) in [
            (WinNullSid, "S-1-0-0"),
            (WinLocalSystemSid, "S-1-5-18"),
            (WinBuiltinAdministratorsSid, "S-1-5-32-544"),
        ] {
            assert_eq!(
                SidBuf::well_known(kind, None).unwrap().to_string(),
                expected
            );
        }
    }

    #[test]
    fn new_builds_the_expected_sid() {
        let sid = nt_sid(&[32, 544]);

        assert_eq!(
            sid.as_bytes(),
            &[
                0x01, // revision
                0x02, // sub-authority count
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority, big-endian
                0x20, 0x00, 0x00, 0x00, // sub-authority #1, little-endian
                0x20, 0x02, 0x00, 0x00, // sub-authority #2, little-endian
            ]
        );
        assert_eq!(sid.revision(), SID_REVISION);
        assert_eq!(sid.sub_authority_count(), 2);
        assert_eq!(sid.authority(), 5);
        assert_eq!(sid.sub_authority(0), Some(32));
        assert_eq!(sid.sub_authority(1), Some(544));
        assert_eq!(sid.sub_authority(2), None);
        assert_eq!(sid.sub_authorities(), [32, 544]);
    }

    #[test]
    fn from_psid_borrows_or_copies_as_requested() {
        let copied = {
            let src = nt_sid(&[18]);
            let borrowed = unsafe { Sid::from_psid(src.as_ptr()) }.expect("valid SID");
            let copied = unsafe { SidBuf::from_psid(src.as_ptr()) }.expect("valid SID");

            assert_eq!(borrowed, &*src);
            assert_eq!(copied, src);
            copied
        };

        assert_eq!(copied.to_string(), "S-1-5-18");
    }

    #[test]
    fn with_capacity_separates_logical_length_from_buffer_length() {
        for (requested, allocated) in [(0, 12), (12, 12), (13, 16), (200, 200)] {
            let sid = SidBuf::with_capacity(requested);

            assert_eq!(sid.buffer_bytes().len(), allocated);
            assert_eq!(sid.as_bytes().len(), 12);
            assert_eq!(sid, SidBuf::default());
        }
    }

    #[test]
    fn as_mut_ptr_lets_a_caller_fill_the_buffer() {
        // Size a buffer for S-1-5-32-544, then fill it through the raw pointer the
        // way a Windows API would write into a caller-supplied buffer
        let admins = nt_sid(&[32, 544]);
        let mut buf = SidBuf::with_capacity(admins.as_bytes().len());

        unsafe {
            let dst = buf.as_mut_ptr() as *mut u8;
            std::ptr::copy_nonoverlapping(admins.as_bytes().as_ptr(), dst, admins.as_bytes().len());
        }

        assert_eq!(buf, admins);
    }

    #[test]
    fn value_traits_ignore_spare_buffer_capacity() {
        use std::collections::hash_map::DefaultHasher;

        let oversized = SidBuf::with_capacity(200);
        let null_sid = SidBuf::default();

        assert_eq!(oversized, null_sid);
        assert_eq!(oversized.as_bytes(), null_sid.as_bytes());
        assert_eq!(oversized.cmp(&null_sid), Ordering::Equal);

        let mut oversized_hash = DefaultHasher::new();
        oversized.hash(&mut oversized_hash);
        let mut null_hash = DefaultHasher::new();
        null_sid.hash(&mut null_hash);
        assert_eq!(oversized_hash.finish(), null_hash.finish());
    }

    #[test]
    fn owned_and_borrowed_views_agree() {
        let owned = nt_sid(&[18]);
        let via_deref: &Sid = &owned;
        let via_borrow: &Sid = owned.borrow();
        let via_as_ref: &Sid = owned.as_ref();

        assert_eq!(via_deref, via_borrow);
        assert_eq!(via_deref, via_as_ref);
        assert_eq!(via_deref.to_owned(), owned);
        assert_eq!(*via_deref, owned);
        assert_eq!(owned, *via_deref);
        assert_eq!(via_deref, owned);
        assert_eq!(owned, via_deref);

        let different = nt_sid(&[19]);
        assert_ne!(via_deref, different);
        assert_ne!(different, via_deref);
    }

    #[test]
    fn display_and_debug_render_canonical_strings() {
        let cases = [
            (SidBuf::default(), "S-1-0-0"),
            (nt_sid(&[18]), "S-1-5-18"),
            (nt_sid(&[32, 544]), "S-1-5-32-544"),
            (
                SidBuf::new([0, 0, 0xFF, 0xFF, 0xFF, 0xFF], &[1]).unwrap(),
                "S-1-4294967295-1",
            ),
            (
                SidBuf::new([0, 1, 0, 0, 0, 0], &[1, 2]).unwrap(),
                "S-1-0x000100000000-1-2",
            ),
        ];

        for (sid, expected) in cases {
            assert_eq!(sid.to_string(), expected);
            assert_eq!(format!("{sid:?}"), format!("{expected:?}"));
            assert_eq!(format!("{:?}", &*sid), format!("{expected:?}"));
        }
    }

    #[test]
    fn from_str_parses_and_round_trips_display() {
        // Display and parse are inverse of each-other for our SID, so ensure that they round-trip
        for s in [
            "S-1-0-0",
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-0x000100000000-1-2",
        ] {
            let sid: SidBuf = s.parse().unwrap();
            assert_eq!(sid.to_string(), s);
        }

        // Validate that both decimal and hex forms of the same SID are equal
        assert_eq!(
            "s-1-4294967296-1".parse::<SidBuf>().unwrap(),
            "S-1-0x000100000000-1".parse::<SidBuf>().unwrap(),
        );

        // A SID can have zero sub-authorities
        assert_eq!(
            "S-1-5".parse::<SidBuf>().unwrap().sub_authorities(),
            &[] as &[u32]
        );
    }

    #[test]
    fn from_str_rejects_malformed_input() {
        for s in [
            "",                                             // empty
            "X-1-5-18",                                     // wrong prefix
            "S-2-5-18",                                     // unsupported revision
            "S-1",                                          // missing authority
            "S-1-5-",                                       // trailing separator
            "S-1-+5-18",                                    // signed decimal authority
            "S-1-0x+5-18",                                  // signed hexadecimal authority
            "S-1-5-+18",                                    // signed sub-authority
            "S-1-5-4294967296",                             // sub-authority overflows u32
            "S-1-0x1000000000000-1",                        // authority overflows 48 bits
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16", // more than 15 sub-authorities
        ] {
            assert!(s.parse::<SidBuf>().is_err(), "parsing should reject {s:?}");
        }
    }

    #[test]
    fn equality_and_ordering_follow_sid_fields_numerically() {
        let a = nt_sid(&[18]);
        let b = nt_sid(&[18]);
        let c = nt_sid(&[19]);
        assert_eq!(a, b);
        assert_ne!(a, c);

        assert!(a < nt_sid(&[32, 544]));
        assert!(nt_sid(&[1]) < nt_sid(&[256]));
        assert!(nt_sid(&[21, 1]) < nt_sid(&[21, 1, 1]));

        let lower_authority = SidBuf::new(4, &[u32::MAX, u32::MAX]).unwrap();
        let higher_authority = SidBuf::new(5, &[0]).unwrap();
        assert!(lower_authority < higher_authority);
    }

    #[test]
    fn equal_prefix_ignores_only_the_last_sub_authority() {
        let first = nt_sid(&[21, 1, 2, 3, 1000]);
        let same_prefix = nt_sid(&[21, 1, 2, 3, 2000]);
        let different_prefix = nt_sid(&[21, 1, 2, 4, 1000]);
        let different_count = nt_sid(&[21, 1, 2, 3]);
        let different_authority = SidBuf::new([0, 0, 0, 0, 0, 4], &[21, 1, 2, 3, 2000]).unwrap();

        assert!(first.equal_prefix(&same_prefix));
        assert!(!first.equal_prefix(&different_prefix));
        assert!(!first.equal_prefix(&different_count));
        assert!(!first.equal_prefix(&different_authority));

        let no_sub_authorities = SidBuf::new(SECURITY_NT_AUTHORITY, &[]).unwrap();
        assert!(no_sub_authorities.equal_prefix(&no_sub_authorities));
    }

    #[test]
    fn windows_domain_helpers_compare_and_extract_domains() {
        let first = nt_sid(&[21, 1, 2, 3, 1000]);
        let same_domain = nt_sid(&[21, 1, 2, 3, 2000]);
        let different_domain = nt_sid(&[21, 1, 2, 4, 1000]);
        let expected_domain = nt_sid(&[21, 1, 2, 3]);

        assert!(first.equal_domain(&same_domain).unwrap());
        assert!(!first.equal_domain(&different_domain).unwrap());
        assert_eq!(first.account_domain_sid().unwrap(), expected_domain);
    }

    #[test]
    fn well_known_sid_helper_classifies_sids() {
        let local_system = nt_sid(&[18]);
        assert!(local_system.is_well_known(WinLocalSystemSid));
        assert!(!local_system.is_well_known(WinWorldSid));
    }

    #[test]
    fn borrowed_sid_looks_up_owned_key() {
        use std::collections::HashMap;

        let mut map = HashMap::new();
        map.insert(nt_sid(&[18]), "LocalSystem");

        let key = nt_sid(&[18]);
        let probe: &Sid = &key;
        assert_eq!(map.get(probe), Some(&"LocalSystem"));
    }

    #[test]
    fn from_string_sid_supports_numeric_and_aliases() {
        let ba = nt_sid(&[32, 544]);
        assert_eq!(SidBuf::from_string_sid("BA").unwrap(), ba);
        assert_eq!(SidBuf::from_string_sid("S-1-5-32-544").unwrap(), ba);
    }

    #[test]
    fn from_string_sid_fails_on_bad_input() {
        assert!(matches!(
            SidBuf::from_string_sid("").unwrap_err().kind,
            SidParseErrorKind::Windows(_)
        ));
        assert!(SidBuf::from_string_sid("not-a-sid").is_err());
        assert!(matches!(
            SidBuf::from_string_sid("BA\0").unwrap_err().kind,
            SidParseErrorKind::InteriorNul
        ));
    }
}
