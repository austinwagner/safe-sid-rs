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
//! Build a SID from its six-byte identifier authority and its sub-authorities:
//!
//! ```
//! use safe_sid::SidBuf;
//!
//! // S-1-5-32-544 is the BUILTIN\Administrators SID.
//! let administrators = SidBuf::new([0, 0, 0, 0, 0, 5], &[32, 544])?;
//! assert_eq!(administrators.to_string(), "S-1-5-32-544");
//! # Ok::<(), safe_sid::Error>(())
//! ```
//!
//! Or ask Windows to create a [well-known SID](well_known):
//!
//! ```
//! use safe_sid::{SidBuf, WinLocalSystemSid};
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
//! # Ok::<(), safe_sid::ParseError>(())
//! ```
//!
//! [`SidBuf::from_cstr_with_alias`] additionally accepts Windows aliases such
//! as `BA` (BUILTIN\Administrators).
//!
//! # Windows API interoperability
//!
//! This crate does not depend on the `windows` crate. [`Sid::as_ptr`] and
//! [`Sid::from_psid`] use raw `c_void` pointers so applications can choose
//! their own Windows bindings and versions.
//!
//! An application using the `windows` crate can wrap the raw pointer at the
//! call site:
//!
//! ```toml
//! [dependencies]
//! safe-sid = "0.2"
//! windows = { version = "0.62", features = ["Win32_Security"] }
//! ```
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

#[allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code,
    clippy::all
)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code,
    clippy::all
)]
/// Constants for the SID types accepted by [`SidBuf::well_known`] and
/// [`Sid::is_well_known`].
///
/// The names and values correspond to Windows'
/// `WELL_KNOWN_SID_TYPE` enumeration.
pub mod well_known {
    include!(concat!(env!("OUT_DIR"), "/well_known.rs"));
}

#[doc(no_inline)]
pub use well_known::*;

const SID_REVISION: u8 = 1;
const SID_MAX_SUB_AUTHORITIES: u8 = 15;
const SID_HEADER_WORDS: usize = 2;
const ERROR_INVALID_SID: u32 = 0x0539;

/// An error reported while creating, validating, or querying a SID.
///
/// The contained value is a Win32 error code, available through [`Error::code`].
/// This type is owned by `safe-sid`, so it remains stable independently of the
/// version of `windows-core` used by an application.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct Error {
    code: u32,
}

impl Error {
    /// Creates an error from a Win32 error code.
    pub const fn from_win32(code: u32) -> Self {
        Self { code }
    }

    /// Returns the underlying Win32 error code.
    pub const fn code(&self) -> u32 {
        self.code
    }

    /// Captures the calling thread's last-error code.
    fn from_thread() -> Self {
        // SAFETY: GetLastError has no preconditions.
        Self::from_win32(unsafe { bindings::GetLastError() })
    }
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&std::io::Error::from_raw_os_error(self.code as i32), f)
    }
}

/// A result returned by fallible `safe-sid` operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Creates an error representing `ERROR_INVALID_SID`.
fn invalid_sid_err() -> Error {
    Error::from_win32(ERROR_INVALID_SID)
}

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
/// The crate's constants, such as [`WinLocalSystemSid`], implement this trait.
pub trait AsWellKnownSidType {
    /// Returns the numeric `WELL_KNOWN_SID_TYPE` value.
    fn as_well_known_sid_type(&self) -> WELL_KNOWN_SID_TYPE;
}

impl AsWellKnownSidType for WELL_KNOWN_SID_TYPE {
    fn as_well_known_sid_type(&self) -> WELL_KNOWN_SID_TYPE {
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

    /// The number of sub-authorities, limited by the capacity of the actual buffer so we
    /// can prevent out-of-bounds reads.
    #[inline]
    fn logical_sub_count(&self) -> usize {
        (self.sub_authority_count as usize).min(self.sub_authority.len())
    }

    /// The SID's words, independent of any extra buffer capacity
    /// (see [`with_capacity`](SidBuf::with_capacity)).
    #[inline]
    fn words(&self) -> &[u32] {
        // SAFETY: logical_sub_count() is limited to our actual buffer size, so
        // even if  sub_authority_count is oversized, it won't return a buffer
        // that can allow out-of-bounds reads
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
    pub fn as_ptr(&self) -> *const c_void {
        self as *const Sid as *const c_void
    }

    /// Borrow a raw `PSID` as `&'a Sid`, validating its structure.
    ///
    /// Returns `ERROR_INVALID_SID` if `psid` is not a valid SID.
    ///
    /// # Safety
    ///
    /// `psid` must point to a readable SID that stays valid for `'a`. It must also be 4-byte
    /// aligned since the words are borrowed as `&[u32]`. The sub-authority count must be accurate
    /// to prevent out-of-bounds reads. Every SID Windows hands out is already aligned with a correct
    /// count.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_INVALID_SID` if the revision or sub-authority count is
    /// outside the range allowed by Windows.
    pub unsafe fn from_psid<'a>(psid: impl AsSidPtr) -> Result<&'a Sid> {
        let psid = psid.as_sid_ptr();

        // SAFETY: the safety rules stated to the caller apply here
        let p = psid as *const u8;
        let (revision, sub_count) = unsafe { (*p, *p.add(1)) };
        if revision != SID_REVISION || sub_count > SID_MAX_SUB_AUTHORITIES {
            return Err(invalid_sid_err());
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
    pub fn revision(&self) -> u8 {
        self.revision
    }

    /// Returns the number of sub-authorities recorded in the SID header.
    #[inline]
    pub fn sub_authority_count(&self) -> u8 {
        self.sub_authority_count
    }

    /// Returns the 48-bit identifier authority as an integer.
    #[inline]
    pub fn authority(&self) -> u64 {
        let [a0, a1, a2, a3, a4, a5] = self.identifier_authority;
        u64::from_be_bytes([0, 0, a0, a1, a2, a3, a4, a5])
    }

    /// Returns the sub-authority at `idx`, or `None` if it is out of bounds.
    #[inline]
    pub fn sub_authority(&self, idx: u8) -> Option<u32> {
        self.sub_authorities().get(idx as usize).copied()
    }

    /// Returns all of the SID's sub-authorities.
    #[inline]
    pub fn sub_authorities(&self) -> &[u32] {
        &self.sub_authority[..self.logical_sub_count()]
    }

    /// Tests whether this SID and `other` have equal prefixes.
    ///
    /// A SID prefix contains the revision, identifier authority, sub-authority
    /// count, and every sub-authority except the last.
    #[inline]
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

    /// Determines whether this SID and `other` belong to the same Windows account domain.
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
            return Err(Error::from_thread());
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
                let error = Error::from_thread();
                if error.code() != bindings::ERROR_INSUFFICIENT_BUFFER {
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
                return Err(Error::from_thread());
            }
            Ok(domain_sid)
        }
    }

    /// Tests whether this SID has the specified well-known SID type.
    ///
    /// Calls the Windows `IsWellKnownSid` function.
    #[inline]
    pub fn is_well_known(&self, well_known_type: impl AsWellKnownSidType) -> bool {
        // SAFETY: self supplies a valid SID pointer
        unsafe {
            bindings::IsWellKnownSid(
                self.as_ptr().cast_mut(),
                well_known_type.as_well_known_sid_type(),
            ) != 0
        }
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
        self.as_bytes().cmp(other.as_bytes())
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
///
/// # Examples
///
/// ```
/// use safe_sid::{Sid, SidBuf};
///
/// let owned: SidBuf = "S-1-5-18".parse()?;
/// let borrowed: &Sid = &owned;
///
/// assert_eq!(borrowed.to_string(), "S-1-5-18");
/// assert_eq!(borrowed.to_owned(), owned);
/// # Ok::<(), safe_sid::ParseError>(())
/// ```
pub struct SidBuf {
    sid: Box<Sid>,
}

impl Clone for SidBuf {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

#[derive(Debug)]
/// The error returned when a string is not a valid numeric SID.
///
/// See [`SidBuf::from_str`](FromStr::from_str) for the accepted format.
pub struct ParseError;

impl std::error::Error for ParseError {}
impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid SID string")
    }
}

impl FromStr for SidBuf {
    type Err = ParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut parts = s.split('-');

        // Leading "S", case-insensitive
        match parts.next() {
            Some(p) if p.eq_ignore_ascii_case("S") => {}
            _ => return Err(ParseError),
        }

        // Revision (only 1 is allowed)
        if parts.next() != Some("1") {
            return Err(ParseError);
        }

        // Identifier authority: decimal or 0x-prefixed hex, 48 bits max
        let authority_str = parts.next().ok_or(ParseError)?;
        let authority = match authority_str
            .strip_prefix("0x")
            .or_else(|| authority_str.strip_prefix("0X"))
        {
            Some(hex) => u64::from_str_radix(hex, 16).map_err(|_| ParseError)?,
            None => authority_str.parse::<u64>().map_err(|_| ParseError)?,
        };
        if authority > 0xFFFF_FFFF_FFFF {
            return Err(ParseError);
        }
        let identifier_authority: [u8; 6] = authority.to_be_bytes()[2..].try_into().unwrap();

        // Remaining fields are decimal sub-authorities
        let sub_authorities = parts
            .map(|p| p.parse::<u32>())
            .collect::<std::result::Result<Vec<u32>, _>>()
            .map_err(|_| ParseError)?;

        SidBuf::new(identifier_authority, &sub_authorities).map_err(|_| ParseError)
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
        // A DST only tracks the size of the array. Our input box is entirely an array while our
        // Sid struct has 2 words before the array. When creating a Sid pointer from the u64 slice
        // we have to account for that by subtracting off the header.
        let data = Box::into_raw(words).cast::<u32>();
        let ptr = std::ptr::slice_from_raw_parts_mut(data, sub_count) as *mut Sid;
        // SAFETY: We are reboxing a pointer with the same alignment as the one it was detached from
        SidBuf {
            sid: unsafe { Box::from_raw(ptr) },
        }
    }

    /// Builds a SID from its identifier authority and sub-authorities.
    ///
    /// Returns `ERROR_INVALID_SID` if more than 15 sub-authorities are given.
    ///
    /// # Examples
    ///
    /// ```
    /// use safe_sid::SidBuf;
    ///
    /// let administrators = SidBuf::new([0, 0, 0, 0, 0, 5], &[32, 544])?;
    /// assert_eq!(administrators.to_string(), "S-1-5-32-544");
    /// # Ok::<(), safe_sid::Error>(())
    /// ```
    pub fn new(identifier_authority: [u8; 6], sub_authorities: &[u32]) -> Result<Self> {
        let count = sub_authorities.len();
        if count > SID_MAX_SUB_AUTHORITIES as usize {
            return Err(invalid_sid_err());
        }

        let mut words = vec![0u32; SID_HEADER_WORDS + count].into_boxed_slice();
        let sid = Sid::from_words_unchecked_mut(&mut words);
        sid.revision = SID_REVISION;
        sid.sub_authority_count = count as u8;
        sid.identifier_authority = identifier_authority;
        sid.sub_authority.copy_from_slice(sub_authorities);

        Ok(Self::from_boxed_words(words))
    }

    /// Allocates a `SidBuf` of `len` bytes for a Windows API to fill.
    ///
    /// The buffer initially contains the null SID (`S-1-0-0`). `len` is the
    /// total requested size of the SID structure in bytes. It is rounded up to
    /// the next four-byte boundary, with a minimum allocation of 12 bytes.
    ///
    /// Extra capacity is not exposed by [`Sid::as_bytes`]; the logical length is
    /// determined by [`Sid::sub_authority_count`].
    pub fn with_capacity(len: usize) -> SidBuf {
        let word_len = len.div_ceil(size_of::<u32>()).max(SID_HEADER_WORDS + 1);

        let mut words = vec![0u32; word_len].into_boxed_slice();
        let sid = Sid::from_words_unchecked_mut(&mut words);
        sid.revision = SID_REVISION;
        sid.sub_authority_count = 1;

        SidBuf::from_boxed_words(words)
    }

    /// Returns a mutable pointer to this SID's bytes, for passing to a Windows API that
    /// fills a caller-supplied buffer.
    ///
    /// This is intended for the second call of Windows APIs that first report a
    /// required buffer length. Allocate that length with
    /// [`SidBuf::with_capacity`], then pass this pointer to the API.
    ///
    /// # Safety
    ///
    /// Writing through the pointer can leave the buffer holding bytes that are not
    /// a valid SID. The caller must not write past the length supplied to
    /// [`SidBuf::with_capacity`] and must leave a valid SID behind before the
    /// buffer is read through `&Sid`. Dropping the buffer remains safe even if
    /// the API fails or writes malformed data.
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
    /// # Examples
    ///
    /// ```
    /// use safe_sid::{SidBuf, WinLocalSystemSid};
    ///
    /// let local_system = SidBuf::well_known(WinLocalSystemSid, None)?;
    /// assert_eq!(local_system.to_string(), "S-1-5-18");
    /// # Ok::<(), safe_sid::Error>(())
    /// ```
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
                well_known_type,
                domain_psid,
                std::ptr::null_mut(),
                &mut len,
            ) == 0
            {
                let error = Error::from_thread();
                if error.code() != bindings::ERROR_INSUFFICIENT_BUFFER {
                    return Err(error);
                }
            }

            let word_len = (len as usize).div_ceil(size_of::<u32>());
            let mut words: Box<[u32]> = vec![0u32; word_len].into_boxed_slice();
            if bindings::CreateWellKnownSid(
                well_known_type,
                domain_psid,
                words.as_mut_ptr().cast(),
                &mut len,
            ) == 0
            {
                return Err(Error::from_thread());
            }

            Ok(SidBuf::from_boxed_words(words))
        }
    }

    /// Converts a C string to a SID with `ConvertStringSidToSidA`.
    ///
    /// Unlike [`FromStr`], this accepts string constants such as `BA` and `AU`
    /// in addition to numeric SIDs. Windows performs the parsing and may clamp
    /// overflowing numeric components instead of rejecting them.
    ///
    /// # Errors
    ///
    /// Returns the error reported by `ConvertStringSidToSidA`.
    ///
    /// # Examples
    ///
    /// ```
    /// use safe_sid::SidBuf;
    ///
    /// let administrators = SidBuf::from_cstr_with_alias(c"BA")?;
    /// assert_eq!(administrators.to_string(), "S-1-5-32-544");
    /// # Ok::<(), safe_sid::Error>(())
    /// ```
    pub fn from_cstr_with_alias(s: &std::ffi::CStr) -> Result<SidBuf> {
        unsafe {
            let mut sid = std::ptr::null_mut();
            if bindings::ConvertStringSidToSidA(s.as_ptr().cast(), &mut sid) == 0 {
                return Err(Error::from_thread());
            }
            let res = SidBuf::from_psid(sid);
            bindings::LocalFree(sid);
            res
        }
    }

    /// Validates and copies the SID pointed to by `psid` into an owned buffer.
    ///
    /// Returns `ERROR_INVALID_SID` if the pointer does not reference a valid SID.
    ///
    /// # Safety
    ///
    /// `psid` must point to a 4-byte-aligned SID structure valid for the duration of this
    /// call. The data is copied so there is no lifetime requirement for `psid` after this returns.
    ///
    /// # Examples
    ///
    /// ```
    /// use safe_sid::{Sid, SidBuf};
    ///
    /// let source: SidBuf = "S-1-5-18".parse().unwrap();
    ///
    /// let borrowed: &Sid = unsafe { Sid::from_psid(source.as_ptr())? };
    /// let copied = unsafe { SidBuf::from_psid(source.as_ptr())? };
    ///
    /// assert_eq!(borrowed, &*source);
    /// assert_eq!(copied, source);
    /// # Ok::<(), safe_sid::Error>(())
    /// ```
    pub unsafe fn from_psid(psid: impl AsSidPtr) -> Result<Self> {
        // SAFETY: safety requirements noted to called in the doc comment
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
        SidBuf::new([0, 0, 0, 0, 0, 0], &[0]).unwrap()
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

#[cfg(test)]
mod tests {
    use super::*;

    const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

    fn nt_sid(sub_authorities: &[u32]) -> SidBuf {
        SidBuf::new(NT_AUTHORITY, sub_authorities).unwrap()
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
            SidBuf::new([0; 6], &[0; 16]).unwrap_err().code(),
            ERROR_INVALID_SID
        );
    }

    #[test]
    fn error_exposes_its_win32_code() {
        let error = Error::from_win32(ERROR_INVALID_SID);

        assert_eq!(error.code(), ERROR_INVALID_SID);
        assert!(!error.to_string().is_empty());
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
            "S-1-5-4294967296",                             // sub-authority overflows u32
            "S-1-0x1000000000000-1",                        // authority overflows 48 bits
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16", // more than 15 sub-authorities
        ] {
            assert!(s.parse::<SidBuf>().is_err(), "parsing should reject {s:?}");
        }
    }

    #[test]
    fn equality_and_ordering_follow_sid_bytes() {
        let a = nt_sid(&[18]);
        let b = nt_sid(&[18]);
        let c = nt_sid(&[19]);
        assert_eq!(a, b);
        assert_ne!(a, c);

        assert!(a < nt_sid(&[32, 544]));
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

        let no_sub_authorities = SidBuf::new(NT_AUTHORITY, &[]).unwrap();
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
    fn from_cstr_supports_numeric_and_aliases() {
        let ba = nt_sid(&[32, 544]);
        assert_eq!(SidBuf::from_cstr_with_alias(c"BA").unwrap(), ba);
        assert_eq!(SidBuf::from_cstr_with_alias(c"S-1-5-32-544").unwrap(), ba);
    }

    #[test]
    fn from_cstr_fails_on_bad_input() {
        assert!(SidBuf::from_cstr_with_alias(c"").is_err());
        assert!(SidBuf::from_cstr_with_alias(c"not-a-sid").is_err());
    }
}
