//! Deterministic length-prefixed binary encoding (ADR-0007).
//!
//! Rules (every value has exactly one encoding):
//!
//! * A document starts with a 4-byte kind tag and a big-endian `u16` format version.
//! * Integers are fixed-width big-endian (`u8`, `u16`, `u32`, `u64`). There are no varints.
//! * Booleans are one byte, `0` or `1`; anything else is rejected.
//! * Fixed-size byte arrays are written raw.
//! * Variable byte strings and UTF-8 strings are a `u32` length then the bytes; strings are capped
//!   at [`MAX_STR_LEN`] bytes.
//! * Sets and maps are a `u32` count then entries in strictly ascending byte order of their keys;
//!   unsorted or duplicate entries are rejected.
//! * Fields appear in a fixed order with no optional fields; trailing bytes are rejected.
//!
//! Decoders built on [`Decoder`] are additionally checked by re-encoding and comparing bytes, so a
//! successful parse always means the input was the canonical encoding.

use std::collections::BTreeSet;
use std::fmt;

/// Longest accepted string, in bytes.
pub const MAX_STR_LEN: usize = 4096;

/// Domain-separation tags prepended to canonical bytes before signing, so a signature over one
/// kind of document can never be replayed as another.
pub mod domain {
    /// Issuing-key certificate (signed by the root key).
    pub const ISSUING_CERT: &[u8] = b"arkhon/v1/issuing-certificate\0";
    /// Issuing-key revocation list (signed by the root key).
    pub const REVOCATION_LIST: &[u8] = b"arkhon/v1/revocation-list\0";
    /// License (signed by an issuing key).
    pub const LICENSE: &[u8] = b"arkhon/v1/license\0";
    /// Release manifest (signed by an issuing key).
    pub const RELEASE_MANIFEST: &[u8] = b"arkhon/v1/release-manifest\0";
}

/// Why a byte string could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The data is for a different kind of document.
    WrongKind,
    /// The format version is not one this build understands.
    UnsupportedVersion(u16),
    /// The data ends early.
    Truncated,
    /// Extra bytes follow the document.
    TrailingBytes,
    /// A string is not valid UTF-8.
    InvalidUtf8,
    /// A string is longer than [`MAX_STR_LEN`].
    TooLong,
    /// Set or map entries are not in strictly ascending order (or are duplicated).
    NotSorted,
    /// A field holds a value that is not allowed (named).
    InvalidValue(&'static str),
    /// The bytes decode but are not the canonical encoding.
    NonCanonical,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::WrongKind => f.write_str("This file is not the expected kind of Arkhon file."),
            DecodeError::UnsupportedVersion(v) => write!(
                f,
                "This file uses format version {v}, which this version of Arkhon doesn't understand. Update Arkhon and try again."
            ),
            DecodeError::Truncated => f.write_str("This file is incomplete. Download it again."),
            DecodeError::TrailingBytes
            | DecodeError::InvalidUtf8
            | DecodeError::TooLong
            | DecodeError::NotSorted
            | DecodeError::NonCanonical => {
                f.write_str("This file is damaged or has been changed. Download it again.")
            }
            DecodeError::InvalidValue(field) => write!(
                f,
                "This file is damaged or has been changed (bad \"{field}\"). Download it again."
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Writes canonical bytes. Infallible: the encoder only ever produces canonical output, so callers
/// must pass sets/maps as sorted collections (`BTreeSet`/`BTreeMap`) and strings within limits
/// (checked by the matching decoder and by each type's validation).
#[derive(Debug, Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Start a document of `kind` at format `version`.
    #[must_use]
    pub fn new(kind: [u8; 4], version: u16) -> Self {
        let mut e = Self { buf: Vec::new() };
        e.array(&kind);
        e.u16(version);
        e
    }

    /// Start a nested value with no kind header.
    #[must_use]
    pub fn bare() -> Self {
        Self::default()
    }

    /// Append one byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Append a boolean as `0`/`1`.
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    /// Append a big-endian `u16`.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a big-endian `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a big-endian `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append fixed-size bytes with no length prefix.
    pub fn array(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Append a length (`u32`) for a collection or byte string.
    ///
    /// # Panics
    /// If `len` exceeds `u32::MAX` (impossible for any valid document).
    pub fn len(&mut self, len: usize) -> &mut Self {
        self.u32(u32::try_from(len).expect("collection longer than u32::MAX"))
    }

    /// Append a `u32` length then the bytes.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.len(v.len());
        self.array(v)
    }

    /// Append a UTF-8 string (`u32` length then bytes).
    pub fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    /// Append a set of strings (already in ascending order because it is a `BTreeSet`).
    pub fn str_set(&mut self, set: &BTreeSet<String>) -> &mut Self {
        self.len(set.len());
        for s in set {
            self.str(s);
        }
        self
    }

    /// Bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Finish and return the bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Reads canonical bytes, rejecting anything non-canonical it can see locally.
#[derive(Debug)]
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Start reading a document, checking its kind and version.
    ///
    /// # Errors
    /// [`DecodeError::WrongKind`], [`DecodeError::UnsupportedVersion`] or
    /// [`DecodeError::Truncated`].
    pub fn new(data: &'a [u8], kind: [u8; 4], version: u16) -> Result<Self, DecodeError> {
        let mut d = Self::bare(data);
        if d.array::<4>()? != kind {
            return Err(DecodeError::WrongKind);
        }
        let v = d.u16()?;
        if v != version {
            return Err(DecodeError::UnsupportedVersion(v));
        }
        Ok(d)
    }

    /// Read nested data with no kind header.
    #[must_use]
    pub fn bare(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes not yet read.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Take the next `n` bytes.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`] if fewer than `n` remain.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(DecodeError::Truncated);
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Read a fixed-size array.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`].
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Read one byte.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`].
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    /// Read a boolean (`0` or `1` only).
    ///
    /// # Errors
    /// [`DecodeError::Truncated`] or [`DecodeError::InvalidValue`].
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::InvalidValue("boolean")),
        }
    }

    /// Read a big-endian `u16`.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`].
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// Read a big-endian `u32`.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`].
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Read a big-endian `u64`.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`].
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// Read a `u32` length/count, checked against the bytes left (each entry takes at least
    /// `min_entry_len` bytes), so a hostile count can never cause a huge allocation.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`].
    pub fn len(&mut self, min_entry_len: usize) -> Result<usize, DecodeError> {
        let n = usize::try_from(self.u32()?).map_err(|_| DecodeError::Truncated)?;
        if n.saturating_mul(min_entry_len.max(1)) > self.remaining() {
            return Err(DecodeError::Truncated);
        }
        Ok(n)
    }

    /// Read a `u32`-length-prefixed byte string.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`].
    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.len(1)?;
        self.take(n)
    }

    /// Read a UTF-8 string of at most [`MAX_STR_LEN`] bytes.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`], [`DecodeError::TooLong`] or [`DecodeError::InvalidUtf8`].
    pub fn str(&mut self) -> Result<&'a str, DecodeError> {
        let raw = self.bytes()?;
        if raw.len() > MAX_STR_LEN {
            return Err(DecodeError::TooLong);
        }
        std::str::from_utf8(raw).map_err(|_| DecodeError::InvalidUtf8)
    }

    /// Read an owned string.
    ///
    /// # Errors
    /// As [`Decoder::str`].
    pub fn string(&mut self) -> Result<String, DecodeError> {
        self.str().map(str::to_owned)
    }

    /// Read a set of strings in strictly ascending order.
    ///
    /// # Errors
    /// As [`Decoder::str`], plus [`DecodeError::NotSorted`].
    pub fn str_set(&mut self) -> Result<BTreeSet<String>, DecodeError> {
        let n = self.len(4)?;
        let mut out = BTreeSet::new();
        let mut prev: Option<&str> = None;
        for _ in 0..n {
            let s = self.str()?;
            if prev.is_some_and(|p| p >= s) {
                return Err(DecodeError::NotSorted);
            }
            prev = Some(s);
            out.insert(s.to_owned());
        }
        Ok(out)
    }

    /// Require that every byte was consumed.
    ///
    /// # Errors
    /// [`DecodeError::TrailingBytes`].
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

/// Final guard for decoders: `reencoded` must equal `input` byte for byte.
///
/// # Errors
/// [`DecodeError::NonCanonical`].
pub fn require_canonical(input: &[u8], reencoded: &[u8]) -> Result<(), DecodeError> {
    if input == reencoded {
        Ok(())
    } else {
        Err(DecodeError::NonCanonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIND: [u8; 4] = *b"TEST";

    fn sample() -> Vec<u8> {
        let set: BTreeSet<String> = ["a", "b", "zz"].iter().map(|s| (*s).to_owned()).collect();
        let mut e = Encoder::new(KIND, 1);
        e.u8(7)
            .bool(true)
            .u16(0x1234)
            .u32(5)
            .u64(u64::MAX)
            .array(&[1, 2])
            .bytes(b"xyz")
            .str("héllo")
            .str_set(&set);
        assert_ne!(e.as_bytes().len(), 0);
        e.finish()
    }

    #[test]
    fn round_trip() {
        let data = sample();
        let mut d = Decoder::new(&data, KIND, 1).unwrap();
        assert_eq!(d.u8().unwrap(), 7);
        assert!(d.bool().unwrap());
        assert_eq!(d.u16().unwrap(), 0x1234);
        assert_eq!(d.u32().unwrap(), 5);
        assert_eq!(d.u64().unwrap(), u64::MAX);
        assert_eq!(d.array::<2>().unwrap(), [1, 2]);
        assert_eq!(d.bytes().unwrap(), b"xyz");
        assert_eq!(d.string().unwrap(), "héllo");
        assert_eq!(d.str_set().unwrap().len(), 3);
        d.finish().unwrap();
    }

    #[test]
    fn rejects_wrong_kind_version_and_truncation() {
        let data = sample();
        assert_eq!(
            Decoder::new(&data, *b"NOPE", 1).unwrap_err(),
            DecodeError::WrongKind
        );
        assert_eq!(
            Decoder::new(&data, KIND, 2).unwrap_err(),
            DecodeError::UnsupportedVersion(1)
        );
        assert_eq!(
            Decoder::new(&data[..3], KIND, 1).unwrap_err(),
            DecodeError::Truncated
        );
        let mut d = Decoder::bare(&[0, 0, 0, 9, 1]);
        assert_eq!(d.bytes().unwrap_err(), DecodeError::Truncated);
    }

    #[test]
    fn rejects_bad_bool_trailing_unsorted_dupes_utf8_and_long() {
        assert_eq!(
            Decoder::bare(&[2]).bool().unwrap_err(),
            DecodeError::InvalidValue("boolean")
        );
        let d = Decoder::bare(&[0]);
        assert_eq!(d.finish().unwrap_err(), DecodeError::TrailingBytes);

        let mut unsorted = Encoder::bare();
        unsorted.u32(2).str("b").str("a");
        assert_eq!(
            Decoder::bare(unsorted.as_bytes()).str_set().unwrap_err(),
            DecodeError::NotSorted
        );
        let mut dup = Encoder::bare();
        dup.u32(2).str("a").str("a");
        assert_eq!(
            Decoder::bare(dup.as_bytes()).str_set().unwrap_err(),
            DecodeError::NotSorted
        );
        let mut bad = Encoder::bare();
        bad.bytes(&[0xff, 0xfe]);
        assert_eq!(
            Decoder::bare(bad.as_bytes()).str().unwrap_err(),
            DecodeError::InvalidUtf8
        );
        let mut long = Encoder::bare();
        long.bytes(&vec![b'a'; MAX_STR_LEN + 1]);
        assert_eq!(
            Decoder::bare(long.as_bytes()).str().unwrap_err(),
            DecodeError::TooLong
        );
        // A huge count with few bytes left is refused before allocating.
        assert_eq!(
            Decoder::bare(&[0xff, 0xff, 0xff, 0xff])
                .str_set()
                .unwrap_err(),
            DecodeError::Truncated
        );
    }

    #[test]
    fn require_canonical_compares_bytes() {
        assert!(require_canonical(b"ab", b"ab").is_ok());
        assert_eq!(
            require_canonical(b"ab", b"ac").unwrap_err(),
            DecodeError::NonCanonical
        );
    }

    #[test]
    fn errors_have_plain_messages() {
        let all = [
            DecodeError::WrongKind,
            DecodeError::UnsupportedVersion(9),
            DecodeError::Truncated,
            DecodeError::TrailingBytes,
            DecodeError::InvalidUtf8,
            DecodeError::TooLong,
            DecodeError::NotSorted,
            DecodeError::InvalidValue("seats"),
            DecodeError::NonCanonical,
        ];
        for e in all {
            let msg = e.to_string();
            assert!(msg.ends_with('.'), "{msg}");
            assert!(!msg.contains("Decode"), "{msg}");
        }
    }
}
