//! Chunked AES-256-GCM model-file format (ADR-0008).
//!
//! ```text
//! header (34 bytes):
//!   magic        8   b"ARKHMDL\0"
//!   version      2   u16 BE = 1
//!   chunk_size   4   u32 BE, 1..=16 MiB (plaintext bytes per chunk)
//!   file_id     16   random, unique per encrypted file
//!   nonce_prefix 4   random
//! chunks: ciphertext || 16-byte GCM tag, each chunk_size plaintext bytes except the last,
//!         which holds 0..=chunk_size bytes. There is always at least one chunk.
//! ```
//!
//! * `header_digest = SHA-256(header bytes)`.
//! * Per-file key: `HKDF-SHA256(ikm = CEK, salt = header_digest, info = "arkhon/v1/model-file-key")`.
//!   Even if two files under one CEK drew the same nonce prefix, they use different keys.
//! * Nonce for chunk `i`: `nonce_prefix || u64 BE i`.
//! * AAD for chunk `i`: `header_digest || u64 BE i || final_flag (1 byte)`.
//!
//! So: header tampering changes the digest (every chunk fails); reordering changes `i`; chunks
//! moved from another file fail (different digest and key); truncation at a chunk boundary leaves a
//! last chunk whose final flag was 0; appended data makes the real last chunk non-final.
//!
//! **Plaintext stays in memory.** Use [`decrypt_model_to_vec`]. [`decrypt_model`] streams into any
//! `Write` and exists for in-memory sinks (a `Vec`, a memfd you created); it writes each chunk as soon
//! as that chunk is authenticated, so on error the caller must discard everything written.

use std::fmt;
use std::io::{self, Read, Write};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hkdf::Hkdf;
use rand_core::{CryptoRngCore, OsRng};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::Cek;

/// File magic.
pub const MAGIC: [u8; 8] = *b"ARKHMDL\0";
/// Format version written by this crate.
pub const FORMAT_VERSION: u16 = 1;
/// Header length in bytes.
pub const HEADER_LEN: usize = 34;
/// GCM tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Default plaintext chunk size (1 MiB).
pub const DEFAULT_CHUNK_SIZE: u32 = 1 << 20;
/// Largest accepted chunk size (16 MiB).
pub const MAX_CHUNK_SIZE: u32 = 16 << 20;

const KEY_INFO: &[u8] = b"arkhon/v1/model-file-key";

/// Why a model file could not be encrypted or decrypted.
#[derive(Debug)]
pub enum ModelError {
    /// The file does not start with the model-file magic.
    NotAModelFile,
    /// The format version is newer than this build understands.
    UnsupportedVersion(u16),
    /// The chunk size is zero or above [`MAX_CHUNK_SIZE`].
    BadChunkSize(u32),
    /// The file ends early (inside the header or a chunk).
    Truncated,
    /// A chunk failed authentication: wrong key, or the file was changed, cut, reordered or extended.
    Damaged {
        /// Index of the chunk that failed.
        chunk: u64,
    },
    /// Reading or writing failed.
    Io(io::Error),
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModelError::NotAModelFile => f.write_str("This isn't an Arkhon engine file."),
            ModelError::UnsupportedVersion(v) => write!(
                f,
                "This engine file uses format version {v}. Update Arkhon to use it."
            ),
            ModelError::BadChunkSize(_) | ModelError::Damaged { .. } => f.write_str(
                "This engine file is damaged, has been changed, or doesn't match your license. Reinstall the engine.",
            ),
            ModelError::Truncated => {
                f.write_str("This engine file is incomplete. Reinstall the engine.")
            }
            ModelError::Io(e) => write!(f, "Couldn't read or write the engine file: {e}"),
        }
    }
}

impl std::error::Error for ModelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ModelError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ModelError {
    fn from(e: io::Error) -> Self {
        ModelError::Io(e)
    }
}

/// The parsed 34-byte file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelHeader {
    /// Plaintext bytes per chunk.
    pub chunk_size: u32,
    /// Random per-file id (also bound into every chunk through the header digest).
    pub file_id: [u8; 16],
    /// Random nonce prefix.
    pub nonce_prefix: [u8; 4],
}

impl ModelHeader {
    /// Parse the first [`HEADER_LEN`] bytes of `bytes` (extra bytes are ignored).
    ///
    /// # Errors
    /// [`ModelError::Truncated`], [`ModelError::NotAModelFile`],
    /// [`ModelError::UnsupportedVersion`] or [`ModelError::BadChunkSize`].
    pub fn parse(bytes: &[u8]) -> Result<Self, ModelError> {
        if bytes.len() < HEADER_LEN {
            return Err(ModelError::Truncated);
        }
        if bytes[..8] != MAGIC {
            return Err(ModelError::NotAModelFile);
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != FORMAT_VERSION {
            return Err(ModelError::UnsupportedVersion(version));
        }
        let chunk_size = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        check_chunk_size(chunk_size)?;
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&bytes[14..30]);
        let mut nonce_prefix = [0u8; 4];
        nonce_prefix.copy_from_slice(&bytes[30..34]);
        Ok(Self {
            chunk_size,
            file_id,
            nonce_prefix,
        })
    }

    /// The canonical header bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..8].copy_from_slice(&MAGIC);
        out[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        out[10..14].copy_from_slice(&self.chunk_size.to_be_bytes());
        out[14..30].copy_from_slice(&self.file_id);
        out[30..34].copy_from_slice(&self.nonce_prefix);
        out
    }

    /// SHA-256 of the header bytes (bound into every chunk's AAD and the file key).
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }

    /// Ciphertext length of a file with this header holding `plaintext_len` bytes.
    #[must_use]
    pub fn ciphertext_len(&self, plaintext_len: u64) -> u64 {
        let cs = u64::from(self.chunk_size);
        let chunks = plaintext_len.div_ceil(cs).max(1);
        HEADER_LEN as u64 + plaintext_len + chunks * TAG_LEN as u64
    }
}

fn check_chunk_size(chunk_size: u32) -> Result<(), ModelError> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        Err(ModelError::BadChunkSize(chunk_size))
    } else {
        Ok(())
    }
}

/// What [`encrypt_model`] produced: the values a release manifest records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedFileInfo {
    /// The header written.
    pub header: ModelHeader,
    /// Plaintext bytes read.
    pub plaintext_len: u64,
    /// Ciphertext bytes written (header included).
    pub ciphertext_len: u64,
    /// SHA-256 of all ciphertext bytes written (header included).
    pub ciphertext_sha256: [u8; 32],
}

struct ChunkCipher {
    aead: Aes256Gcm,
    digest: [u8; 32],
    prefix: [u8; 4],
}

impl ChunkCipher {
    fn new(cek: &Cek, header: &ModelHeader) -> Self {
        let digest = header.digest();
        let hk = Hkdf::<Sha256>::new(Some(&digest), cek.expose_secret());
        let mut key = Zeroizing::new([0u8; 32]);
        hk.expand(KEY_INFO, key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        let aead = Aes256Gcm::new_from_slice(key.as_ref()).expect("key is 32 bytes");
        Self {
            aead,
            digest,
            prefix: header.nonce_prefix,
        }
    }

    fn nonce(&self, index: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.prefix);
        n[4..].copy_from_slice(&index.to_be_bytes());
        n
    }

    fn aad(&self, index: u64, is_final: bool) -> [u8; 41] {
        let mut a = [0u8; 41];
        a[..32].copy_from_slice(&self.digest);
        a[32..40].copy_from_slice(&index.to_be_bytes());
        a[40] = u8::from(is_final);
        a
    }

    fn seal(&self, index: u64, is_final: bool, buf: &mut [u8]) -> [u8; TAG_LEN] {
        let tag = self
            .aead
            .encrypt_in_place_detached(
                Nonce::from_slice(&self.nonce(index)),
                &self.aad(index, is_final),
                buf,
            )
            .expect("chunk is far below the GCM length limit");
        tag.into()
    }

    fn open(
        &self,
        index: u64,
        is_final: bool,
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), ModelError> {
        self.aead
            .decrypt_in_place_detached(
                Nonce::from_slice(&self.nonce(index)),
                &self.aad(index, is_final),
                buf,
                Tag::from_slice(tag),
            )
            .map_err(|_| ModelError::Damaged { chunk: index })
    }
}

/// Read up to `n` bytes (fewer only at end of input). Grows as data arrives, so a hostile header
/// asking for 16 MiB chunks costs nothing until 16 MiB is actually supplied.
fn read_up_to<R: Read>(input: &mut R, n: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::new());
    input.take(n as u64).read_to_end(&mut buf).map(|_| buf)
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> HashingWriter<W> {
    fn put(&mut self, data: &[u8]) -> io::Result<()> {
        self.inner.write_all(data)?;
        self.hasher.update(data);
        self.written += data.len() as u64;
        Ok(())
    }
}

/// Encrypt everything from `input` into `output` with a fresh random file id and nonce prefix.
///
/// # Errors
/// [`ModelError::BadChunkSize`] or [`ModelError::Io`].
pub fn encrypt_model<R: Read, W: Write>(
    cek: &Cek,
    input: R,
    output: W,
    chunk_size: u32,
) -> Result<EncryptedFileInfo, ModelError> {
    encrypt_model_with_rng(&mut OsRng, cek, input, output, chunk_size)
}

/// As [`encrypt_model`], drawing the file id and nonce prefix from `rng` (for test vectors).
///
/// # Errors
/// [`ModelError::BadChunkSize`] or [`ModelError::Io`].
pub fn encrypt_model_with_rng<R: Read, W: Write>(
    rng: &mut impl CryptoRngCore,
    cek: &Cek,
    mut input: R,
    output: W,
    chunk_size: u32,
) -> Result<EncryptedFileInfo, ModelError> {
    check_chunk_size(chunk_size)?;
    let mut header = ModelHeader {
        chunk_size,
        file_id: [0; 16],
        nonce_prefix: [0; 4],
    };
    rng.fill_bytes(&mut header.file_id);
    rng.fill_bytes(&mut header.nonce_prefix);
    let cipher = ChunkCipher::new(cek, &header);
    let mut out = HashingWriter {
        inner: output,
        hasher: Sha256::new(),
        written: 0,
    };
    out.put(&header.to_bytes())?;

    let cs = chunk_size as usize;
    let mut plaintext_len = 0u64;
    let mut index = 0u64;
    let mut current = read_up_to(&mut input, cs)?;
    loop {
        let next = if current.len() == cs {
            read_up_to(&mut input, cs)?
        } else {
            Zeroizing::new(Vec::new())
        };
        let is_final = next.is_empty();
        plaintext_len += current.len() as u64;
        let tag = cipher.seal(index, is_final, &mut current);
        out.put(&current)?;
        out.put(&tag)?;
        if is_final {
            break;
        }
        current = next;
        index += 1;
    }
    out.inner.flush()?;
    Ok(EncryptedFileInfo {
        header,
        plaintext_len,
        ciphertext_len: out.written,
        ciphertext_sha256: out.hasher.finalize().into(),
    })
}

/// Decrypt from `input` into `output`, authenticating every chunk. Returns plaintext bytes written.
///
/// `output` should be an in-memory sink. Chunks are written as they are authenticated, so if this
/// returns an error, discard (and zeroize) everything already written. Prefer
/// [`decrypt_model_to_vec`], which does that for you.
///
/// # Errors
/// Any [`ModelError`]. Trailing data after the last chunk is reported as [`ModelError::Damaged`].
pub fn decrypt_model<R: Read, W: Write>(
    cek: &Cek,
    mut input: R,
    output: &mut W,
) -> Result<u64, ModelError> {
    let raw_header = read_up_to(&mut input, HEADER_LEN)?;
    let header = ModelHeader::parse(&raw_header)?;
    let cipher = ChunkCipher::new(cek, &header);
    let ct_len = header.chunk_size as usize + TAG_LEN;

    let mut written = 0u64;
    let mut index = 0u64;
    let mut current = read_up_to(&mut input, ct_len)?;
    loop {
        if current.len() < TAG_LEN {
            return Err(ModelError::Truncated);
        }
        let next = if current.len() == ct_len {
            read_up_to(&mut input, ct_len)?
        } else {
            Zeroizing::new(Vec::new())
        };
        let is_final = next.is_empty();
        let body_len = current.len() - TAG_LEN;
        let (body, tag) = current.split_at_mut(body_len);
        cipher.open(index, is_final, body, tag)?;
        output.write_all(body)?;
        written += body_len as u64;
        if is_final {
            return Ok(written);
        }
        current = next;
        index = index
            .checked_add(1)
            .ok_or(ModelError::Damaged { chunk: index })?;
    }
}

/// Decrypt a whole model file into a zeroizing in-memory buffer.
///
/// Growth never leaves stale plaintext copies behind: when the buffer must grow, the old allocation
/// is wiped before it is freed. Pass `capacity_hint` (e.g. the manifest's size) to avoid regrowth.
/// On error, everything decrypted so far is wiped.
///
/// # Errors
/// Any [`ModelError`].
pub fn decrypt_model_to_vec<R: Read>(
    cek: &Cek,
    input: R,
    capacity_hint: usize,
) -> Result<Zeroizing<Vec<u8>>, ModelError> {
    let mut sink = SecretBuffer::with_capacity(capacity_hint);
    decrypt_model(cek, input, &mut sink)?;
    Ok(sink.into_inner())
}

/// A `Write` sink that keeps plaintext in memory and wipes every buffer it discards.
#[derive(Default)]
pub struct SecretBuffer {
    buf: Zeroizing<Vec<u8>>,
}

impl SecretBuffer {
    /// An empty buffer with room for `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Zeroizing::new(Vec::with_capacity(capacity)),
        }
    }

    /// The bytes written so far.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Take the contents (still zeroized on drop).
    #[must_use]
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

impl fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuffer({} bytes, <redacted>)", self.buf.len())
    }
}

impl Write for SecretBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let needed = self.buf.len() + data.len();
        if needed > self.buf.capacity() {
            let mut grown = Vec::with_capacity(needed.max(self.buf.capacity() * 2));
            grown.extend_from_slice(&self.buf);
            self.buf.zeroize();
            *self.buf = grown;
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
