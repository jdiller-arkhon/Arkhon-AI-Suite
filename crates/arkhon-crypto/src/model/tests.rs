use super::*;
use proptest::prelude::*;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn cek(seed: u8) -> Cek {
    Cek::from_bytes([seed; 32])
}

fn encrypt(cek: &Cek, plain: &[u8], chunk: u32) -> (Vec<u8>, EncryptedFileInfo) {
    let mut out = Vec::new();
    let info = encrypt_model(cek, plain, &mut out, chunk).unwrap();
    (out, info)
}

fn decrypt(cek: &Cek, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, ModelError> {
    decrypt_model_to_vec(cek, data, 0)
}

#[test]
fn round_trip_various_sizes() {
    let key = cek(1);
    for (len, chunk) in [
        (0usize, 16u32),
        (1, 16),
        (15, 16),
        (16, 16),
        (17, 16),
        (64, 16),
        (1000, 7),
    ] {
        let plain: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let (ct, info) = encrypt(&key, &plain, chunk);
        assert_eq!(info.plaintext_len, len as u64);
        assert_eq!(info.ciphertext_len, ct.len() as u64);
        assert_eq!(info.header.ciphertext_len(len as u64), ct.len() as u64);
        assert_eq!(info.ciphertext_sha256, crate::sha256(&ct));
        assert_eq!(&*decrypt(&key, &ct).unwrap(), &plain[..]);
    }
}

#[test]
fn empty_file_is_one_tag_only_chunk() {
    let (ct, _) = encrypt(&cek(1), &[], 16);
    assert_eq!(ct.len(), HEADER_LEN + TAG_LEN);
}

#[test]
fn wrong_key_fails_on_first_chunk() {
    let (ct, _) = encrypt(&cek(1), b"hello world", 4);
    assert!(matches!(
        decrypt(&cek(2), &ct),
        Err(ModelError::Damaged { chunk: 0 })
    ));
}

#[test]
fn header_errors() {
    let (ct, _) = encrypt(&cek(1), b"x", 4);
    assert!(matches!(
        ModelHeader::parse(&ct[..10]),
        Err(ModelError::Truncated)
    ));
    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert!(matches!(
        ModelHeader::parse(&bad),
        Err(ModelError::NotAModelFile)
    ));
    let mut v2 = ct.clone();
    v2[9] = 2;
    assert!(matches!(
        ModelHeader::parse(&v2),
        Err(ModelError::UnsupportedVersion(2))
    ));
    let mut zero = ct.clone();
    zero[10..14].copy_from_slice(&0u32.to_be_bytes());
    assert!(matches!(
        ModelHeader::parse(&zero),
        Err(ModelError::BadChunkSize(0))
    ));
    let mut huge = ct.clone();
    huge[10..14].copy_from_slice(&(MAX_CHUNK_SIZE + 1).to_be_bytes());
    assert!(matches!(
        ModelHeader::parse(&huge),
        Err(ModelError::BadChunkSize(_))
    ));
    let h = ModelHeader::parse(&ct).unwrap();
    assert_eq!(&h.to_bytes()[..], &ct[..HEADER_LEN]);
}

#[test]
fn encrypt_rejects_bad_chunk_size() {
    let mut out = Vec::new();
    assert!(matches!(
        encrypt_model(&cek(1), &b""[..], &mut out, 0),
        Err(ModelError::BadChunkSize(0))
    ));
    assert_eq!(out.len(), 0);
}

#[test]
fn truncated_inside_header_and_inside_first_tag() {
    let (ct, _) = encrypt(&cek(1), b"abc", 4);
    assert!(matches!(
        decrypt(&cek(1), &ct[..5]),
        Err(ModelError::Truncated)
    ));
    assert!(matches!(
        decrypt(&cek(1), &ct[..HEADER_LEN + 3]),
        Err(ModelError::Truncated)
    ));
}

#[test]
fn chunk_from_another_file_fails() {
    let key = cek(1);
    let plain = [9u8; 32];
    let (a, _) = encrypt(&key, &plain, 8);
    let (b, _) = encrypt(&key, &plain, 8);
    let ct = 8 + TAG_LEN;
    let mut spliced = a.clone();
    spliced[HEADER_LEN + ct..HEADER_LEN + 2 * ct]
        .copy_from_slice(&b[HEADER_LEN + ct..HEADER_LEN + 2 * ct]);
    assert!(matches!(
        decrypt(&key, &spliced),
        Err(ModelError::Damaged { chunk: 1 })
    ));
}

#[test]
fn errors_display_plain_language() {
    use std::error::Error;
    let errs = [
        ModelError::NotAModelFile,
        ModelError::UnsupportedVersion(3),
        ModelError::BadChunkSize(0),
        ModelError::Truncated,
        ModelError::Damaged { chunk: 2 },
        ModelError::Io(io::Error::other("disk gone")),
    ];
    for e in &errs {
        assert_ne!(e.to_string(), "");
    }
    assert!(errs[5].source().is_some());
    assert!(errs[0].source().is_none());
    assert!(ModelError::from(io::Error::other("x"))
        .to_string()
        .contains('x'));
}

#[test]
fn io_errors_propagate() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("boom"))
        }
    }
    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("boom"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut out = Vec::new();
    assert!(matches!(
        encrypt_model(&cek(1), Failing, &mut out, 4),
        Err(ModelError::Io(_))
    ));
    assert!(matches!(
        encrypt_model(&cek(1), &b"ab"[..], Failing, 4),
        Err(ModelError::Io(_))
    ));
    assert!(matches!(decrypt(&cek(1), &[]), Err(ModelError::Truncated)));
    let (ct, _) = encrypt(&cek(1), b"ab", 4);
    assert!(matches!(
        decrypt_model(&cek(1), &ct[..], &mut Failing),
        Err(ModelError::Io(_))
    ));
}

#[test]
fn secret_buffer_grows_and_redacts_debug() {
    let mut b = SecretBuffer::default();
    for _ in 0..100 {
        b.write_all(b"0123456789").unwrap();
    }
    b.flush().unwrap();
    assert_eq!(b.as_slice().len(), 1000);
    let shown = format!("{b:?}");
    assert!(shown.contains("1000 bytes") && !shown.contains("0123"));
    assert_eq!(b.into_inner().len(), 1000);
}

/// Published test vector (fixed seeds; see `test-vectors/README.md`).
#[test]
fn test_vector_model_file() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors");
    let key = Cek::from_bytes(crate::sha256(b"arkhon test vector CEK - NOT SECRET"));
    let plain: Vec<u8> = (0u8..=99).collect();
    let mut rng = ChaCha20Rng::from_seed([42; 32]);
    let mut ct = Vec::new();
    let info = encrypt_model_with_rng(&mut rng, &key, &plain[..], &mut ct, 32).unwrap();
    let path = format!("{dir}/model-file-v1.hex");
    if std::env::var_os("ARKHON_REGEN_VECTORS").is_some() {
        std::fs::write(&path, crate::to_hex(&ct) + "\n").unwrap();
    }
    let expected = crate::from_hex(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(ct, expected, "model-file vector changed");
    assert_eq!(&*decrypt(&key, &expected).unwrap(), &plain[..]);
    assert_eq!(info.ciphertext_sha256, crate::sha256(&expected));
}

fn arb_case() -> impl Strategy<Value = (Vec<u8>, u32)> {
    (prop::collection::vec(any::<u8>(), 0..300), 1u32..64)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_round_trip((plain, chunk) in arb_case(), seed in any::<u8>()) {
        let key = cek(seed);
        let (ct, _) = encrypt(&key, &plain, chunk);
        prop_assert_eq!(&*decrypt(&key, &ct).unwrap(), &plain[..]);
    }

    #[test]
    fn prop_any_single_bit_flip_fails((plain, chunk) in arb_case(), pos in any::<prop::sample::Index>(), bit in 0u8..8) {
        let key = cek(3);
        let (mut ct, _) = encrypt(&key, &plain, chunk);
        let i = pos.index(ct.len());
        ct[i] ^= 1 << bit;
        prop_assert!(decrypt(&key, &ct).is_err());
    }

    #[test]
    fn prop_any_truncation_fails((plain, chunk) in arb_case(), cut in any::<prop::sample::Index>()) {
        let key = cek(4);
        let (ct, _) = encrypt(&key, &plain, chunk);
        let keep = cut.index(ct.len()); // strictly shorter than the full file
        prop_assert!(decrypt(&key, &ct[..keep]).is_err());
    }

    #[test]
    fn prop_appended_data_fails((plain, chunk) in arb_case(), extra in prop::collection::vec(any::<u8>(), 1..80)) {
        let key = cek(5);
        let (mut ct, _) = encrypt(&key, &plain, chunk);
        ct.extend_from_slice(&extra);
        prop_assert!(decrypt(&key, &ct).is_err());
    }

    #[test]
    fn prop_chunk_reorder_fails(plain in prop::collection::vec(any::<u8>(), 2..300), chunk in 1u32..32, a in any::<prop::sample::Index>(), b in any::<prop::sample::Index>()) {
        let key = cek(6);
        let (ct, _) = encrypt(&key, &plain, chunk);
        let cs = chunk as usize;
        let full_chunks = plain.len() / cs; // chunks of exactly ct_len bytes (excluding a short tail)
        prop_assume!(full_chunks >= 2);
        let (i, j) = (a.index(full_chunks), b.index(full_chunks));
        let ct_len = cs + TAG_LEN;
        let ci = &ct[HEADER_LEN + i * ct_len..HEADER_LEN + (i + 1) * ct_len];
        let cj = &ct[HEADER_LEN + j * ct_len..HEADER_LEN + (j + 1) * ct_len];
        prop_assume!(i != j && ci != cj);
        let mut swapped = ct.clone();
        let (ci, cj) = (ci.to_vec(), cj.to_vec());
        swapped[HEADER_LEN + i * ct_len..HEADER_LEN + (i + 1) * ct_len].copy_from_slice(&cj);
        swapped[HEADER_LEN + j * ct_len..HEADER_LEN + (j + 1) * ct_len].copy_from_slice(&ci);
        prop_assert!(decrypt(&key, &swapped).is_err());
    }

    #[test]
    fn prop_dropping_a_whole_chunk_fails(plain in prop::collection::vec(any::<u8>(), 2..300), chunk in 1u32..32, which in any::<prop::sample::Index>()) {
        let key = cek(7);
        let (ct, _) = encrypt(&key, &plain, chunk);
        let cs = chunk as usize;
        let ct_len = cs + TAG_LEN;
        let n_chunks = plain.len().div_ceil(cs);
        prop_assume!(n_chunks >= 2);
        let i = which.index(n_chunks - 1); // any non-final chunk (all full-size)
        let mut cut = ct[..HEADER_LEN + i * ct_len].to_vec();
        cut.extend_from_slice(&ct[HEADER_LEN + (i + 1) * ct_len..]);
        prop_assert!(decrypt(&key, &cut).is_err());
    }
}
