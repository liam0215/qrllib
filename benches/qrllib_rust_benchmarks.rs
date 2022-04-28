use criterion::{criterion_group, criterion_main, Criterion};
use qrllib::rust_wrapper::errors::QRLError;
use qrllib::rust_wrapper::qrl::qrl_address_format::AddrFormatType;
use qrllib::rust_wrapper::qrl::xmss_base::{Sign, XMSSBaseTrait};
use qrllib::rust_wrapper::qrl::xmss_basic::XMSSBasic;
use qrllib::rust_wrapper::qrl::xmss_fast::XMSSFast;
use qrllib::rust_wrapper::xmss_alt::hash_functions::HashFunction;

const XMSS_HEIGHT: u8 = 4;
const XMSS_SEED_SIZE: usize = 48;

fn sign_verify_index_shift<T: XMSSBaseTrait + Sign>(mut xmss: T) -> Result<(), QRLError> {
    xmss.set_index(1).unwrap();
    let message = "This is a test message";
    let data = message.as_bytes();
    let mut data_to_sign = data.to_vec();

    let pk = xmss.get_pk();
    for i in 0..10 {
        let signature = xmss.sign(&data_to_sign).unwrap();
        assert_eq!(data, data_to_sign);
        assert!(T::verify(&mut data_to_sign, &signature, &pk, None).is_ok());
    }
    Ok(())
}

fn xmss_fast_key_creation() -> XMSSFast {
    let seed: Vec<u8> = vec![0; XMSS_SEED_SIZE];

    XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap()
}

fn xmss_basic_key_creation() -> XMSSBasic {
    let seed: Vec<u8> = vec![0; XMSS_SEED_SIZE];

    XMSSBasic::new(
        seed.clone(),
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("xmss_fast_key_creation", |b| {
        b.iter(|| xmss_fast_key_creation())
    });
    c.bench_function("xmss_basic_key_creation", |b| {
        b.iter(|| xmss_basic_key_creation())
    });
    c.bench_function("xmss_fast_sign_verify_index_shift", |b| {
        let seed: Vec<u8> = (0..48).collect();
        let xmss = XMSSFast::new(
            seed,
            XMSS_HEIGHT,
            Some(HashFunction::Shake128),
            Some(AddrFormatType::SHA256_2X),
            None,
        )
        .unwrap();
        b.iter(|| sign_verify_index_shift(xmss.clone()))
    });
    c.bench_function("xmss_basic_sign_verify_index_shift", |b| {
        let seed: Vec<u8> = (0..48).collect();
        let xmss = XMSSBasic::new(
            seed,
            XMSS_HEIGHT,
            HashFunction::Shake128,
            AddrFormatType::SHA256_2X,
            None,
        )
        .unwrap();
        b.iter(|| sign_verify_index_shift(xmss.clone()))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
