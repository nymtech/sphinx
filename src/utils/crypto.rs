use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes128Ctr;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use rand_os;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const CURVE_GENERATOR: MontgomeryPoint = curve25519_dalek::constants::X25519_BASEPOINT;
pub const STREAM_CIPHER_KEY_SIZE: usize = 16;
pub const STREAM_CIPHER_INIT_VECTOR: [u8; 16] = [0u8; 16];

pub type PublicKey = MontgomeryPoint;
pub type SharedSecret = MontgomeryPoint;
pub type SharedKey = MontgomeryPoint;

pub fn generate_secret() -> Scalar {
    let mut rng = rand_os::OsRng::new().unwrap();
    Scalar::random(&mut rng)
}

pub fn generate_random_curve_point() -> MontgomeryPoint {
    CURVE_GENERATOR * generate_secret()
}

pub fn generate_pseudorandom_bytes(
    key: &[u8; STREAM_CIPHER_KEY_SIZE],
    iv: &[u8; STREAM_CIPHER_KEY_SIZE],
    length: usize,
) -> Vec<u8> {
    let cipher_key = GenericArray::from_slice(&key[..]);
    let cipher_nonce = GenericArray::from_slice(&iv[..]);

    // generate a random string as an output of a PRNG, which we implement using stream cipher AES_CTR
    let mut cipher = Aes128Ctr::new(cipher_key, cipher_nonce);
    let mut data = vec![0u8; length];
    cipher.apply_keystream(&mut data);
    data
}

pub fn compute_keyed_hmac(key: Vec<u8>, data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_varkey(&key).expect("HMAC can take key of any size");
    mac.input(&data);
    mac.result().code().to_vec()
}

#[cfg(test)]
mod generating_pseudorandom_bytes {
    use super::*;

    // TODO: 10,000 is the wrong number, @aniap what is correct here?
    #[test]
    fn it_generates_output_of_size_10000() {
        let key: [u8; STREAM_CIPHER_KEY_SIZE] =
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let iv: [u8; STREAM_CIPHER_KEY_SIZE] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let rand_bytes = generate_pseudorandom_bytes(&key, &iv, 10000);
        assert_eq!(10000, rand_bytes.len());
    }
}

#[cfg(test)]
mod secret_generation {
    use super::*;

    #[test]
    fn it_returns_a_32_byte_scalar() {
        let secret = generate_secret();
        assert_eq!(32, secret.to_bytes().len());
    }
}

#[cfg(test)]
mod generating_a_random_curve_point {
    use super::*;

    #[test]
    fn it_returns_a_32_byte_montgomery_point() {
        let secret = generate_random_curve_point();
        assert_eq!(32, secret.to_bytes().len())
    }
}
