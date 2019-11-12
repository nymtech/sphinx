use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand_os;

pub const CURVE_GENERATOR: MontgomeryPoint = curve25519_dalek::constants::X25519_BASEPOINT;

pub fn generate_secret() -> Scalar {
    let mut rng = rand_os::OsRng::new().unwrap();
    Scalar::random(&mut rng)
}

pub fn generate_random_curve_point() -> MontgomeryPoint {
    CURVE_GENERATOR * generate_secret()
}

// xor produces new Vector with the XOR result
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());

    a.iter().zip(b.iter()).map(|(&x1, &x2)| x1 ^ x2).collect()
}

// xor_with xors assigns the result of xor to the first argument
pub fn xor_with(a: &mut [u8], b: &[u8]) {
    assert_eq!(a.len(), b.len());

    a.iter_mut()
        .zip(b.iter())
        .map(|(x1, &x2)| *x1 ^= x2)
        .collect()
}

#[cfg(test)]
use speculate::speculate;

#[cfg(test)]
speculate! {
    describe "secret generation" {
        it "returns a 32 byte scalar" {
            let secret = generate_secret();
            assert_eq!(32, secret.to_bytes().len());
        }
    }

    describe "generating a random curve point" {
        it "returns a 32 byte Montgomery point" {
            let secret = generate_random_curve_point();
            assert_eq!(32, secret.to_bytes().len())
        }
    }

    describe "xor_with" {
        context "for empty inputs" {
            it "does not change initial value" {
                let mut a: Vec<u8> = vec![];
                let b: Vec<u8> = vec![];
                xor_with(&mut a, &b);
                assert_eq!(0, a.len());
            }
        }

        context "for non-zero inputs of same length" {
            it "returns the expected xor of the vectors" {
                let mut a: Vec<u8> = vec![1, 2, 3];
                let b: Vec<u8> = vec![4, 5, 6];
                xor_with(&mut a, &b);
                assert_eq!(1^4, a[0]);
                assert_eq!(2^5, a[1]);
                assert_eq!(3^6, a[2]);

            }
        }

        context "for inputs of different lengths" {
            #[should_panic]
            it "panics" {
                let mut a: Vec<u8> = vec![1, 2, 3];
                let b: Vec<u8> = vec![4, 5];
                xor_with(&mut a, &b);
            }
        }
    }

    describe "xor" {
        context "for empty inputs" {
            it "returns an empty vector" {
                let a: Vec<u8> = vec![];
                let b: Vec<u8> = vec![];
                let c = xor(&a, &b);
                assert_eq!(0, c.len());
            }
        }

        context "for non-zero inputs of same length" {
            it "returns the expected xor of the vectors" {
                let a: Vec<u8> = vec![1, 2, 3];
                let b: Vec<u8> = vec![4, 5, 6];
                let c = xor(&a, &b);
                assert_eq!(a.len(), c.len());
                for i in 0..c.len() {
                    assert_eq!(c[i], a[i] ^ b[i])
                }
            }
        }

        context "for inputs of different lengths" {
            #[should_panic]
            it "panics" {
                let a: Vec<u8> = vec![1, 2, 3];
                let b: Vec<u8> = vec![4, 5];
                let c = xor(&a, &b);
            }
        }
    }
}
