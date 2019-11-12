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
}
