use crate::constants::{AVERAGE_DELAY, SECURITY_PARAMETER};
use crate::crypto::{generate_secret, CURVE_GENERATOR};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use rand;
use rand_distr::{Distribution, Exp};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct Address {}

pub struct Delay {}

pub enum RouteElement {
    FinalHop(Destination),
    ForwardHop(Host),
}

impl RouteElement {
    fn get_pub_key(&self) -> MontgomeryPoint {
        use RouteElement::*;

        match self {
            FinalHop(destination) => destination.pub_key,
            ForwardHop(host) => host.pub_key,
        }
    }
}

pub struct Destination {
    pub pub_key: MontgomeryPoint,
}

pub struct Host {
    pub address: Address,
    pub pub_key: MontgomeryPoint,
}

struct KeyMaterial {
    initial_shared_secret: SharedSecret,
    shared_keys: Vec<SharedKey>,
}

pub struct SphinxHeader {}
struct FillerString {}

pub type SharedSecret = MontgomeryPoint;
pub type SharedKey = MontgomeryPoint;

// needs client's secret key, how should we inject this?
// needs to deal with SURBs too at some point
pub fn create_header(route: &[RouteElement]) -> (SphinxHeader, Vec<SharedKey>) {
    let initial_secret = generate_secret();
    let key_material = derive_key_material(route, initial_secret);
    let delays = generate_delays(route.len() - 1); // we don't generate delay for the destination

    // compute filler strings
    // encapsulate routing information, compute MACs
    (SphinxHeader {}, vec![])
}

fn create_zero_bytes(length: usize) -> Vec<u8> {
    vec![0; length]
}

// TODO: remember about the destination
fn generate_filler_string(shared_keys: Vec<SharedKey>) -> Vec<u8> {
    let mut filler_string: Vec<u8> = vec![];
    for x in 0..(shared_keys.len()) {
        let zero_bytes = create_zero_bytes(SECURITY_PARAMETER * 2);
    }

    // start with empty filler string
    // then have the for loop:
    // iterate through all hops:
    // take current filler string then concatenate with string of zeroes of size 2*k (k is the security parameter)
    // then xor the result with output of PRNG seeded with shared key of the iteration
    // take some bits as specified in the paper...
    // this gives new filler string.
    // repeat the loop

    vec![]
}

fn generate_delays(number: usize) -> Vec<f64> {
    let exp = Exp::new(1.0 / AVERAGE_DELAY).unwrap();

    std::iter::repeat(())
        .take(number)
        .map(|_| exp.sample(&mut rand::thread_rng()))
        .collect()
}

fn compute_shared_key(node_pub_key: MontgomeryPoint, exponent: &Scalar) -> SharedKey {
    node_pub_key * exponent
}

fn compute_blinding_factor(shared_key: MontgomeryPoint, exponent: &Scalar) -> Scalar {
    let shared_secret = CURVE_GENERATOR * exponent;
    compute_keyed_hmac(shared_secret.to_bytes(), shared_key.to_bytes())
}

// derive shared keys, group elements, blinding factors
fn derive_key_material(route: &[RouteElement], initial_secret: Scalar) -> KeyMaterial {
    let initial_shared_secret = CURVE_GENERATOR * initial_secret;

    let shared_keys = route
        .iter()
        .scan(initial_secret, |accumulator, hop| {
            let shared_key = compute_shared_key(hop.get_pub_key(), &accumulator);

            // TODO: don't compute those 2 lines for last iteration
            let blinding_factor = compute_blinding_factor(shared_key, &accumulator);
            *accumulator = *accumulator * blinding_factor;

            Some(shared_key)
        })
        .collect();

    KeyMaterial {
        shared_keys,
        initial_shared_secret,
    }
}

fn compute_keyed_hmac(alpha: [u8; 32], data: [u8; 32]) -> Scalar {
    let mut mac = HmacSha256::new_varkey(&alpha).expect("HMAC can take key of any size");
    mac.input(&data);
    let mut output = [0u8; 32];
    output.copy_from_slice(&mac.result().code().to_vec()[..32]);
    Scalar::from_bytes_mod_order(output)
}

#[cfg(test)]
mod tests {
    use crate::crypto::generate_random_curve_point;

    use super::*;

    #[test]
    fn generate_delays_returns_correct_number_of_delays() {
        let delays = generate_delays(3);

        assert_eq!(delays.len(), 3);
    }

    #[test]
    fn generate_secret_returns_a_scalar() {
        let secret = generate_secret();
        assert_eq!(32, secret.to_bytes().len());
    }

    #[test]
    fn generate_curve_point_multiplies_the_seed() {
        let secret = generate_random_curve_point();
        assert_eq!(32, secret.to_bytes().len())
    }

    #[test]
    fn compute_shared_key_returns_correct_shared_key() {
        let exponent = Scalar::from_bytes_mod_order([42u8; 32]);
        let sample_pub_key = CURVE_GENERATOR * Scalar::from_bytes_mod_order([16u8; 32]);

        let expected_shared_key = sample_pub_key * exponent;
        let shared_key = compute_shared_key(sample_pub_key, &exponent);

        assert_eq!(expected_shared_key, shared_key);
    }

    #[test]
    fn compute_blinding_factor_returns_correct_hmac() {
        let exponent = Scalar::from_bytes_mod_order([42u8; 32]);
        let shared_key = CURVE_GENERATOR * Scalar::from_bytes_mod_order([16u8; 32]);

        // given the above exponent and shared key, we should see:
        let expected_blinding_factor = Scalar::from_bytes_mod_order([
            65, 236, 88, 7, 186, 168, 172, 170, 90, 46, 49, 164, 225, 73, 145, 77, 181, 151, 37,
            178, 37, 181, 248, 165, 180, 75, 103, 133, 191, 146, 10, 8,
        ]);

        let blinding_factor = compute_blinding_factor(shared_key, &exponent);
        assert_eq!(expected_blinding_factor, blinding_factor)
    }

    #[test]
    fn derive_key_material_shared_keys_count_equals_hops_count() {
        let key1 = generate_random_curve_point();
        let key2 = generate_random_curve_point();
        let key3 = generate_random_curve_point();
        let route = vec![new_hop_host(key1), new_hop_host(key2), new_hop_host(key3)];

        let initial_secret = generate_secret();
        let key_material = derive_key_material(&route, initial_secret);
        assert_eq!(route.len(), key_material.shared_keys.len());
    }

    #[test]
    fn derive_key_material_returns_correct_initial_shared_secret() {
        let key1 = generate_random_curve_point();
        let key2 = generate_random_curve_point();
        let key3 = generate_random_curve_point();
        let route = vec![new_hop_host(key1), new_hop_host(key2), new_hop_host(key3)];

        let initial_secret = generate_secret();
        let key_material = derive_key_material(&route, initial_secret);

        let expected_initial_secret = CURVE_GENERATOR * initial_secret;
        assert_eq!(expected_initial_secret, key_material.initial_shared_secret);
    }

    #[test]
    fn derive_key_material_generates_correct_shared_key() {
        let key1 = generate_random_curve_point();
        let key2 = generate_random_curve_point();
        let key3 = generate_random_curve_point();
        let route = vec![new_hop_host(key1), new_hop_host(key2), new_hop_host(key3)];

        let initial_secret = generate_secret();
        let key_material = derive_key_material(&route, initial_secret);

        // this is unwrapping first iteration of the for loop in derive_key_material function
        let mut expected_accumulator = initial_secret;
        let s1 = compute_shared_key(key1, &expected_accumulator);
        let b1 = compute_blinding_factor(s1, &expected_accumulator);
        expected_accumulator = expected_accumulator * b1;
        // we could loop further, but if it works once it should work more times

        let expected_shared_key1 = compute_shared_key(key2, &expected_accumulator);

        // The accumulator is the key to our blinding factors working. If the accumulator value isn't incremented
        // correctly, we risk passing an incorrectly blinded shared key through the mixnet in the (unencrypted)
        // Sphinx packet header. So this test ensures that the accumulator gets incremented properly
        // on each run through the loop.
        assert_eq!(expected_shared_key1, key_material.shared_keys[1]);
    }

    fn new_hop_host(pub_key: MontgomeryPoint) -> RouteElement {
        RouteElement::ForwardHop(Host {
            address: Address {},
            pub_key,
        })
    }
}
