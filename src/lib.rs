use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use rand_os;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

struct Address {}

struct Delay {}

pub struct Destination {}

pub struct Hop {
    host: Host,
    delay: Delay,
}

struct Host {
    address: Address,
    pub_key: MontgomeryPoint,
}

struct KeyMaterial {
    initial_shared_secret: SharedSecret,
    shared_keys: Vec<SharedKey>,
}

struct SphinxHeader {}

pub struct SphinxPacket {
    header: SphinxHeader,
    payload: Vec<u8>,
}

type SharedSecret = MontgomeryPoint;
type SharedKey = MontgomeryPoint;

const CURVE_GENERATOR: MontgomeryPoint = curve25519_dalek::constants::X25519_BASEPOINT;

// TODO: a utility function to turn this into properly concatenated bytes
pub fn create_packet(message: Vec<u8>, route: Vec<Hop>) -> SphinxPacket {
    let (header, shared_keys) = create_header(route);
    let enc_payload = create_enc_payload(message, shared_keys);
    let packet = SphinxPacket {
        header,
        payload: enc_payload,
    };
    packet
}

// needs the processor's secret key somehow, figure out where this will come from
// the return value could also be a message, handle this
fn unwrap_layer(packet: SphinxPacket) -> (SphinxPacket, Hop) {
    return (
        SphinxPacket {
            header: SphinxHeader {},
            payload: vec![],
        },
        Hop {
            host: Host {
                address: Address {},
                pub_key: MontgomeryPoint([0u8; 32]),
            },
            delay: Delay {},
        },
    );
}

// needs client's secret key, how should we inject this?
// needs to deal with SURBs too at some point
fn create_header(route: Vec<Hop>) -> (SphinxHeader, Vec<SharedKey>) {
    let initial_secret = generate_secret();
    let key_material = derive_key_material(&route, initial_secret);
    // compute filler strings
    // encapsulate routing information, compute MACs
    (SphinxHeader {}, vec![])
}

fn compute_shared_key(node_pub_key: MontgomeryPoint, exponent: &Scalar) -> SharedKey {
    node_pub_key * exponent
}

fn compute_blinding_factor(shared_key: MontgomeryPoint, exponent: &Scalar) -> Scalar {
    let shared_secret = CURVE_GENERATOR * exponent;
    compute_keyed_hmac(shared_secret.to_bytes(), shared_key.to_bytes())
}

// derive shared keys, group elements, blinding factors
fn derive_key_material(route: &Vec<Hop>, initial_secret: Scalar) -> KeyMaterial {
    let mut shared_keys: Vec<SharedKey> = vec![];

    let initial_shared_secret = CURVE_GENERATOR * initial_secret;
    let mut accumulator = initial_secret;

    for hop in route.iter() {
        let shared_key = compute_shared_key(hop.host.pub_key, &accumulator);
        shared_keys.push(shared_key);

        let blinding_factor = compute_blinding_factor(shared_key, &accumulator);
        accumulator = accumulator * blinding_factor;
    }

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

fn generate_secret() -> Scalar {
    let mut rng = rand_os::OsRng::new().unwrap();
    Scalar::random(&mut rng)
}

fn generate_random_curve_point() -> MontgomeryPoint {
    CURVE_GENERATOR * generate_secret()
}

// We may be able to switch from Vec to array types as an optimization,
// as in theory everything will have a constant size which we already know.
// For now we'll stick with Vecs.
fn create_enc_payload(payload: Vec<u8>, shared_keys: Vec<SharedKey>) -> Vec<u8> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let expected_blinding_factor = Scalar::from_bytes_mod_order([
            65, 236, 88, 7, 186, 168, 172, 170, 90, 46, 49, 164, 225, 73, 145, 77, 181, 151, 37,
            178, 37, 181, 248, 165, 180, 75, 103, 133, 191, 146, 10, 8,
        ]);

        let exponent = Scalar::from_bytes_mod_order([42u8; 32]);
        let shared_key = CURVE_GENERATOR * Scalar::from_bytes_mod_order([16u8; 32]);

        let blinding_factor = compute_blinding_factor(shared_key, &exponent);
        assert_eq!(expected_blinding_factor, blinding_factor)
    }

    #[test]
    fn derive_key_material_shared_keys_count_equals_hops_count() {
        let key1 = generate_random_curve_point();
        let key2 = generate_random_curve_point();
        let key3 = generate_random_curve_point();
        let route = vec![new_hop(key1), new_hop(key2), new_hop(key3)];

        let initial_secret = generate_secret();
        let key_material = derive_key_material(&route, initial_secret);
        assert_eq!(route.len(), key_material.shared_keys.len());
    }

    #[test]
    fn derive_key_material_returns_correct_initial_shared_secret() {
        let key1 = generate_random_curve_point();
        let key2 = generate_random_curve_point();
        let key3 = generate_random_curve_point();
        let route = vec![new_hop(key1), new_hop(key2), new_hop(key3)];

        let initial_secret = generate_secret();
        let key_material = derive_key_material(&route, initial_secret);

        let expected_initial_secret = CURVE_GENERATOR * initial_secret;
        assert_eq!(expected_initial_secret, key_material.initial_shared_secret);
    }

    #[test]
    fn derive_key_material_returns_uses_correct_accumulator() {
        let key1 = generate_random_curve_point();
        let key2 = generate_random_curve_point();
        let key3 = generate_random_curve_point();
        let route = vec![new_hop(key1), new_hop(key2), new_hop(key3)];

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

    fn new_hop(pub_key: MontgomeryPoint) -> Hop {
        Hop {
            host: Host {
                address: Address {},
                pub_key,
            },
            delay: Delay {},
        }
    }
}
