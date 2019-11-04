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
    shared_keys: Vec<SharedKey>,
}

struct SphinxHeader {}
pub struct SphinxPacket {
    header: SphinxHeader,
    payload: Vec<u8>,
}
type SharedKey = MontgomeryPoint;

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
    let key_material = derive_key_material(&route);
    // compute filler strings
    // encapsulate routing information, compute MACs
    (SphinxHeader {}, vec![])
}

// derive shared keys, group elements, blinding factors
fn derive_key_material(route: &Vec<Hop>) -> KeyMaterial {
    let secret = generate_secret();

    // do group element 0
    let alpha0 = curve25519_dalek::constants::X25519_BASEPOINT * secret;
    // generate first shared key 0
    let hop_key0 = route[0].host.pub_key;
    let shared_key0 = hop_key0 * secret;

    let mut mac =
        HmacSha256::new_varkey(&alpha0.to_bytes()).expect("HMAC can take key of any size");
    mac.input(&shared_key0.to_bytes());
    let mut output = [0u8; 32];
    output.copy_from_slice(&mac.result().code().to_vec()[..32]);
    let blinding_factor0 = Scalar::from_bytes_mod_order(output);

    let tmp1 = secret * blinding_factor0;
    let alpha1 = curve25519_dalek::constants::X25519_BASEPOINT * tmp1;
    let shared_key1 = route[1].host.pub_key * tmp1;

    let mut mac =
        HmacSha256::new_varkey(&alpha1.to_bytes()).expect("HMAC can take key of any size");
    mac.input(&shared_key1.to_bytes());
    let mut output = [0u8; 32];
    output.copy_from_slice(&mac.result().code().to_vec()[..32]);
    let blinding_factor1 = Scalar::from_bytes_mod_order(output);

    let tmp2 = secret * blinding_factor0 * blinding_factor1;
    let alpha2 = curve25519_dalek::constants::X25519_BASEPOINT * tmp2;
    let shared_key2 = route[2].host.pub_key * tmp2;

    let mut mac =
        HmacSha256::new_varkey(&alpha2.to_bytes()).expect("HMAC can take key of any size");
    mac.input(&shared_key2.to_bytes());
    let mut output = [0u8; 32];
    output.copy_from_slice(&mac.result().code().to_vec()[..32]);
    let blinding_factor2 = Scalar::from_bytes_mod_order(output);

    KeyMaterial {
        shared_keys: vec![shared_key0, shared_key1, shared_key2],
    }
}

fn generate_secret() -> Scalar {
    let mut rng = rand_os::OsRng::new().unwrap();
    Scalar::random(&mut rng)
}

fn generate_curve_point() -> MontgomeryPoint {
    curve25519_dalek::constants::X25519_BASEPOINT * generate_secret()
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
        let secret = generate_curve_point();
        assert_eq!(32, secret.to_bytes().len())
    }
    #[test]
    fn derive_key_material_shared_keys_count_equals_hops_count() {
        let key1 = generate_curve_point();
        let key2 = generate_curve_point();
        let key3 = generate_curve_point();
        let route = vec![new_hop(key1), new_hop(key2), new_hop(key3)];
        let key_material = derive_key_material(&route);
        assert_eq!(route.len(), key_material.shared_keys.len());
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
