use curve25519_dalek::scalar::Scalar;
use rand_os;

struct Address {}
struct Delay {}
pub struct Destination {}

pub struct Hop {
    host: Host,
    delay: Delay,
}

struct Host {
    address: Address,
    pub_key: String,
}

pub struct SenderSecret {}
struct SphinxHeader {}
pub struct SphinxPacket {
    header: SphinxHeader,
    payload: Vec<u8>,
}
struct SharedKey {}

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
                pub_key: String::from(""),
            },
            delay: Delay {},
        },
    );
}

// header: SphinxHeader, enc_payload: Vec<u8>

// needs client's secret key, how should we inject this?
// needs to deal with SURBs too at some point
fn create_header(route: Vec<Hop>) -> (SphinxHeader, Vec<SharedKey>) {
    // let secret: SenderSecret = gen_sender_secret();

    // derive shared keys, group elements, blinding factors
    // computer filler strings
    // encapsulate routing information, compute MACs
    (SphinxHeader {}, vec![])
}

fn generate_secret() -> Scalar {
    let mut rng = rand_os::OsRng::new().unwrap();
    Scalar::random(&mut rng)
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
    fn gen_sender_secret_returns_a_scalar() {
        let secret = generate_secret();
        assert_eq!(secret.to_bytes().len(), 32);
    }
}
