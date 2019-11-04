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
pub struct SphinxPacket {}
struct SharedKey {}

pub fn create_packet(message: Vec<u8>, route: Vec<Hop>) -> SphinxPacket {
    let (header, shared_keys) = create_header(route);
    let payload = create_enc_payload(message, shared_keys);
    // let packet: SphinxPacket = header.to_bytes || payload.to_bytes
    // return packet;
    SphinxPacket {}
}

// needs a secret key somehow
// the return value could also be a message, handle this
fn unwrap_layer(packet: SphinxPacket) -> (SphinxPacket, Address, Delay) {
    return (SphinxPacket {}, Address {}, Delay {});
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

// We may be able to switch from Vec to array types as an optimization,
// as in theory everything will have a constant size which we already know.
// For now we'll stick with Vecs.
fn create_enc_payload(payload: Vec<u8>, shared_keys: Vec<SharedKey>) -> Vec<u8> {
    vec![]
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
