use crate::header;
use crate::header::keys::PayloadKey;
use crate::route::NodeAddressBytes;

pub struct SURB {
    pub SURBHeader: header::SphinxHeader,
    pub first_hop_address: NodeAddressBytes,
    pub payload_key_material: Vec<PayloadKey>,
}
