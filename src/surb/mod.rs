use crate::constants::{
    DESTINATION_ADDRESS_LENGTH, NODE_ADDRESS_LENGTH, PAYLOAD_KEY_SIZE, PAYLOAD_SIZE,
    SECURITY_PARAMETER,
};
use crate::header::delays::Delay;
use crate::header::keys::PayloadKey;
use crate::payload::Payload;
use crate::route::{Destination, Node, NodeAddressBytes};
use crate::{crypto::EphemeralSecret, Error, ErrorKind, Result};
use crate::{header, SphinxPacket};
use header::{SphinxHeader, HEADER_SIZE};

#[allow(non_snake_case)]
pub struct SURB {
    /* A Single Use Reply Block (SURB) must have a pre-aggregated Sphinx header,
    the address of the first hop in the route of the SURB, and the key material
    used to layer encrypt the payload. */
    SURB_header: header::SphinxHeader,
    first_hop_address: NodeAddressBytes,
    payload_keys: Vec<PayloadKey>,
}

pub struct SURBMaterial {
    surb_route: Vec<Node>,
    surb_delays: Vec<Delay>,
    surb_destination: Destination,
}

impl SURBMaterial {
    pub fn new(route: Vec<Node>, delays: Vec<Delay>, destination: Destination) -> Self {
        SURBMaterial {
            surb_route: route,
            surb_delays: delays,
            surb_destination: destination,
        }
    }

    #[allow(non_snake_case)]
    pub fn construct_SURB(self) -> Result<SURB> {
        let surb_initial_secret = EphemeralSecret::new();
        SURB::new(surb_initial_secret, self)
    }
}

#[allow(non_snake_case)]
impl SURB {
    pub fn new(surb_initial_secret: EphemeralSecret, surb_material: SURBMaterial) -> Result<Self> {
        let surb_route = surb_material.surb_route;
        let surb_delays = surb_material.surb_delays;
        let surb_destination = surb_material.surb_destination;
        // let surb_payload_size = surb_material.surb_payload_size;

        /* Pre-computes the header of the Sphinx packet which will be used as SURB
        and encapsulates it into struct together with the address of the first hop in the route of the SURB, and the key material
        which should be used to layer encrypt the payload. */
        if surb_route.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "tried to create SURB for an empty route",
            ));
        }
        if surb_route.len() != surb_delays.len() {
            return Err(Error::new(ErrorKind::InvalidSURB, format!("creating SURB for contradictory data: route has len {} while there are {} delays generated", surb_route.len(), surb_delays.len())));
        }

        let first_hop = surb_route.first().unwrap();

        let (header, payload_keys) = header::SphinxHeader::new(
            surb_initial_secret,
            &surb_route,
            &surb_delays,
            &surb_destination,
        );

        Ok(SURB {
            SURB_header: header,
            first_hop_address: first_hop.address.clone(),
            payload_keys,
        })
    }

    pub fn use_surb(
        self,
        plaintext_message: &[u8],
        payload_size: usize,
        // TODO: surb_destination might get removed here
        // you might not know who you are replying to.
        surb_destination: &Destination,
    ) -> Result<(SphinxPacket, NodeAddressBytes)> {
        /* Function takes the precomputed surb header, layer encrypts the plaintext payload content
        using the precomputed payload key material and returns the full Sphinx packet
        together with the address of first hop to which it should be forwarded. */

        let header = self.SURB_header;

        if plaintext_message.len() + DESTINATION_ADDRESS_LENGTH > PAYLOAD_SIZE - SECURITY_PARAMETER
        {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "not enough payload left to fit a SURB",
            ));
        };

        let payload = Payload::encapsulate_message(
            &plaintext_message,
            &self.payload_keys,
            surb_destination.address.clone(),
            payload_size,
        )?;

        Ok((SphinxPacket { header, payload }, self.first_hop_address))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.SURB_header
            .to_bytes()
            .into_iter()
            .chain(self.first_hop_address.to_bytes().iter().cloned())
            .chain(self.payload_keys.iter().flat_map(|x| x.iter()).cloned())
            .collect()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // SURB needs to contain AT LEAST a single payload key
        if bytes.len() < HEADER_SIZE + NODE_ADDRESS_LENGTH + PAYLOAD_KEY_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "not enough bytes provided to try to recover a SURB",
            ));
        }

        let header_bytes = &bytes[..HEADER_SIZE];
        let first_hop_bytes = &bytes[HEADER_SIZE..HEADER_SIZE + NODE_ADDRESS_LENGTH];
        let payload_keys_bytes = &bytes[HEADER_SIZE + NODE_ADDRESS_LENGTH..];
        // make sure that bytes of valid length were sent
        if payload_keys_bytes.len() % PAYLOAD_KEY_SIZE != 0 {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "bytes of invalid length provided",
            ));
        }

        let SURB_header = SphinxHeader::from_bytes(header_bytes)?;
        let first_hop_address = NodeAddressBytes::try_from_byte_slice(first_hop_bytes)?;

        let key_count = payload_keys_bytes.len() / PAYLOAD_KEY_SIZE;
        let mut payload_keys = Vec::with_capacity(key_count);

        for i in 0..key_count {
            let mut payload_key = [0u8; PAYLOAD_KEY_SIZE];
            payload_key.copy_from_slice(
                &payload_keys_bytes[i * PAYLOAD_KEY_SIZE..(i + 1) * PAYLOAD_KEY_SIZE],
            );
            payload_keys.push(payload_key);
        }

        Ok(SURB {
            SURB_header,
            first_hop_address,
            payload_keys,
        })
    }
}

#[cfg(test)]
mod prepare_and_use_process_surb {
    use super::*;
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::crypto;
    use crate::header::{delays, HEADER_SIZE};
    use crate::{packet::builder::DEFAULT_PAYLOAD_SIZE, test_utils::fixtures::destination_fixture};
    use std::time::Duration;

    #[allow(non_snake_case)]
    fn SURB_fixture() -> SURB {
        let (_, node1_pk) = crypto::keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (_, node2_pk) = crypto::keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (_, node3_pk) = crypto::keygen();
        let node3 = Node {
            address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = destination_fixture();
        let surb_initial_secret = EphemeralSecret::new();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        SURB::new(
            surb_initial_secret,
            SURBMaterial::new(surb_route, surb_delays, surb_destination),
        )
        .unwrap()
    }

    #[test]
    fn returns_error_if_surb_route_empty() {
        let surb_route = Vec::new();
        let surb_destination = destination_fixture();
        let surb_initial_secret = EphemeralSecret::new();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));
        let expected = ErrorKind::InvalidSURB;

        match SURB::new(
            surb_initial_secret,
            SURBMaterial::new(surb_route, surb_delays, surb_destination),
        ) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when route empty"),
        };
    }

    #[test]
    fn surb_header_has_correct_length() {
        let pre_surb = SURB_fixture();
        assert_eq!(pre_surb.SURB_header.to_bytes().len(), HEADER_SIZE);
    }

    #[test]
    fn to_bytes_returns_correct_value() {
        let pre_surb = SURB_fixture();

        let pre_surb_bytes = pre_surb.to_bytes();
        let expected = [
            pre_surb.SURB_header.to_bytes(),
            [5u8; NODE_ADDRESS_LENGTH].to_vec(),
            pre_surb.payload_keys[0].to_vec(),
            pre_surb.payload_keys[1].to_vec(),
            pre_surb.payload_keys[2].to_vec(),
        ]
        .concat();
        assert_eq!(pre_surb_bytes, expected);
    }

    #[test]
    fn returns_error_is_payload_too_large() {
        let pre_surb = SURB_fixture();
        // SURB_fixture uses destination_fixture for its destination
        let surb_destination = destination_fixture();
        let plaintext_message = vec![42u8; 5000];
        let expected = ErrorKind::InvalidSURB;

        match SURB::use_surb(
            pre_surb,
            &plaintext_message,
            DEFAULT_PAYLOAD_SIZE,
            &surb_destination,
        ) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when payload bytes too long"),
        };
    }

    #[test]
    #[allow(non_snake_case)]
    fn can_be_converted_to_and_from_bytes() {
        let dummy_SURB = SURB_fixture();
        let bytes = dummy_SURB.to_bytes();
        let recovered_SURB = SURB::from_bytes(&bytes).unwrap();

        assert_eq!(
            dummy_SURB.first_hop_address,
            recovered_SURB.first_hop_address
        );
        for i in 0..dummy_SURB.payload_keys.len() {
            assert_eq!(
                dummy_SURB.payload_keys[i].to_vec(),
                recovered_SURB.payload_keys[i].to_vec()
            )
        }

        // TODO: saner way of comparing headers...
        assert_eq!(
            dummy_SURB.SURB_header.to_bytes(),
            dummy_SURB.SURB_header.to_bytes()
        );
    }
}
