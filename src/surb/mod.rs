use crate::constants::{DESTINATION_ADDRESS_LENGTH, PAYLOAD_SIZE, SECURITY_PARAMETER};
use crate::header::delays::Delay;
use crate::header::keys::PayloadKey;
use crate::payload::Payload;
use crate::route::{Destination, Node, NodeAddressBytes};
use crate::{header, SphinxPacket};
use crate::{Error, ErrorKind, Result};
use curve25519_dalek::scalar::Scalar;

#[derive(Clone)]
pub struct SURB {
    /* A Single Use Reply Block (SURB) must have a pre-aggregated Sphinx header,
    the address of the first hop in the route of the SURB, and the key material
    used to layer encrypt the payload. */
    pub SURBHeader: header::SphinxHeader,
    pub first_hop_address: NodeAddressBytes,
    pub payload_keys: Vec<PayloadKey>,
}

impl SURB {
    pub fn new(
        surb_initial_secret: Scalar,
        surb_route: &[Node],
        surb_delays: &[Delay],
        surb_destination: &Destination,
    ) -> Result<Self> {
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
            surb_route,
            surb_delays,
            surb_destination,
        );

        Ok(SURB {
            SURBHeader: header,
            first_hop_address: first_hop.address.clone(),
            payload_keys: payload_keys,
        })
    }

    pub fn use_surb(
        self,
        plaintext_message: &[u8],
        surb_destination: &Destination,
    ) -> Result<(SphinxPacket, NodeAddressBytes)> {
        /* Function takes the precomputed surb header, layer encrypts the plaintext payload content
        using the precomputed payload key material and returns the full Sphinx packet
        together with the address of first hop to which it should be forwarded. */

        let header = self.SURBHeader;

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
        )?;

        Ok((SphinxPacket { header, payload }, self.first_hop_address))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.SURBHeader
            .to_bytes()
            .iter()
            .cloned()
            .chain(self.first_hop_address.to_bytes().iter().cloned())
            .chain(self.payload_keys.iter().flat_map(|x| x.iter()).cloned())
            .collect()
    }
}

#[cfg(test)]
mod prepare_and_use_process_surb {
    use super::*;
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::crypto;
    use crate::header::{delays, HEADER_SIZE};
    use crate::route::destination_fixture;
    use std::time::Duration;

    #[test]
    fn returns_error_if_surb_route_empty() {
        let surb_route = [];
        let surb_destination = destination_fixture();
        let surb_initial_secret = crypto::generate_secret();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));
        let expected = ErrorKind::InvalidSURB;

        match SURB::new(
            surb_initial_secret,
            &surb_route,
            &surb_delays,
            &surb_destination,
        ) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when route empty"),
        };
    }

    #[test]
    fn surb_header_has_correct_length() {
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

        let surb_route = [node1, node2, node3];
        let surb_destination = destination_fixture();
        let surb_initial_secret = crypto::generate_secret();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = SURB::new(
            surb_initial_secret,
            &surb_route,
            &surb_delays,
            &surb_destination,
        )
        .unwrap();

        assert_eq!(pre_surb.SURBHeader.to_bytes().len(), HEADER_SIZE);
    }

    #[test]
    fn to_bytes_returns_correct_value() {
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

        let surb_route = [node1, node2, node3];
        let surb_destination = destination_fixture();
        let surb_initial_secret = crypto::generate_secret();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = SURB::new(
            surb_initial_secret,
            &surb_route,
            &surb_delays,
            &surb_destination,
        )
        .unwrap();

        let pre_surb_bytes = pre_surb.to_bytes();
        let expected = [
            pre_surb.SURBHeader.to_bytes(),
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

        let surb_route = [node1, node2, node3];
        let surb_destination = destination_fixture();
        let surb_initial_secret = crypto::generate_secret();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        let pre_surb = SURB::new(
            surb_initial_secret,
            &surb_route,
            &surb_delays,
            &surb_destination,
        )
        .unwrap();
        let plaintext_message = vec![42u8; 5000];
        let expected = ErrorKind::InvalidSURB;

        match SURB::use_surb(pre_surb, &plaintext_message, &surb_destination) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when payload bytes too long"),
        };
    }
}
