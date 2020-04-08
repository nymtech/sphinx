use crate::constants::{DESTINATION_ADDRESS_LENGTH, PAYLOAD_SIZE, SECURITY_PARAMETER};
use crate::header::delays::Delay;
use crate::header::keys::PayloadKey;
use crate::header::SphinxError;
use crate::payload::Payload;
use crate::route::{Destination, Node, NodeAddressBytes};
use crate::{crypto, header, SphinxPacket};
use curve25519_dalek::scalar::Scalar;

#[derive(Clone)]
pub struct SURB {
    /// A Single Use Reply Block (SURB) must have a pre-aggregated Sphinx header,
    /// the address of the first hop in the route of the SURB, and the key material
    /// used to layer encrypt the payload.
    pub SURBHeader: header::SphinxHeader,
    pub first_hop_address: NodeAddressBytes,
    pub payload_keys: Vec<PayloadKey>,
}

#[derive(Debug, PartialEq)]
pub enum SURBError {
    IncorrectSURBRoute,
}

impl SURB {
    pub fn new(
        surb_initial_secret: Scalar,
        surb_route: &[Node],
        surb_delays: &[Delay],
        surb_destination: &Destination,
    ) -> Result<Self, SURBError> {
        /// Precomputes the header of the Sphinx packet which will be used as SURB
        /// and encapsulates it into struct together with the address of the first hop in the route of the SURB, and the key material
        /// which should be used to layer encrypt the payload.
        assert_eq!(surb_route.len(), surb_delays.len());

        let first_hop = surb_route.first().ok_or(SURBError::IncorrectSURBRoute)?;

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
    ) -> Result<(SphinxPacket, NodeAddressBytes), SphinxError> {
        /// Function takes the precomputed surb header, layer encrypts the plaintext payload content
        /// using the precomputed payload key material and returns the full Sphinx packet
        /// together with the address of first hop to which it should be forwarded.
        let header = self.SURBHeader;

        if plaintext_message.len() + DESTINATION_ADDRESS_LENGTH > PAYLOAD_SIZE - SECURITY_PARAMETER
        {
            return Err(SphinxError::NotEnoughPayload);
        };

        let payload = Payload::encapsulate_message(
            &plaintext_message,
            &self.payload_keys,
            surb_destination.address.clone(),
        )?;

        Ok((SphinxPacket { header, payload }, self.first_hop_address))
    }
}

#[cfg(test)]
mod prepare_and_use_process_surb {
    use super::*;
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::header::delays;
    use crate::route::destination_fixture;
    use std::time::Duration;

    #[test]
    fn returns_error_if_surb_route_empty() {
        let surb_route = [];
        let surb_destination = destination_fixture();
        let surb_initial_secret = crypto::generate_secret();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));
        let expected = SURBError::IncorrectSURBRoute;

        match SURB::new(
            surb_initial_secret,
            &surb_route,
            &surb_delays,
            &surb_destination,
        ) {
            Err(err) => assert_eq!(expected, err),
            _ => panic!("Should have returned an error when route empty"),
        };
    }

    #[test]
    fn returns_error_is_payload_too_large() {
        let (node1_sk, node1_pk) = crypto::keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk, node2_pk) = crypto::keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk, node3_pk) = crypto::keygen();
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
        let expected = SphinxError::NotEnoughPayload;

        match SURB::use_surb(pre_surb, &plaintext_message, &surb_destination) {
            Err(err) => assert_eq!(expected, err),
            _ => panic!("Should have returned an error when payload bytes too long"),
        };
    }
}
