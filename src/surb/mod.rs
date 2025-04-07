use crate::constants::{NODE_ADDRESS_LENGTH, PAYLOAD_KEY_SEED_SIZE, PAYLOAD_KEY_SIZE};
use crate::header::delays::Delay;
use crate::payload::key::{PayloadKey, PayloadKeySeed};
use crate::payload::Payload;
use crate::route::{Destination, Node, NodeAddressBytes};
use crate::version::Version;
use crate::{header, SphinxPacket};
use crate::{Error, ErrorKind, Result};
use header::{SphinxHeader, HEADER_SIZE};
use std::fmt;
use x25519_dalek::StaticSecret;

// legacy compatibility wrapper
#[derive(Debug)]
enum PayloadKeysMaterial {
    DerivedKeys(Vec<PayloadKey>),
    KeySeeds(Vec<PayloadKeySeed>),
}

impl PayloadKeysMaterial {
    fn from_bytes(bytes: &[u8]) -> Result<PayloadKeysMaterial> {
        // given that our maximum path length is 5, payload key is 192 and key seed is 16,
        // the maximum possible size of 'updated' surb seeds is 5*16 = 80, which is smaller than
        // a single key, and thus we can use this information in order to determine which variant we should attempt to parse
        if bytes.len() < PAYLOAD_KEY_SIZE {
            // seeds
            if bytes.len() % PAYLOAD_KEY_SEED_SIZE != 0 {
                return Err(Error::new(
                    ErrorKind::InvalidSURB,
                    "bytes of invalid length provided",
                ));
            }
            let seeds_count = bytes.len() / PAYLOAD_KEY_SEED_SIZE;
            let mut payload_key_seeds = Vec::with_capacity(seeds_count);
            for i in 0..seeds_count {
                let mut payload_key = [0u8; PAYLOAD_KEY_SEED_SIZE];
                payload_key.copy_from_slice(
                    &bytes[i * PAYLOAD_KEY_SEED_SIZE..(i + 1) * PAYLOAD_KEY_SEED_SIZE],
                );
                payload_key_seeds.push(payload_key);
            }
            Ok(PayloadKeysMaterial::KeySeeds(payload_key_seeds))
        } else {
            // full keys
            if bytes.len() % PAYLOAD_KEY_SIZE != 0 {
                return Err(Error::new(
                    ErrorKind::InvalidSURB,
                    "bytes of invalid length provided",
                ));
            }
            let key_count = bytes.len() / PAYLOAD_KEY_SIZE;
            let mut payload_keys = Vec::with_capacity(key_count);
            for i in 0..key_count {
                let mut payload_key = [0u8; PAYLOAD_KEY_SIZE];
                payload_key
                    .copy_from_slice(&bytes[i * PAYLOAD_KEY_SIZE..(i + 1) * PAYLOAD_KEY_SIZE]);
                payload_keys.push(payload_key);
            }
            Ok(PayloadKeysMaterial::DerivedKeys(payload_keys))
        }
    }
}

/// A Single Use Reply Block (SURB) must have a pre-aggregated Sphinx header,
/// the address of the first hop in the route of the SURB, and the key material
/// used to layer encrypt the payload.
#[allow(non_snake_case)]
pub struct SURB {
    SURB_header: header::SphinxHeader,
    first_hop_address: NodeAddressBytes,
    payload_keys_material: PayloadKeysMaterial,
}

impl fmt::Debug for SURB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SURB")
            .field("SURB_header", &self.SURB_header)
            .field("first_hop_address", &self.first_hop_address)
            .field("payload_keys_material", &self.payload_keys_material)
            .finish()
    }
}

pub struct SURBMaterial {
    surb_route: Vec<Node>,
    surb_delays: Vec<Delay>,
    surb_destination: Destination,
    version: Version,
}

impl SURBMaterial {
    pub fn new(route: Vec<Node>, delays: Vec<Delay>, destination: Destination) -> Self {
        SURBMaterial {
            surb_route: route,
            surb_delays: delays,
            surb_destination: destination,
            version: Default::default(),
        }
    }

    #[allow(non_snake_case)]
    pub fn construct_legacy_SURB(self) -> Result<SURB> {
        let surb_initial_secret = StaticSecret::random();
        SURB::new(surb_initial_secret, self)
    }

    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }
}

#[allow(non_snake_case)]
impl SURB {
    pub fn new(surb_initial_secret: StaticSecret, surb_material: SURBMaterial) -> Result<Self> {
        let surb_route = surb_material.surb_route;
        let surb_delays = surb_material.surb_delays;
        let surb_destination = surb_material.surb_destination;

        /* Pre-computes the header of the Sphinx packet which will be used as SURB
        and encapsulates it into struct together with the address of the first hop in the route of the SURB, and the key material
        which should be used to layer encrypt the payload. */
        let Some(first_hop) = surb_route.first() else {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "tried to create SURB for an empty route",
            ));
        };

        if surb_route.len() != surb_delays.len() {
            return Err(Error::new(ErrorKind::InvalidSURB, format!("creating SURB for contradictory data: route has len {} while there are {} delays generated", surb_route.len(), surb_delays.len())));
        }

        #[allow(deprecated)]
        let built_header = header::SphinxHeader::new_versioned(
            &surb_initial_secret,
            &surb_route,
            &surb_delays,
            &surb_destination,
            surb_material.version,
        );

        if surb_material.version.expects_legacy_full_payload_keys() {
            Ok(SURB {
                first_hop_address: first_hop.address,
                payload_keys_material: PayloadKeysMaterial::DerivedKeys(
                    built_header.legacy_full_payload_keys(),
                ),
                SURB_header: built_header.into_header(),
            })
        } else {
            Ok(SURB {
                first_hop_address: first_hop.address,
                payload_keys_material: PayloadKeysMaterial::KeySeeds(
                    built_header.payload_key_seeds(),
                ),
                SURB_header: built_header.into_header(),
            })
        }
    }

    /// Function takes the precomputed surb header, layer encrypts the plaintext payload content
    /// using the precomputed payload key material and returns the full Sphinx packet
    /// together with the address of first hop to which it should be forwarded.
    pub fn use_surb(
        self,
        plaintext_message: &[u8],
        payload_size: usize,
    ) -> Result<(SphinxPacket, NodeAddressBytes)> {
        let header = self.SURB_header;

        // Note that Payload::encapsulate_message performs checks to verify whether the plaintext
        // is going to fit in the packet.
        let payload = match self.payload_keys_material {
            PayloadKeysMaterial::DerivedKeys(keys) => {
                Payload::encapsulate_message(plaintext_message, keys.as_slice(), payload_size)?
            }
            PayloadKeysMaterial::KeySeeds(seeds) => {
                Payload::encapsulate_message(plaintext_message, &seeds, payload_size)?
            }
        };

        Ok((SphinxPacket { header, payload }, self.first_hop_address))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let initial_bytes = self
            .SURB_header
            .to_bytes()
            .into_iter()
            .chain(self.first_hop_address.to_bytes());

        match &self.payload_keys_material {
            PayloadKeysMaterial::DerivedKeys(keys) => initial_bytes
                .chain(keys.iter().flat_map(|k| k.iter().copied()))
                .collect(),
            PayloadKeysMaterial::KeySeeds(seeds) => initial_bytes
                .chain(seeds.iter().flat_map(|s| s.iter().copied()))
                .collect(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // SURB needs to contain AT LEAST a single payload key (or seed)
        if bytes.len() < HEADER_SIZE + NODE_ADDRESS_LENGTH + PAYLOAD_KEY_SEED_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "not enough bytes provided to try to recover a SURB",
            ));
        }

        let header_bytes = &bytes[..HEADER_SIZE];
        let first_hop_bytes = &bytes[HEADER_SIZE..HEADER_SIZE + NODE_ADDRESS_LENGTH];
        let payload_keys_material_bytes = &bytes[HEADER_SIZE + NODE_ADDRESS_LENGTH..];

        let SURB_header = SphinxHeader::from_bytes(header_bytes)?;
        let first_hop_address = NodeAddressBytes::try_from_byte_slice(first_hop_bytes)?;
        let payload_keys_material = PayloadKeysMaterial::from_bytes(payload_keys_material_bytes)?;

        Ok(SURB {
            SURB_header,
            first_hop_address,
            payload_keys_material,
        })
    }
}

#[cfg(test)]
mod prepare_and_use_process_surb {
    use super::*;
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::header::{delays, HEADER_SIZE};
    use crate::version::{PAYLOAD_KEYS_SEEDS_VERSION, X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION};
    use crate::{
        packet::builder::DEFAULT_PAYLOAD_SIZE,
        test_utils::fixtures::{destination_fixture, keygen},
    };
    use std::time::Duration;

    fn surb_material_fixture() -> SURBMaterial {
        let (_, node1_pk) = keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (_, node2_pk) = keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (_, node3_pk) = keygen();
        let node3 = Node {
            address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = destination_fixture();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        SURBMaterial::new(surb_route, surb_delays, surb_destination)
    }

    #[allow(non_snake_case)]
    fn legacy_SURB_fixture() -> SURB {
        let surb_initial_secret = StaticSecret::random();
        let surb_material =
            surb_material_fixture().with_version(X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION);

        SURB::new(surb_initial_secret, surb_material).unwrap()
    }

    #[allow(non_snake_case)]
    fn seeded_SURB_fixture() -> SURB {
        let surb_initial_secret = StaticSecret::random();
        let surb_material = surb_material_fixture().with_version(PAYLOAD_KEYS_SEEDS_VERSION);

        SURB::new(surb_initial_secret, surb_material).unwrap()
    }

    #[test]
    fn returns_error_if_surb_route_empty() {
        let surb_route = Vec::new();
        let surb_destination = destination_fixture();
        let surb_initial_secret = StaticSecret::random();
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
        let pre_surb = legacy_SURB_fixture();
        assert_eq!(pre_surb.SURB_header.to_bytes().len(), HEADER_SIZE);
    }

    #[test]
    fn to_bytes_returns_correct_value() {
        let pre_surb = legacy_SURB_fixture();
        let PayloadKeysMaterial::DerivedKeys(keys) = &pre_surb.payload_keys_material else {
            unreachable!()
        };

        let pre_surb_bytes = pre_surb.to_bytes();
        let expected = [
            pre_surb.SURB_header.to_bytes(),
            [5u8; NODE_ADDRESS_LENGTH].to_vec(),
            keys[0].to_vec(),
            keys[1].to_vec(),
            keys[2].to_vec(),
        ]
        .concat();
        assert_eq!(pre_surb_bytes, expected);

        let pre_surb = seeded_SURB_fixture();
        let PayloadKeysMaterial::KeySeeds(seeds) = &pre_surb.payload_keys_material else {
            unreachable!()
        };

        let pre_surb_bytes = pre_surb.to_bytes();
        let expected = [
            pre_surb.SURB_header.to_bytes(),
            [5u8; NODE_ADDRESS_LENGTH].to_vec(),
            seeds[0].to_vec(),
            seeds[1].to_vec(),
            seeds[2].to_vec(),
        ]
        .concat();
        assert_eq!(pre_surb_bytes, expected);
    }

    #[test]
    fn returns_error_is_payload_too_large() {
        let pre_surb = legacy_SURB_fixture();
        let plaintext_message = vec![42u8; 5000];
        let expected = ErrorKind::InvalidPayload;

        match SURB::use_surb(pre_surb, &plaintext_message, DEFAULT_PAYLOAD_SIZE) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when payload bytes too long"),
        };
    }

    #[test]
    #[allow(non_snake_case)]
    fn can_be_converted_to_and_from_bytes_with_legacy_keys() {
        let dummy_SURB = legacy_SURB_fixture();
        let bytes = dummy_SURB.to_bytes();
        let recovered_SURB = SURB::from_bytes(&bytes).unwrap();

        assert_eq!(
            dummy_SURB.first_hop_address,
            recovered_SURB.first_hop_address
        );

        let PayloadKeysMaterial::DerivedKeys(original_keys) = &dummy_SURB.payload_keys_material
        else {
            unreachable!()
        };

        let PayloadKeysMaterial::DerivedKeys(recovered_keys) =
            &recovered_SURB.payload_keys_material
        else {
            unreachable!()
        };

        for i in 0..original_keys.len() {
            assert_eq!(original_keys[i], recovered_keys[i])
        }

        // TODO: saner way of comparing headers...
        assert_eq!(
            dummy_SURB.SURB_header.to_bytes(),
            dummy_SURB.SURB_header.to_bytes()
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn can_be_converted_to_and_from_bytes_with_key_seeds() {
        let dummy_SURB = seeded_SURB_fixture();
        let bytes = dummy_SURB.to_bytes();
        let recovered_SURB = SURB::from_bytes(&bytes).unwrap();

        assert_eq!(
            dummy_SURB.first_hop_address,
            recovered_SURB.first_hop_address
        );

        let PayloadKeysMaterial::KeySeeds(original_seeds) = &dummy_SURB.payload_keys_material
        else {
            unreachable!()
        };

        let PayloadKeysMaterial::KeySeeds(recovered_seeds) = &recovered_SURB.payload_keys_material
        else {
            unreachable!()
        };

        for i in 0..original_seeds.len() {
            assert_eq!(original_seeds[i], recovered_seeds[i])
        }

        // TODO: saner way of comparing headers...
        assert_eq!(
            dummy_SURB.SURB_header.to_bytes(),
            dummy_SURB.SURB_header.to_bytes()
        );
    }
}
