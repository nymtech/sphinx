use crate::constants::HEADER_INTEGRITY_MAC_SIZE;
use crate::crypto;
use crate::header::keys::HeaderIntegrityMacKey;

// In paper gamma
// the derivation is only required for the tests. please remove it in production
#[derive(Clone)]
pub struct HeaderIntegrityMac {
    value: [u8; HEADER_INTEGRITY_MAC_SIZE],
}

impl HeaderIntegrityMac {
    // TODO: perhaps change header_data to concrete type? (but then we have issue with ownership)
    pub(crate) fn compute(key: HeaderIntegrityMacKey, header_data: &[u8]) -> Self {
        let routing_info_mac = crypto::compute_keyed_hmac(key.to_vec(), &header_data);
        let mut integrity_mac = [0u8; HEADER_INTEGRITY_MAC_SIZE];
        integrity_mac.copy_from_slice(&routing_info_mac[..HEADER_INTEGRITY_MAC_SIZE]);
        Self {
            value: integrity_mac,
        }
    }

    pub fn get_value(self) -> [u8; HEADER_INTEGRITY_MAC_SIZE] {
        self.value
    }

    #[allow(dead_code)]
    pub fn get_value_ref(&self) -> &[u8] {
        self.value.as_ref()
    }

    pub fn verify(
        &self,
        integrity_mac_key: HeaderIntegrityMacKey,
        enc_routing_info: &[u8],
    ) -> bool {
        let recomputed_integrity_mac = Self::compute(integrity_mac_key, enc_routing_info);
        self.value == recomputed_integrity_mac.get_value()
    }

    pub fn from_bytes(bytes: [u8; HEADER_INTEGRITY_MAC_SIZE]) -> Self {
        Self { value: bytes }
    }
}

pub fn header_integrity_mac_fixture() -> HeaderIntegrityMac {
    HeaderIntegrityMac {
        value: [6u8; HEADER_INTEGRITY_MAC_SIZE],
    }
}

#[cfg(test)]
mod computing_integrity_mac {
    use crate::constants::INTEGRITY_MAC_KEY_SIZE;
    use crate::header::routing::MAX_ENCRYPTED_ROUTING_INFO_SIZE;

    use super::*;

    #[test]
    fn it_is_possible_to_verify_correct_mac() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let data = vec![3u8; MAX_ENCRYPTED_ROUTING_INFO_SIZE];
        let integrity_mac = HeaderIntegrityMac::compute(key, &data);

        assert!(integrity_mac.verify(key, &data));
    }

    #[test]
    fn it_lets_detecting_flipped_data_bits() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let mut data = vec![3u8; MAX_ENCRYPTED_ROUTING_INFO_SIZE];
        let integrity_mac = HeaderIntegrityMac::compute(key, &data);
        data[10] = !data[10];
        assert!(!integrity_mac.verify(key, &data));
    }
}
