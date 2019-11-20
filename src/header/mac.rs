use crate::constants::HEADER_INTEGRITY_MAC_SIZE;
use crate::header::keys::HeaderIntegrityMacKey;
use crate::utils::crypto;

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

    pub fn get_value_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

pub fn header_integrity_mac_fixture() -> HeaderIntegrityMac {
    HeaderIntegrityMac {
        value: [6u8; HEADER_INTEGRITY_MAC_SIZE],
    }
}

#[cfg(test)]
mod computing_integrity_mac {
    use super::*;
    use crate::constants::INTEGRITY_MAC_KEY_SIZE;
    use crate::header::routing::ENCRYPTED_ROUTING_INFO_SIZE;

    #[test]
    fn it_is_possible_to_verify_correct_mac() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let data = vec![3u8; ENCRYPTED_ROUTING_INFO_SIZE];
        let integrity_mac = HeaderIntegrityMac::compute(key, &data);

        let mut computed_mac = crypto::compute_keyed_hmac(key.to_vec(), &data.to_vec());
        computed_mac.truncate(HEADER_INTEGRITY_MAC_SIZE);
        assert_eq!(computed_mac, integrity_mac.value);
    }

    #[test]
    fn it_lets_detecting_flipped_data_bits() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let mut data = vec![3u8; ENCRYPTED_ROUTING_INFO_SIZE];
        let integrity_mac = HeaderIntegrityMac::compute(key, &data);
        data[10] = !data[10];
        let mut computed_mac = crypto::compute_keyed_hmac(key.to_vec(), &data.to_vec());
        computed_mac.truncate(HEADER_INTEGRITY_MAC_SIZE);
        assert_ne!(computed_mac, integrity_mac.value);
    }
}
