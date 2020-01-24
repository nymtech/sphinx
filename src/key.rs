use curve25519_dalek::montgomery::MontgomeryPoint;

type Key = MontgomeryPoint;

pub fn new(bytes: [u8; 32]) -> Key {
    MontgomeryPoint(bytes)
}
