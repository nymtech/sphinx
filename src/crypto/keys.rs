// Copyright 2020 Nym Technologies SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Ideally we would have used pure x25519_dalek implementation and created a wrapper for
// it, but unfortunately it's not an option as what we're doing here is not 'pure'
// x25519, as we require (in form of optimization, TODO: WHICH WE MUST ACTUALLY LEARN IF ITS
// NOT A VULNERABILITY) multiplying scalars together before exponentiation, i.e.
// to obtain g^{xyz} we compute `tmp = x*y*z` followed by g^tmp rather than
// G1 = g^x, G2 = G1^y, G3 = G2^z

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, montgomery::MontgomeryPoint, scalar::Scalar,
};
use rand::{rngs::OsRng, CryptoRng, RngCore};

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SHARED_SECRET_SIZE: usize = PUBLIC_KEY_SIZE;

// this is specific to our keys being on curve25519;
// if not done, it could introduce attacks involving use
// of small-order points (and some side-channel attacks I think?).
// TODO: could an ECC 'expert' verify those claims?
pub fn clamp_scalar_bytes(mut scalar_bytes: [u8; PRIVATE_KEY_SIZE]) -> Scalar {
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;

    Scalar::from_bits(scalar_bytes)
}

// TODO: similarly to what x25519_dalek is doing, we should probably
// derive zeroize::Zeroize on drop here
pub struct PrivateKey(Scalar);

#[allow(clippy::derive_hash_xor_eq)] // TODO: we must be careful about that one if anything changes in the future
#[derive(Copy, Clone, Debug, Hash)]
pub struct PublicKey(MontgomeryPoint);

// type aliases for easier reasoning
pub type EphemeralSecret = PrivateKey;
pub type SharedSecret = PublicKey;

impl PrivateKey {
    /// Perform a key exchange with another public key
    pub fn diffie_hellman(&self, remote_public_key: &PublicKey) -> SharedSecret {
        PublicKey(self.0 * remote_public_key.0)
    }

    // Do not expose this. It can lead to serious security issues if used incorrectly.
    pub(crate) fn clone(&self) -> Self {
        PrivateKey(self.0)
    }

    // honestly, this method shouldn't really exist, but right now we have no decent
    // rng propagation in the library
    pub fn new() -> Self {
        Self::new_with_rng(&mut OsRng)
    }

    pub fn new_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; PRIVATE_KEY_SIZE];
        rng.fill_bytes(&mut bytes);
        PrivateKey(clamp_scalar_bytes(bytes))
    }

    pub fn to_bytes(&self) -> [u8; PRIVATE_KEY_SIZE] {
        self.0.to_bytes()
    }
}

impl Default for PrivateKey {
    fn default() -> Self {
        PrivateKey::new()
    }
}

// TODO: is this 'safe' ?
impl<'a, 'b> std::ops::Mul<&'b Scalar> for &'a EphemeralSecret {
    type Output = EphemeralSecret;
    fn mul(self, rhs: &'b Scalar) -> EphemeralSecret {
        PrivateKey(self.0 * rhs)
    }
}

impl<'b> std::ops::MulAssign<&'b Scalar> for EphemeralSecret {
    fn mul_assign(&mut self, _rhs: &'b Scalar) {
        self.0.mul_assign(_rhs)
    }
}

impl From<Scalar> for EphemeralSecret {
    fn from(scalar: Scalar) -> EphemeralSecret {
        // TODO: should we ensure it's a valid scalar by performing
        // montgomery reduction and/or clamping?
        PrivateKey(scalar)
    }
}

impl From<[u8; PRIVATE_KEY_SIZE]> for PrivateKey {
    fn from(bytes: [u8; 32]) -> PrivateKey {
        // TODO: do we have to clamp it here?
        PrivateKey(clamp_scalar_bytes(bytes))
    }
}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        self.0.as_bytes()
    }
}

impl<'a> From<&'a PrivateKey> for PublicKey {
    fn from(private_key: &'a PrivateKey) -> PublicKey {
        // multiplication in edwards using the precomputed ed25519 basepoint table is over 3x quicker
        // than multiplication inside montgomery using the curve generator
        PublicKey((&ED25519_BASEPOINT_TABLE * &private_key.0).to_montgomery())
    }
}

impl From<[u8; PUBLIC_KEY_SIZE]> for PublicKey {
    fn from(bytes: [u8; PUBLIC_KEY_SIZE]) -> PublicKey {
        PublicKey(MontgomeryPoint(bytes))
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Eq for PublicKey {}

pub fn keygen() -> (PrivateKey, PublicKey) {
    keygen_with_rng(&mut OsRng)
}

pub fn keygen_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> (PrivateKey, PublicKey) {
    let private_key = PrivateKey::new_with_rng(rng);
    let public_key = PublicKey::from(&private_key);
    (private_key, public_key)
}
