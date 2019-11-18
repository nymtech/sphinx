use crate::header::keys::PayloadKey;

// We may be able to switch from Vec to array types as an optimization,
// as in theory everything will have a constant size which we already know.
// For now we'll stick with Vecs.
pub fn create(payload: Vec<u8>, shared_keys: Vec<PayloadKey>) -> Vec<u8> {
    vec![]
}
