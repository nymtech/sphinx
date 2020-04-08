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

use rand_core::RngCore;

// xor produces new Vector with the XOR result
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());

    a.iter().zip(b.iter()).map(|(&x1, &x2)| x1 ^ x2).collect()
}

// xor_with xors assigns the result of xor to the first argument
pub fn xor_with(a: &mut [u8], b: &[u8]) {
    assert_eq!(a.len(), b.len());

    a.iter_mut()
        .zip(b.iter())
        .map(|(x1, &x2)| *x1 ^= x2)
        .collect()
}

pub fn random(number: usize) -> Vec<u8> {
    let mut rng = rand_core::OsRng;
    let mut scalar_bytes = vec![0u8; number];
    rng.fill_bytes(&mut scalar_bytes);
    scalar_bytes.to_vec()
}

#[cfg(test)]
mod test_random {
    use super::*;

    #[test]
    fn test_generating_specified_number_of_bytes() {
        let random_bytes = random(10);
        assert_eq!(10, random_bytes.len());
    }
}

#[cfg(test)]
mod test_xor_with {
    use super::*;

    #[cfg(test)]
    mod for_valid_inputs {
        use super::*;

        #[cfg(test)]
        mod for_empty_inputs {
            use super::*;

            #[test]
            fn does_not_change_initial_value() {
                let mut a: Vec<u8> = vec![];
                let b: Vec<u8> = vec![];
                xor_with(&mut a, &b);
                assert_eq!(0, a.len());
            }
        }

        #[cfg(test)]
        mod for_non_zero_inputs_of_same_length {
            use super::*;

            #[test]
            fn it_returns_the_expected_xor_of_vectors() {
                let mut a: Vec<u8> = vec![1, 2, 3];
                let b: Vec<u8> = vec![4, 5, 6];
                xor_with(&mut a, &b);
                assert_eq!(1 ^ 4, a[0]);
                assert_eq!(2 ^ 5, a[1]);
                assert_eq!(3 ^ 6, a[2]);
            }
        }
    }

    #[cfg(test)]
    mod for_invalid_inputs {
        use super::*;

        #[test]
        #[should_panic]
        fn panics_for_inputs_of_different_lengths() {
            let mut a: Vec<u8> = vec![1, 2, 3];
            let b: Vec<u8> = vec![4, 5];
            xor_with(&mut a, &b);
        }
    }
}

#[cfg(test)]
mod test_xor {
    use super::*;

    #[cfg(test)]
    mod for_valid_inputs {
        use super::*;

        #[test]
        fn for_empty_inputs_it_returns_empty_vector() {
            let a: Vec<u8> = vec![];
            let b: Vec<u8> = vec![];
            let c = xor(&a, &b);
            assert_eq!(0, c.len());
        }

        #[test]
        fn for_non_zero_inputs_of_same_length_it_returns_expected_xor() {
            let a: Vec<u8> = vec![1, 2, 3];
            let b: Vec<u8> = vec![4, 5, 6];
            let c = xor(&a, &b);
            assert_eq!(a.len(), c.len());
            for i in 0..c.len() {
                assert_eq!(c[i], a[i] ^ b[i])
            }
        }
    }

    #[cfg(test)]
    mod for_invalid_inputs {
        use super::*;

        #[test]
        #[should_panic]
        fn panics_for_inputs_of_different_lengths() {
            let a: Vec<u8> = vec![1, 2, 3];
            let b: Vec<u8> = vec![4, 5];
            let _ = xor(&a, &b);
        }
    }
}
