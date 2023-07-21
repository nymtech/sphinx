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

use crate::constants::DELAY_LENGTH;
use byteorder::{BigEndian, ByteOrder};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use rand_distr::{Distribution, Exp};
use std::{borrow::Borrow, time::Duration};

// TODO: once we get to proper refactoring, I think this should just be
// a type alias to probably time::Duration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delay(u64);

impl Delay {
    // Be more explicit about what kind of value we are expecting
    pub const fn new_from_nanos(value: u64) -> Self {
        Delay(value)
    }

    pub const fn new_from_millis(value: u64) -> Self {
        const NANOS_PER_MILLI: u64 = 1_000_000;

        Self::new_from_nanos(NANOS_PER_MILLI * value)
    }

    pub fn to_nanos(&self) -> u64 {
        self.0
    }

    pub fn to_duration(&self) -> Duration {
        Duration::from_nanos(self.0)
    }

    pub fn to_bytes(&self) -> [u8; DELAY_LENGTH] {
        let mut delay_bytes = [0; DELAY_LENGTH];
        BigEndian::write_u64(&mut delay_bytes, self.0);
        delay_bytes
    }

    pub fn from_bytes(delay_bytes: [u8; DELAY_LENGTH]) -> Self {
        Delay(BigEndian::read_u64(&delay_bytes))
    }
}

impl<T> std::iter::Sum<T> for Delay
where
    T: Borrow<Delay>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Delay(0), |acc, item| acc + item)
    }
}

impl<T> std::ops::Add<T> for &Delay
where
    T: Borrow<Delay>,
{
    type Output = Delay;
    fn add(self, rhs: T) -> Self::Output {
        *self + rhs
    }
}

impl<T> std::ops::Add<T> for Delay
where
    T: Borrow<Delay>,
{
    type Output = Delay;
    fn add(self, rhs: T) -> Self::Output {
        Delay(self.0 + rhs.borrow().0)
    }
}

impl std::ops::Mul<f64> for Delay {
    type Output = Delay;
    fn mul(self, rhs: f64) -> Self::Output {
        // TODO: the question whether it's safe-ish to do it?
        // Because for high enough delay (not sure about how "high"),
        // the casting will not be lossless.
        // Perhaps it's not a problem as we don't expect delays to realistically
        // be more than minutes/hours and definitely not thousands of thousands
        // of years.
        Delay((self.0 as f64 * rhs) as u64)
    }
}

// TODO: in both of those methods we are converting u64 to f64 to perform the division
// surely this is a lossy conversion - how much does it affect us?

pub fn generate_from_nanos(number: usize, average_delay: u64) -> Vec<Delay> {
    let exp = Exp::new(1.0 / average_delay as f64).unwrap();

    std::iter::repeat(())
        .take(number)
        .map(|_| Delay::new_from_nanos((exp.sample(&mut rand::thread_rng())).round() as u64)) // for now I just assume we will express it in nano-seconds to have an integer
        .collect()
}

pub fn generate_from_average_duration(number: usize, average_delay: Duration) -> Vec<Delay> {
    generate_from_average_duration_with_rng(number, average_delay, &mut OsRng)
}

pub fn generate_from_average_duration_with_rng<R: RngCore + CryptoRng>(
    number: usize,
    average_delay: Duration,
    rng: &mut R,
) -> Vec<Delay> {
    let exp = Exp::new(1.0 / average_delay.as_nanos() as f64).unwrap();

    std::iter::repeat(())
        .take(number)
        .map(|_| Delay::new_from_nanos(exp.sample(rng).round() as u64))
        .collect()
}

#[cfg(test)]
mod test_delay_generation {
    use super::*;

    #[test]
    fn with_0_delays_returns_an_empty_vector() {
        let delays = generate_from_average_duration(0, Duration::from_millis(10));
        assert_eq!(0, delays.len());
    }

    #[test]
    fn with_1_delay_it_returns_1_delay() {
        let delays = generate_from_average_duration(1, Duration::from_secs(1));
        assert_eq!(1, delays.len());
    }

    #[test]
    fn with_3_delays_it_returns_3_delays() {
        let delays = generate_from_average_duration(3, Duration::from_nanos(1));
        assert_eq!(3, delays.len());
    }

    #[test]
    fn it_is_possible_to_convert_it_to_and_from_bytes_without_data_loss() {
        let expected_delay_nanos = 1_234_567_890; // 1.234... s
        let delay = Delay::new_from_nanos(expected_delay_nanos);
        let delay_bytes = delay.to_bytes();
        let recovered_delay = Delay::from_bytes(delay_bytes);
        assert_eq!(delay, recovered_delay);
    }

    #[test]
    fn it_is_possible_to_convert_it_to_and_from_nanos_without_data_loss() {
        let expected_delay_nanos = 1_234_567_890; // 1.234... s
        let delay = Delay::new_from_nanos(expected_delay_nanos);
        assert_eq!(expected_delay_nanos, delay.to_nanos());
    }

    #[test]
    fn it_is_possible_to_convert_it_to_and_from_duration_without_data_loss() {
        let expected_delay_nanos = 1_234_567_890; // 1.234... s
        let delay = Delay::new_from_nanos(expected_delay_nanos);
        let delay_duration = delay.to_duration();
        assert_eq!(Duration::from_nanos(expected_delay_nanos), delay_duration);
    }
}

#[cfg(test)]
mod delay_summing {
    use super::*;

    #[test]
    fn works_with_std_ops_only() {
        let delay1 = Delay(42);
        let delay2 = Delay(123);

        let expected1 = Delay(165);
        assert_eq!(expected1, &delay1 + &delay2);

        let expected2 = Delay(265);
        let delay3 = Delay(100);
        assert_eq!(expected2, delay1 + delay2 + delay3)
    }

    #[test]
    fn works_with_iterator() {
        let delays = vec![Delay(42), Delay(123), Delay(100)];
        let expected = Delay(265);

        assert_eq!(expected, delays.iter().sum());
        assert_eq!(Delay(0), Vec::new().iter().sum())
    }
}
