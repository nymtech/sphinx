use crate::constants::DELAY_LENGTH;
use byteorder::{BigEndian, ByteOrder};
use rand_distr::{Distribution, Exp};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Delay(u64);

impl Delay {
    // Be more explicit about what kind of value we are expecting
    pub fn new_from_nanos(value: u64) -> Self {
        Delay(value)
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
    let exp = Exp::new(1.0 / average_delay.as_nanos() as f64).unwrap();

    std::iter::repeat(())
        .take(number)
        .map(|_| Delay::new_from_nanos(exp.sample(&mut rand::thread_rng()).round() as u64))
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
}
