use crate::constants::DELAY_LENGTH;
use byteorder::{BigEndian, ByteOrder};
use rand_distr::{Distribution, Exp};
use std::time;

#[derive(Debug, Clone)]
pub struct Delay {
    value: u64,
}

impl Delay {
    pub fn new(value: u64) -> Self {
        Self { value }
    }
    pub fn to_bytes(&self) -> [u8; DELAY_LENGTH] {
        let mut delay_bytes = [0; DELAY_LENGTH];
        BigEndian::write_u64(&mut delay_bytes, self.value);
        delay_bytes
    }

    pub fn from_bytes(delay_bytes: [u8; DELAY_LENGTH]) -> Self {
        Self {
            value: BigEndian::read_u64(&delay_bytes),
        }
    }

    pub fn get_value(&self) -> u64 {
        self.value
    }
}

#[deprecated(note = "Please use the generate_from_average_duration function instead")]
pub fn generate(number: usize, average_delay: f64) -> Vec<Delay> {
    let exp = Exp::new(1.0 / average_delay).unwrap();

    std::iter::repeat(())
        .take(number)
        .map(|_| Delay::new((exp.sample(&mut rand::thread_rng()) * 1_000_000_000.0).round() as u64)) // for now I just assume we will express it in nano-seconds to have an integer
        .collect()
}

pub fn generate_from_average_duration(number: usize, average_delay: time::Duration) -> Vec<Delay> {
    let exp = Exp::new(1.0 / average_delay.as_nanos() as f64).unwrap();

    std::iter::repeat(())
        .take(number)
        .map(|_| Delay::new(exp.sample(&mut rand::thread_rng()).round() as u64))
        .collect()
}

#[cfg(test)]
mod test_delay_generation {
    use super::*;

    #[test]
    fn with_0_delays_returns_an_empty_vector() {
        let delays = generate(0, 1.0);
        assert_eq!(0, delays.len());
    }

    #[test]
    fn with_1_delay_it_returns_1_delay() {
        let delays = generate(1, 1.0);
        assert_eq!(1, delays.len());
    }

    #[test]
    fn with_3_delays_it_returns_3_delays() {
        let delays = generate(3, 1.0);
        assert_eq!(3, delays.len());
    }

    #[test]
    fn it_does_not_panic_when_generating_delays_using_time_duration() {
        let delays = generate_from_average_duration(3, time::Duration::from_secs_f64(42.0));
        assert_eq!(3, delays.len());

        let delays = generate_from_average_duration(8, time::Duration::from_nanos(42_000_000_000));
        assert_eq!(8, delays.len());
    }
}
