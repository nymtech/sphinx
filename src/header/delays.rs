use rand_distr::{Distribution, Exp};

#[cfg(test)]
use speculate::speculate;

use crate::constants;

pub(crate) fn generate(number: usize) -> Vec<f64> {
    let exp = Exp::new(1.0 / constants::AVERAGE_DELAY).unwrap();

    std::iter::repeat(())
        .take(number)
        .map(|_| exp.sample(&mut rand::thread_rng()))
        .collect()
}

#[cfg(test)]
speculate! {
    describe "generating delays" {
        context "for 0 delays" {
            it "returns an empty delays vector" {
                let delays = generate(0);
                assert_eq!(0, delays.len());
            }
        }

        context "for 1 delay" {
            it "returns 1 delay" {
                let delays = generate(1);
                assert_eq!(1, delays.len());
            }
        }

        context "for 3 delays" {
            it "returns 3 delays" {
                let delays = generate(3);
                assert_eq!(3, delays.len());
            }
        }
    }
}
