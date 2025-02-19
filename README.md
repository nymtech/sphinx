## Sphinx

A [Sphinx](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf) packet implementation in Rust.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/nymtech/sphinx/build.yml?branch=develop&style=for-the-badge&logo=github-actions)](https://github.com/nymtech/sphinx/actions?query=branch%3Adevelop)

### Prerequisites

* rust (stable) : https://www.rust-lang.org/
* docker (for code coverage reports): https://www.docker.com/

### Testing

`cargo test` will run the unit and integration tests.

### Benchmarks

To run benchmarks, use:

```
cargo bench
```

Rust benchmarks run the operation multiple times to give a consistent output and report back in the number of
nanoseconds (billionths of a second) per iteration. `1000000000 / result` gives you the number of operations per second.

For later reference, on Dave's i7 Dell XPS-13 (2018) laptop (our test reference machine :)) output is as follows.

```
test tests::bench_new     ... bench:     386.348 us/iter
test tests::bench_process ... bench:     157.322 us/iter
```

* `1000000 / 386.348` = ~2588 packet creations per second
* `1000000 / 157.322` = ~6356 packet unwrappings per second
