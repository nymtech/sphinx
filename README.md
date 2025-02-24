## Sphinx

A [Sphinx](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf) packet implementation in Rust.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/nymtech/sphinx/build.yml?branch=develop&style=for-the-badge&logo=github-actions)](https://github.com/nymtech/sphinx/actions?query=branch%3Adevelop)

### Prerequisites

* rust (stable) : https://www.rust-lang.org/
* docker (for code coverage reports): https://www.docker.com/

### Testing

`cargo test` will run the unit and integration tests.

### Versioning

Whilst this crate hasn't been strictly following the semver versioning conventions, the following changes have been
made:

#### v0.1.0

initial release

#### v0.1.1

updates crypto dependencies, including dalek libraries

#### v0.2.0

fixes uses of undefined scalar multiplications and transitions to using pure x25519 instead

#### v0.3.0

allows using the library with either the v0.2.0 or v0.1.1 crypto (for backwards compatibility reasons). it also changes
the public API to expose version information which has further been reinterpreted to no longer map to the semver version
of this library

#### v0.3.1

added additional public methods on the `Version`

#### v0.4.0

removed processing and creation of packets with undefined operations

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
