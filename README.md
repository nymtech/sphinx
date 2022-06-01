## Sphinx

A [Sphinx](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf) packet implementation in Rust.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/github/workflow/status/nymtech/sphinx/Continuous%20integration/develop?style=for-the-badge&logo=github-actions)](https://github.com/nymtech/sphinx/actions?query=branch%3Adevelop)
[![codecov](https://img.shields.io/codecov/c/github/nymtech/sphinx?style=for-the-badge&logo=codecov)](https://codecov.io/gh/nymtech/sphinx)

### Prerequisites

* rust (stable) : https://www.rust-lang.org/
* docker (for code coverage reports): https://www.docker.com/

### Testing

`cargo test` will run the unit and integration tests.

### Code coverage reporting

If you want to find out how you're doing in terms of code coverage, [install docker](https://www.docker.com) and then run the code coverage shell script at `./scripts/coverage_report.sh`. Docker will download all the dependencies (get a coffee!), and output an HTML code coverage report at `coverage/tarpaulin-report.html`. Open the generated file in your browser to check coverage.

Unit + integration test coverage is currently well above 90%, please ensure that any pull requests maintain good test coverage.

### Benchmarks

To run benchmarks, use: 

```
cargo bench
```

Rust benchmarks run the operation multiple times to give a consistent output and report back in the number of nanoseconds (billionths of a second) per iteration. `1000000000 / result` gives you the number of operations per second.

For later reference, on Dave's i7 Dell XPS-13 laptop (our test reference machine :)) output is as follows.

```
test tests::bench_new     ... bench:     386.348 us/iter
test tests::bench_process ... bench:     157.322 us/iter
```

* `1000000 / 386.348` = 2588 packet creations per second
* `1000000 / 157.322` = 6356 packet unwrappings per second
