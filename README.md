## Sphinx

A [Sphinx](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf) packet implementation in Rust.

[![Build Status](https://travis-ci.com/nymtech/sphinx.svg?branch=develop)](https://travis-ci.com/nymtech/sphinx)

### Prerequisites

* rust (stable) : https://www.rust-lang.org/
* docker (for code coverage reports): https://www.docker.com/

### Testing

`cargo test` will run the unit and integration tests.

### Code coverage reporting

If you want to find out how you're doing in terms of code coverage, [install docker](https://www.docker.com) and then run the code coverage shell script at `./scripts/coverage_report.sh`. Docker will download all the dependencies (get a coffee!), and output an HTML code coverage report at `coverage/tarpaulin-report.html`. Open the generated file in your browser to check coverage.

Unit + integration test coverage is currently well above 90%, please ensure that any pull requests maintain good test coverage.

### Benchmarks

Rust benchmarks are currently an unstable feature. To run them, use: 

```
rustup run nightly cargo bench
```

Rust benchmarks run the operation multiple times to give a consistent output and report back in the number of nanoseconds (billionths of a second) per iteration. `1000000000 / result` gives you the number of operations per second.

For later reference, on Dave's laptop (our test reference machine :)) output is as follows.

```
     Running target/release/deps/benchmarks-8ed6fdf75be394ab

running 2 tests
test tests::bench_new     ... bench:     386,348 ns/iter (+/- 14,901)
test tests::bench_process ... bench:     157,322 ns/iter (+/- 2,068)
```

* `1000000000 / 386348` = 2588 packet creations per second
* `1000000000 / 157322` = 6356 packet unwrappings per second