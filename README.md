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
