#!/bin/bash



# Set the directory containing the tests to run (includes subdirectories)
TEST_DIR=.

# Set the directory to which the report will be saved
COVERAGE_DIR=coverage

# This needs to run in sphinx
SPHINX_DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && cd .. && pwd)"
if [ "$(pwd)" != "$SPHINX_DIR"  ]
then
        echo "Error: This needs to run from sphinx/, not in $(pwd)" >&2
        exit 1
fi

set -e

# Check that grcov is installed
if ! [ -x "$(command -v grcov)" ]; then
        echo "Error: grcov is not installed." >&2

        read -p "Install grcov? [yY/*] " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]
        then
                [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
        fi
        cargo install grcov

fi

# Check that lcov is installed
if ! [ -x "$(command -v lcov)" ]; then
        echo "Error: lcov is not installed." >&2
        echo "Documentation for lcov can be found at http://ltp.sourceforge.net/coverage/lcov.php"
        echo "If on Linux and using apt, run 'sudo apt install lcov'"
        echo "If on macOS and using homebrew, run 'brew install lcov'"
        exit 1
fi

# Warn that cargo clean will happen


# Set the flags necessary for coverage output
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Zno-landing-pads -Coverflow-checks=off -Clink-dead-code"
export CARGO_INCREMENTAL=0

# Clean the project
echo "Cleaning project..."
(cd "$TEST_DIR"; cargo +nightly clean)

# Run tests
echo "Running tests..."
while read -r line; do
        dirline=$(realpath $(dirname "$line"));
        (cd "$dirline"; cargo +nightly test --all-features)
done < <(find "$TEST_DIR" -name 'Cargo.toml')

# Make the coverage directory if it doesn't exist
if [ ! -d "$COVERAGE_DIR" ]; then
        mkdir "$COVERAGE_DIR";
fi

# Generate lcov report
echo "Generating lcov report at ${COVERAGE_DIR}/lcov.info..."
grcov target -t lcov  --llvm --branch --ignore "/*" -o "$COVERAGE_DIR/lcov.info"

# Generate HTML report
echo "Generating report at ${COVERAGE_DIR}..."
# Flag "--ignore-errors source" ignores missing source files
genhtml -o "$COVERAGE_DIR" --show-details --highlight --ignore-errors source --legend "$COVERAGE_DIR/lcov.info"

echo "Done. Please view report at ${COVERAGE_DIR}/index.html"
