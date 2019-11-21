CMD="cargo tarpaulin -v --output-dir coverage --out Html"
docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin sh -c "$CMD"
