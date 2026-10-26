# HNF production line

Versioned transformation and verification tooling for an accepted Hermes sealed-release candidate.

Model: exact immutable sealed d3 release artifact -> two immutable source patches -> deterministic unchecked-hash `.pyc` outputs -> full candidate inventory -> focused/regression tests -> secret scan -> clean reproduction -> read-only rollback verification.

This is not a source-only rebuild and does not perform deployment, service restart, repository administration, dependency updates, or remote publication by itself.

Run the local verification with explicit runtime inputs:

```sh
python tools/hnf_production_line_b1/local_ci.py \
  --sealed-release <sealed-release> \
  --test-python <accepted-test-python> \
  --tool-search-regression-root <tool-search-regression-root> \
  --website-regression-root <website-regression-root> \
  --rollback-release <rollback-release> \
  --scratch <scratch-directory>
```

All machine-specific locations are runtime arguments. The builder fails closed on frozen sealed manifest, release inventory, source identities, patch identities, dependency-lock identities, candidate inventory, and changed output hashes.

The accepted candidate fingerprint is inventory-bound: it is reported only after the exact full candidate inventory SHA matches `expected-output.json`.
