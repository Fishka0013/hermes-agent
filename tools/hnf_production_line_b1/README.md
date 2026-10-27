# HNF production line

Versioned transformation and verification tooling for an accepted Hermes sealed-release candidate.

Model: exact immutable sealed d3 release artifact -> two immutable source patches -> deterministic unchecked-hash `.pyc` outputs -> full candidate inventory -> focused/regression tests -> secret scan -> clean reproduction -> read-only rollback verification.

This is not a source-only rebuild and does not perform deployment, service restart, repository administration, dependency updates, or remote publication by itself.

Historical B2 local verification (not part of Candidate-03 acceptance/promotion):

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
## Candidate-03 lineage overlay

Candidate-03 is derived from the immutable Candidate-02/B2 publication lineage and adds only `patches/gateway_run.patch`, which removes the speculative startup-warmup model-context resolution while preserving ordinary real-turn resolution. The builder applies that patch and regenerates `gateway/run.cpython-314.pyc` with the same deterministic `UNCHECKED_HASH` method.

`tools/hnf_production_line_b1/local_ci.py` is retained as historical B2 tooling. It is **not** part of the Candidate-03 acceptance or promotion path and must not be invoked for Candidate-03. Candidate-03 acceptance is bound to the frozen full inventory SHA, clean reproduction, the retained 228-test matrix, and the focused 2-test startup-warmup proof.
