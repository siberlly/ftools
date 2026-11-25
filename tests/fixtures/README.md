# Test fixtures

Fixtures in this directory are synthetic and contain no acquired user data.

- `synthetic-empty.evtx` is a minimal valid, empty EVTX container.
- Browser, registry and filesystem records used by unit tests are generated in
  temporary directories by the helper modules under `tests/`.

Integration tests that require a real E01 or AD1 image are marked
`integration` and skip unless the operator supplies the documented local lab
image. CI deliberately runs the deterministic synthetic suite only.

To verify the committed binary has not changed unexpectedly:

```text
sha256sum tests/fixtures/synthetic-empty.evtx
```

Expected SHA-256 is recorded in `SHA256SUMS`.

Regenerate it deterministically from the repository root:

```bash
PYTHONPATH=tests python -c "from pathlib import Path; from evtx_helpers import synthetic_empty_evtx; Path('tests/fixtures/synthetic-empty.evtx').write_bytes(synthetic_empty_evtx())"
sha256sum -c tests/fixtures/SHA256SUMS
```
