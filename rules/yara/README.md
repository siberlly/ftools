# YARA rules

This directory is project-managed. The triage service compiles every
`*.yar` / `*.yara` file here before scanning an extracted copy, using
`yara-python`. Invalid rules make the YARA analyzer fail for the job; they are
never silently skipped.

Rules are local only:

- nothing is downloaded automatically;
- evidence content cannot modify this directory;
- the triage service never writes here;
- an empty directory is reported as **No active YARA rules**, which is not
  evidence that a file is clean.

## Adding a rule

1. Add a `.yar` file with a unique rule name.
2. Keep metadata (`author`, `description`, `reference`, `severity`) so analysts
   can interpret a match.
3. Test the rule compiles:

   ```bash
   .venv/bin/python - <<'PY'
   import yara
   print(yara.compile(filepath="rules/yara/example.yar"))
   PY
   ```

4. Restart the web/MCP service (rules are compiled per triage job).
5. Run a triage job and confirm the rule appears in the YARA section with its
   namespace, tags, metadata and matched identifiers.

Matches are indicators, not verdicts. The UI and MCP responses never label a
file as malicious from a YARA hit alone.

## Test rule

`test-fixture.yar` matches the harmless marker `DFIR_TRIAGE_TEST_MARKER` used
by deterministic unit tests. Do not add real malware samples to this
repository.
