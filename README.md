# dfir-browser

Read-only DFIR file browser for disk images and logical AD1 evidence. One
shared Python core powers a small FastAPI + Jinja2 + HTMX web UI, a SQLite
filesystem index, and an MCP server over stdio.

For E01/RAW/IMG evidence, filesystem data is read through The Sleuth Kit
(`fls`, `istat`, `icat`, `fsstat`, `img_stat`) with
`mmls` used only for layout detection. Evidence is never mounted read-write,
modified, opened, or executed.

AD1 logical containers are parsed through an isolated `AD1EvidenceBackend`
using `dissect.evidence`; they are never passed to Sleuth Kit or libewf.
Primary `.ad1` registration discovers contiguous `.ad2`, `.ad3`, ... siblings
and pins each segment. ADCRYPT is detected and reported as unsupported.

## Cross-source investigation

The **Timeline** tab builds a SQLite snapshot from the current filesystem,
Amcache, EVTX and browser artifact indexes. Start it from the tab or call MCP
`start_timeline_index`; it does not rescan evidence. Results are paginated,
filterable and carry source URLs and index generation provenance. If a source
generation changes, timeline results are hidden as stale until rebuilt. Source
errors are reported independently and invalid/missing timestamps are counted
and skipped. All stored/displayed event times are UTC. Filesystem created,
modified, accessed and metadata-change times remain distinct metadata events;
they do not imply program execution. Amcache compile/key/first-run fields retain
their source meaning and do not by themselves establish execution.

The **Related artifacts** panel checks indexes for the same evidence only.
Exact stored hashes and normalized full paths rank ahead of browser download
targets and filename-only leads. A filename-only match is explicitly weak and
is not an identity claim. Windows path matching folds case, slash direction,
device prefixes and surrounding whitespace while preserving original values
for display. The current MVP does not query VirusTotal or scan evidence when a
panel opens. Source records open through the existing EVTX/browser/filesystem
details or the Amcache record detail route. MCP tools are
`start_timeline_index`, `get_timeline_index_status`, `query_timeline`,
`get_timeline_event`, and `find_related_artifacts`.

### Third-party license notice

The AD1 parser dependency `dissect.evidence>=3.13,<4` is licensed under
**AGPL-3.0-or-later**. The parser is isolated behind the evidence backend
interface, but this dependency may impose obligations on distribution or
network use of the combined application. The project metadata remains MIT;
this dependency does not change that declaration. Review the AGPL terms for
the intended deployment and distribution model.

This is a hardened single-user forensic MVP, not a production multi-tenant
service.

## What the index and tree add

- One recursive `fls -r -p -l` scan per evidence, streamed line-by-line into
  SQLite. The web UI and MCP query the index instead of running `fls` on every
  directory click.
- Allocated and deleted/unallocated entries in the same index.
- Index status with real progress: status, entries seen/indexed, deleted
  counts, parse errors, elapsed time, current path, completeness and errors.
- Browse, All entries, Deleted files and Search tabs with pagination and sort.
- A lazy, Explorer-style filesystem tree backed by parent/child row IDs in
  SQLite. Only direct children of an opened directory are queried; the whole
  133k-entry index is never rendered or shipped to the browser.
- MCP tools for index start/status, deleted files, search, and lazy tree
  children/ancestors.
- **Static file triage** for a selected file: hashes, entropy, strings,
  suspicious-string rules, YARA, ExifTool metadata and PE summary, run as a
  background job against a read-only extracted copy. Nothing is executed.
- **Opt-in VirusTotal hash lookup**: only a hash is sent, never the evidence,
  the extracted copy, a filename or a path.
- **Offline registry hive browser** (SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT,
  NTUSER.DAT, UsrClass.dat, Amcache.hve and other `.hve` files) with a lazy key
  tree, value decoding and search.
- **Amcache executable inventory**: raw FileId preservation, conservative hash
  normalization, search and hash comparison against static triage.
- **Windows EVTX Explorer**: discover `.evtx` logs from the filesystem index,
  index and query events offline, with transparent investigation presets.
- **Recycle Bin deletion metadata**: `$I`/`$R` pairing, real deletion time,
  original path and size, owner SID.
- **ShellBags Explorer**: folder/device access history from `UsrClass.dat` and
  `NTUSER.DAT`, including MTP device trees that regipy shows as
  `<UNKNOWN: 0x00>`.
- **Read-only file content preview** in the Browse panel: text, log, config,
  XML, JSON, CSV, extension-less files (`hosts`, `services`, `networks`,
  `protocol`), source code, PowerShell history and batch files as plain text,
  with bounded hex previews and registry-hive detection.
- **Browser Artifacts Explorer**: discover and index IE/Legacy Edge
  `WebCacheV01.dat` (ESE), Chromium/Edge `History` and Firefox `places.sqlite`
  from the filesystem index, parse downloads, history and cache records, and
  correlate download targets with filesystem entries.
- Derived index data only: rebuilding never modifies evidence or extracted
  files.

## Safety model

- Evidence registration only accepts absolute paths under
  `/home/ubuntu/test` or `/home/ubuntu/evidence` (configurable). Paths are
  canonicalised; symlinks and `..` traversal that escape the allowlist are
  rejected.
- Every E01 registration records the resolved source path, the source
  container SHA-256, source size and source mtime. Size and mtime are
  re-checked before live evidence access; indexed queries validate the pinned
  evidence/index generation instead.
- EWF raw exposures are never discovered by media size or directory scanning.
  Identity comes from an explicit administrator mapping or from a managed
  `ewfmount` exposure with a marker tied to the evidence id, source path and
  source SHA-256.
- Explicit exposures must be regular, readable, and have no write permission
  bits. They are verified with `fsstat` and `img_stat`; media size is only a
  secondary check.
- Every subprocess uses an argument list with `shell=False`. There is no
  shell/command tool in the web UI or MCP server.
- Commands have bounded timeouts and bounded stdout/stderr. On timeout the
  entire process group is terminated (SIGTERM then SIGKILL) and the direct
  child is reaped.
- The indexer streams `fls` stdout; it never holds the full scan output in RAM
  and does not apply the 256 KiB live-command stdout cap to the scan.
- Inodes must be plain decimal MFT entry numbers before they reach `istat` or
  `icat`. Case and evidence IDs are validated against strict patterns.
- Export filenames are generated by the server. Client-supplied output paths
  are never used.
- Extracted files are written with mode `0600` under
  `var/cases/<case_id>/exports/`, marked `untrusted: true`, hashed with
  SHA-256, and are never executed.
- Directories cannot be extracted as files.
- Filenames, paths, timestamps, metadata and raw `istat`/`fls` output are
  untrusted evidence data. The GUI autoescapes them and never uses `|safe`.
  MCP responses carry `"trust": "untrusted_evidence_data"`.

## Requirements

- Python >= 3.11
- The Sleuth Kit: `mmls`, `fsstat`, `img_stat`, `fls`, `istat`, `icat`
- libewf tools: `ewfinfo`, `ewfmount` (and `ewfverify` if you verify separately)
- Hashing is done in Python; `sha256sum` is not required
- SQLite is the Python standard-library `sqlite3` module

## Setup

```bash
cd /home/ubuntu/ftools_v2/dfir-browser
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e . --no-deps
```

The currently existing `.venv` was originally bootstrapped with `get-pip.py`
because this Ubuntu image did not include `python3-venv`/`ensurepip`. The
recommended standard installation is `python3 -m venv` with ensurepip (or the
Ubuntu `python3.12-venv` package). Do not re-run `get-pip.py` for normal
operations.

Alternatively:

```bash
pip install -e ".[dev]"
```

## Explicit EWF mapping (required by default)

The application does **not** scan `/home/ubuntu/mnt/ewf` or match images by
media size. Configure an explicit mapping from the resolved E01 source path to
the resolved read-only raw exposure.

Default config file: `var/ewf_mappings.json` (relative to `DFIR_VAR_DIR`).

```json
{
  "version": 1,
  "mappings": {
    "/home/ubuntu/test/temp_extract_dir/SysInternals.E01": {
      "exposure": "/home/ubuntu/mnt/ewf/ewf1",
      "source_sha256": "6a6c35218060ae91cb737f1063683b541c2928383e72b5d8089b8da53c67f198",
      "media_size": 14720958464
    }
  }
}
```

- `source_sha256` is the SHA-256 of the E01 **container file**, not the
  internal media digest reported by `ewfinfo`. It is optional but recommended;
  when present it must match or registration is rejected.
- `media_size` is optional and is only a secondary check.
- A mapping value may also be a plain path string.
- A direct map without the `{"version", "mappings"}` wrapper is accepted.
- The mapping file comes from `DFIR_EWF_MAPPING_FILE` if set, otherwise
  `<var_dir>/ewf_mappings.json`.
- `DFIR_EWF_MAPPINGS` may contain the same JSON object and overrides file
  entries.

A tracked example is `config/ewf_mappings.example.json`.

Prepare the exposure once, outside this application:

```bash
mkdir -p /home/ubuntu/mnt/ewf
ewfmount /home/ubuntu/test/temp_extract_dir/SysInternals.E01 /home/ubuntu/mnt/ewf
ls -l /home/ubuntu/mnt/ewf/ewf1
```

The application never unmounts an explicit exposure.

### Managed exposure (optional)

If `DFIR_EWF_AUTOMOUNT=1` and no explicit mapping exists:

- mount directory: `var/mounts/<evidence_id>/`
- command: `ewfmount <source> <mount_dir>` (argv list, no sudo)
- marker: `var/mounts/<evidence_id>/.dfir-managed.json` with evidence id,
  source path, source SHA-256 and media size
- only managed mounts created by the current process are unmounted on
  shutdown
- mount directories without a matching marker are never reused or unmounted
- if `ewfmount` fails, the error is structured and there is no fallback

## Filesystem index

The index is stored at `var/index/filesystem.db` by default (mode `0600`,
directory `0700`). The scan command is:

```text
fls [-o <offset_sectors>] -r -p -l <raw_exposure>
```

The current NTFS volume uses offset 0. If a partitioned image is detected, the
offset from `mmls` is passed with `-o`.

### Scan behavior

- One scan per evidence at a time, enforced by an in-process thread guard and a
  per-evidence `flock` lock under `var/index/locks/`.
- `DFIR_AUTO_INDEX=1` (default) starts a background scan after registration.
- The web UI has a CSRF-protected Build/Rebuild Index button and polls real
  progress with HTMX.
- Output is read with bounded `readline()` calls, parsed line-by-line and
  inserted in transactions in batches. A final partial line is dropped and
  recorded as a parse error.
- Limits: `DFIR_INDEX_TIMEOUT` (default 1800s), `DFIR_INDEX_MAX_ENTRIES`
  (2,000,000), `DFIR_INDEX_MAX_LINE_BYTES` (64 KiB),
  `DFIR_INDEX_MAX_RAW_ERROR_BYTES` (4 KiB), `DFIR_INDEX_BATCH_SIZE` (1000).
- Status values: `pending`, `running`, `ready`, `incomplete`, `failed`,
  `interrupted`.
- Non-zero `fls` exit or timeout → `failed`; entry limit, parse errors or a
  dropped partial line → `incomplete`. Only `ready` with zero parse errors is
  reported as complete.
- If the process restarts during a scan, the old row becomes `interrupted` on
  the next startup when the per-evidence lock is free. A later successful scan
  replaces the old generation; rows from different scans are never mixed.

### SQLite schema

`evidence_indexes` stores the per-evidence identity, status, counts, timestamps
and error state:

- evidence_id, source_sha256, raw_exposure_path, filesystem, offset_sectors
- fls_version, index_schema_version, scanner_version
- status, stale, scan_id, started_at, completed_at
- entries_seen, entries_indexed, parse_errors
- deleted_files, deleted_directories, allocated_files, allocated_directories
- current_path, error_code, error_message

`filesystem_entries` stores one row per parsed entry:

- full_path, parent_path, basename, extension
- inode, sequence, attribute_id, fls_type
- entry_type (`file`/`directory`), allocated, deleted, size
- created_time, modified_time, accessed_time, mft_modified_time
- raw_line_hash
- parent_id (row id of the parent directory inside the same scan, `NULL` for
  volume-root children)
- has_children (derived, 1 when at least one indexed row points at this entry)

`filesystem_parse_errors` stores a bounded raw line, line number and error for
debugging. Indexes cover evidence+parent path, evidence+deleted, basename,
full path, inode, extension, evidence+parent_id, and per-sort composite indexes
(`parent_id, basename/id`, `parent_id, modified_time, id`,
`parent_id, size, id`, `parent_id, entry_type, ...`,
`parent_id, deleted, allocated, ...`). Full path is not a unique key:
hardlinks and ADS can share inodes or paths. Node identity is the index row
`id`, not the path.

Tree links are resolved once at the end of a scan inside a transaction, before
the index is published as `ready`. Schema version 2 upgrades a version 1
database in place by adding the columns and deriving them from the existing
rows; the index generation is preserved and no registry/case data is touched.
Tree indexes are created after linking so bulk insert does not pay index
maintenance per row.

### Identity and invalidation

An index is valid only when all of these match the current evidence record and
scanner:

- source container SHA-256
- resolved raw exposure path
- filesystem type and offset
- index schema version and scanner version
- `fls` tool version

A mismatch marks the index stale. Stale index data is not used: browse falls
back to a clearly labelled live result, while deleted/search require a rebuild.
The source E01 is **not** re-hashed for every directory request; the pinned
identity from registration is used.

### Deleted files view

The Deleted files tab defaults to `deleted=true` and `entry_type=file`.
Directories can be included explicitly. It supports extension filtering,
filename/path search, pagination, sorting and a summary of deleted files,
deleted directories, parse errors and index completeness. A red
`DELETED / UNALLOCATED` badge is shown for each deleted row. If the index is
incomplete, a prominent warning says the list may be missing entries.

### Search

Search is parameterized and uses the SQLite index:

- exact or contains matching over basename/full path
- optional extension, deleted-only, allocated-only and entry type filters
- page/page_size with a configurable maximum (default 100/500)
- wildcard characters in the query are escaped with `ESCAPE '\'`
- no regex or raw SQL from user input

Every result includes `total`, `page`, `page_size`, `index_status`, `complete`,
`warning` and `trust`.

## Filesystem tree explorer

The Browse view is a two-pane Explorer-style tree:

- left: lazy directory tree, toolbar (filter, collapse all, go to root, show
  deleted, directories only), breadcrumb, and a draggable splitter;
- right: direct children of the selected directory (Name, Type, Size, MFT,
  Modified, Status, sortable and paginated) or full file metadata plus the
  existing extract form.

Behavior and guarantees:

- Opening a directory issues exactly one `GET /tree/children?parent_id=<row id>`
  query for its direct children. Re-opening uses the in-memory cache. `fls` is
  never run again for browsing, search or deleted views.
- `Show deleted entries` and `Directories only` are query filters, not CSS
  hiding. Changing them reloads the tree.
- `Load more` pages through large directories (for example `$OrphanFiles`).
- The selected node is kept in the URL as `?entry=<row id>` and expanded nodes
  and selection are kept in `sessionStorage`, so switching Browse → Search →
  Deleted → Browse preserves position. Refreshing restores the selection and
  expands its ancestors.
- Search and Deleted results have **Reveal in tree**, which expands the
  ancestor chain, selects the node, scrolls it into view and loads its panel.
  Entries whose parent directory is absent from the index are attached to the
  volume root and the UI says why.
- Nodes show a chevron (directories), an SVG volume/directory/file icon, the
  name, and a text badge (`allocated`, `deleted`, `unallocated`). Status is
  never conveyed by color alone. Title/tooltip includes the full path, MFT
  entry and status.
- Accessibility: `role="tree"`, `role="treeitem"`, `role="group"`,
  `aria-expanded`, `aria-selected`, `aria-level`, roving focus and
  `:focus-visible`. Keyboard: Up/Down move, Right expands or enters the first
  child, Left collapses or moves to the parent, Home/End jump, Enter
  selects/expands, Space selects.
- The four browser views use a full ARIA tablist (`role="tab"`,
  `aria-selected`, `aria-controls`, roving tabindex, Left/Right/Home/End).
- Responsive: at ≤900px the tree becomes a full-width stacked panel with a
  Tree show/hide button; at ≤700px the summary cards and metadata definitions
  collapse to one column. There is no horizontal page overflow at 280, 320 or
  414 CSS pixels. Long paths and hashes wrap; wide tables scroll inside their
  own container.
- Evidence-derived names and metadata are inserted with `textContent` in the
  tree script and autoescaped in Jinja fragments. There is no `innerHTML` of
  evidence strings and no CDN asset.

### Tree endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/evidence/{id}/tree` | returns the tree shell (or an index-required panel) |
| GET | `/evidence/{id}/tree/children?parent_id=&include_deleted=&directories_only=&page=&page_size=&sort=&sort_dir=&filter=` | JSON direct children; `parent_id=0` is the synthetic volume root |
| GET | `/evidence/{id}/tree/reveal?entry_id=` | JSON ancestor chain plus the child page needed to expand to the entry |
| GET | `/evidence/{id}/entry/{entry_id}` | HTML right-panel fragment for a directory or file |
| GET | `/evidence/{id}/entry/{entry_id}/extract` | POST target for extraction from the file panel (CSRF required) |

Entry IDs are digits only. Negative, non-numeric, out-of-range or
other-evidence row IDs are rejected with structured errors
(`invalid_entry_id`, `entry_not_found`, `not_a_directory`). Raw filesystem
paths are never accepted for host access; the only path form accepted is the
normalized index path resolved inside the selected evidence.

## Static file triage

Triage is analyst-initiated: selecting a file only shows metadata and a
**Run static triage** button. The job then runs in the background against a
read-only `icat` copy in the case workspace and reports:

- evidence path, MFT/inode, entry ID, allocated/deleted/unallocated status
- extractability and the extracted copy path (mode `0600`)
- MD5, SHA1, SHA256, size
- `file` identification and MIME type
- whole-file entropy and per-chunk entropy (bounded)
- printable ASCII and UTF-16LE strings
- rule-based suspicious-string findings (URL, IPv4, domain, email, Windows and
  registry paths, PowerShell/`cmd.exe`/`rundll32`/`regsvr32`/`mshta`/`certutil`,
  base64-like tokens, mutex-like names, user agents, executable names)
- YARA matches with rule name, namespace, tags, metadata and matched
  identifiers
- ExifTool metadata
- PE32/PE32+ summary: machine, compile timestamp (flagged as forgeable), entry
  point, image base, sections with entropy, imports, exports, signature
  directory presence, PDB path, version info, overlay size
- per-analyzer status, duration, tool version, warnings and errors

Phases reported by the job: `queued → extracting → hashing → identifying →
strings → yara → metadata → complete`. One failing or timed-out analyzer marks
the job `partial` and the remaining analyzers still run.

### Safety rules

- The E01 and the raw exposure stay read-only; only the extracted copy is read.
- Nothing is executed, no Wine, no `shell=True`, argv-only commands.
- Each analyzer has a timeout and an output cap; the whole job has a deadline.
- File size, string counts/lengths, findings, YARA matches and ExifTool tags are
  bounded in configuration.
- The extracted path must resolve inside the case export directory, must not be
  a symlink and must be a regular file.
- Evidence text is escaped; the UI never uses `innerHTML` for evidence values.
- No sample, hash or metadata is uploaded anywhere. There is no VirusTotal or
  network lookup.

### Cache

A triage result is reused when `evidence_id + entry_id + file SHA-256 + triage
profile version` match a previous `complete`/`partial` job. The cached job is
still a distinct audited job with `cached=true` and `cached_from_job_id`, and
the UI labels it **cached result**. **Run again** / `force=true` always starts a
new job. Filenames and paths are never used as cache keys.

### YARA rules

Rules live in `rules/yara/` (packaged into the wheel) and are compiled per job.
See `rules/yara/README.md`. The shipped `test-fixture.yar` matches only the
harmless `DFIR_TRIAGE_TEST_MARKER` string used by tests. An empty or
unreadable rule set is reported as **No active YARA rules**, which is not a
clean verdict; an invalid rule fails the YARA analyzer for that job instead of
being silently ignored.

### Triage storage

`var/cases/triage.db` (mode `0600`) stores jobs, analyzers, strings, findings
and YARA matches in separate tables, so strings are paginated in SQL instead of
being embedded in one large JSON blob. Jobs left `queued`/`running` by a server
crash are marked `interrupted` on the next startup.

### Triage endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/evidence/{id}/entries/{entry_id}/triage/panel` | triage card with the start form |
| POST | `/evidence/{id}/entries/{entry_id}/triage` | start a job (CSRF required) |
| GET | `/triage/jobs/{job_id}` | status/result fragment, polled while running |
| GET | `/triage/jobs/{job_id}/results` | same result fragment |
| GET | `/triage/jobs/{job_id}/strings` | paginated, filterable strings fragment |

## VirusTotal hash lookup (opt-in)

The browser and MCP can look up a file hash on VirusTotal. This is deliberately
narrow:

- one endpoint only: `GET https://www.virustotal.com/api/v3/files/{hash}`
- no upload, download, rescan, URL scan, comments, votes or relationship
  crawling; no POST to VirusTotal
- only the hash is sent. Filenames, paths, case IDs, evidence IDs and file
  content are never sent
- no automatic lookup: opening a file, running triage or browsing directories
  never contacts VirusTotal
- the base URL is fixed and HTTPS-only; redirects and unexpected hosts are
  rejected; TLS verification stays enabled
- responses are size-limited and JSON-validated; a VirusTotal failure never
  breaks triage or browsing

### Configure a key

Open **Settings → Integrations → VirusTotal**. The key is a 64-hexadecimal
secret. Two sources are supported, in this order:

1. `VT_API_KEY` environment variable (takes precedence; the UI shows
   **Managed by environment**)
2. UI secret store: `var/secrets/virustotal.key`

The UI never prefills or reveals the key and never returns it in HTML or JSON.
Only the last four characters are shown. Saving is atomic; the directory is
`0700` and the file is `0600`. There is **no encryption**: Unix permissions are
the only protection. Removing the UI key cannot remove an environment variable.

The settings page also offers a **Test lookup** with a hash you type. That is
the only path that accepts a caller-supplied hash; evidence lookups always
resolve the hash server-side.

### Lookup behavior

- The SHA-256 comes from the latest triage result or is computed from a
  read-only extraction; the browser cannot pass a hash or URL for an evidence
  lookup.
- A successful report is cached in `var/cases/virustotal.db` for 24 hours
  (configurable); 404 is cached for 1 hour. 401/403/429 are never cached.
- The local limiter allows **4 outbound requests per minute** for the whole
  key. Concurrent requests for the same hash are coalesced into one outbound
  request.
- Cache metadata includes `fetched_at`, `cached` and cache age. **Refresh from
  VirusTotal** sends a new request and consumes quota.
- The UI reports found, not found, invalid key, forbidden, quota exhausted,
  timeout, TLS/network failure and invalid response separately. A report with
  zero malicious engines is described as "No engines reported malicious in this
  VirusTotal report", never as clean; the report timestamp is always shown.

Audit events (`virustotal_lookup`, key save/remove) record evidence ID, entry
ID, hash type, hash, requested time, result status, cache/live and HTTP
category. The API key is never written to the audit log, SQLite, MCP responses,
HTML or URLs.

## Registry hive browser and Amcache

Registry parsing is offline and read-only. The parser is
`python-registry` 1.3.1; no Windows Registry API, mount or credential mechanism
is used.

Supported/discovered hives: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`,
`NTUSER.DAT`, `UsrClass.dat`, `Amcache.hve`, plus other `.hve` files. Discovery
uses the filesystem index (known filenames/paths, entry type, deleted flag and
size); the working copy is extracted with `icat` and the `regf` signature is
validated before parsing. The whole filesystem is never scanned for signatures.

- **Index**: per-hive SQLite index (`var/cases/registry.db`) with keys, values
  (decoded defensively), parent/child links, timestamps and Amcache records.
  Phases: `queued → extracting → validating → parsing → indexing → ready`.
  Limits: hive size, key count, depth, single-value bytes, decoded text length,
  preview size and build timeout (see configuration table).
- **Lazy tree**: the Registry tab lists hives; opening one loads direct subkeys
  only. Values are shown for the selected key. Search covers key names, value
  names and string values, with pagination. Binary values return a bounded hex
  preview, never the full binary.
- **Transaction logs**: `.LOG`, `.LOG1`, `.LOG2` siblings are detected and
  shown. The base hive is parsed; logs are not replayed. `recover_with_logs=true`
  returns `transaction_log_recovery_unavailable` rather than pretending a
  recovery occurred.
- **Sensitive hives**: SAM and SECURITY are metadata-only. Credential material
  is never decrypted, extracted or logged; binary values are preview-only.
- **Cache**: a valid working copy and index are reused without re-extraction
  when evidence identity, entry, SHA-256, parser and schema versions match.
  Rebuild is explicit; a rebuild replaces derived rows atomically.

### Amcache

Amcache records are parsed from real key/value names, not from a hard-coded
single schema. The current schema (`InventoryApplicationFile`) and the older
`Root\File\...` layout are both supported; every record keeps its source key
path and source value names.

- `FileId` is always preserved raw. A 40-hex value is treated as SHA-1; a
  44-hex value beginning with `0000` is normalized by stripping that prefix and
  recording `strip-4-hex-prefix-sha1`. Any other shape keeps
  `hash_algorithm="unknown"` and no normalized hash. Values are never silently
  truncated or guessed.
- Search by executable name, full path, program/product name, publisher,
  FileId or normalized hash, with pagination.
- **Compare with triage** accepts a filesystem entry ID and compares only the
  same algorithm (SHA-1 with SHA-1, SHA-256 with SHA-256). Results are `match`,
  `mismatch`, `incompatible`, `unavailable` or `unknown`; a mismatch is not a
  malware verdict.
- An explicit VirusTotal lookup is available for a validated Amcache hash. Only
  the normalized hash is sent; registry paths, filenames, profiles and evidence
  IDs are never sent.

### Registry endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/evidence/{id}/registry` | hive list and build actions |
| POST | `/evidence/{id}/registry/{entry_id}/index` | build/rebuild (CSRF) |
| GET | `/registry/hives/{hive_id}/status` | polling status |
| GET | `/registry/hives/{hive_id}` | two-pane registry browser |
| GET | `/registry/hives/{hive_id}/keys` | lazy subkeys (JSON) |
| GET | `/registry/hives/{hive_id}/key/{key_id}` | values panel |
| GET | `/registry/hives/{hive_id}/search` | key/value search |
| GET | `/registry/hives/{hive_id}/reveal` | ancestor chain for reveal |
| GET | `/registry/hives/{hive_id}/amcache` | Amcache search |
| POST | `/registry/hives/{hive_id}/amcache/{record_id}/compare` | hash comparison |
| POST | `/registry/hives/{hive_id}/amcache/{record_id}/virustotal` | explicit hash lookup |

## Windows Event Log (EVTX) Explorer

EVTX support is offline and read-only. Logs are discovered from the filesystem
index and parsed from a `0600` working copy.

- **Parser**: the `evtx` Rust extension (`evtx==0.15.0`). `python-evtx` was too
  slow (about 4 ms/record, ~20 s for the 4.3k-record Security log); the Rust
  parser yields the same XML in about 15 ms and the XML is still normalized by
  the same safe parser. XML is parsed with `defusedxml` (no DTD, entities,
  external fetch or network) and bounded by size/field limits.
- **Discovery**: `.evtx` extension plus the `Windows/System32/winevt/Logs/`
  path, entry type, allocation state and size sanity. Only plausible candidates
  are inspected; the whole filesystem is never signature-scanned. Deleted logs
  are supported when the file still extracts.
- **Index**: per-log SQLite index (`var/cases/evtx.db`) with FTS5 text search.
  If FTS5 is unavailable the service falls back to a parameterized `LIKE`
  search and reports the limitation.
- **Limits**: file size, record count, event XML size, decoded field length,
  raw XML size, query length, page size, parser/index timeout and concurrent
  jobs (see configuration table).
- **Robustness**: a corrupt record is stored as a structured parse error and the
  job continues; a failed job never crashes the server. Problem records mark the
  log `partial` rather than discarding the whole file.

### Message rendering

The image does not ship Windows message resource DLLs, so rendered event
messages are **not available**. Events carry `message_status="message_unavailable"`;
the UI shows structured EventData/UserData, raw XML (on request) and never
generates a message by guessing. When a producer does include a `Message`, it is
shown.

### Web usage

**Event Logs** tab → pick a log → Build/Rebuild index → Open:

- filters: event IDs (space/comma separated), provider, level, SID, computer,
  process ID, ISO-8601 time range, text (FTS5), preset and sort direction;
- result table: timestamp, channel, provider, event ID, level, computer, SID,
  structured summary, record ID;
- actions: Details, Raw XML (explicit), Context (bounded neighbours), Search fs
  (fills the filesystem search box, no automatic extract/triage/VirusTotal);
- the detail panel is separate from the table and is cleared when the log or
  results change;
- **Compute summary** shows counts by channel/provider/event ID/level/SID/
  computer/day, top structured process/path values and rule-based notable
  activity with rule IDs.

### Presets

Presets are transparent filters, not verdicts (see `core/evtx/presets.py`):

| Rule | Preset | Event IDs |
| --- | --- | --- |
| `preset.authentication` | Authentication | 4624, 4625, 4634, 4647, 4648, 4672 |
| `preset.process_execution` | Process execution | 4688, Sysmon 1 |
| `preset.service_persistence` | Service persistence | 7045, 4697 |
| `preset.scheduled_tasks` | Scheduled tasks | 4698–4702 + TaskScheduler |
| `preset.powershell` | PowerShell | 4103, 4104, 400, 600 |
| `preset.defender` | Defender | 1116–1119, 1006, 1007, 1015 |
| `preset.log_clearing` | Log clearing | 1102, 104 |
| `preset.sysmon_network_file_registry` | Sysmon | 3, 7, 11, 13 |

Each preset lists its channels/providers, event IDs, limitations and rule ID.
An event appearing does not mean the activity was malicious.

### EVTX endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/evidence/{id}/event-logs` | discovery list |
| POST | `/evidence/{id}/event-logs/{entry_id}/index` | build/rebuild (CSRF) |
| GET | `/event-logs/{log_id}/status` | polling status |
| GET | `/event-logs/{log_id}` | explorer |
| GET | `/evidence/{id}/event-logs/query` | filtered query |
| GET | `/event-logs/{log_id}/events/{record_id}` | detail (`?raw=1` for XML) |
| GET | `/event-logs/{log_id}/events/{record_id}/context` | bounded neighbours |
| GET | `/evidence/{id}/event-logs/summary` | activity summary |

## Browser Artifacts Explorer

Browser artifacts are parsed strictly offline and read-only. URLs, titles,
referrer values and paths are untrusted evidence data: they are never opened,
fetched, resolved or executed, and no browsing data is ever sent anywhere.

### Supported browsers and artifacts

| Browser | Artifact | Detected path | Backend |
| --- | --- | --- | --- |
| IE / Legacy Edge | `WebCacheV01.dat` | `Users/<user>/AppData/Local/Microsoft/Windows/WebCache/` | `dissect.esedb` 3.18 (pure Python ESE) |
| Microsoft Edge (Chromium) | `History` | `Users/<user>/AppData/Local/Microsoft/Edge/User Data/<profile>/History` | SQLite (`sqlite3`) |
| Google Chrome | `History` | `Users/<user>/AppData/Local/Google/Chrome/User Data/<profile>/History` | SQLite (`sqlite3`) |
| Mozilla Firefox | `places.sqlite` | `Users/<user>/AppData/Roaming/Mozilla/Firefox/Profiles/<profile>/` | SQLite (`sqlite3`) |
| Mozilla Firefox (Linux) | `places.sqlite` | `~/.mozilla/firefox/<profile>/`, `~/snap/firefox/common/.mozilla/firefox/<profile>/` | SQLite (`sqlite3`) |
| Chromium (Linux) | `History` | `~/.config/google-chrome/<profile>/`, `~/.config/chromium/<profile>/`, `snap/chromium/.../User Data/<profile>/` | SQLite (`sqlite3`) |

Discovery is driven by the filesystem index and limited to those known
profile paths (Windows, Linux and snap layouts); the whole evidence is never signature-scanned. Each expected
artifact type is reported as `indexed`, `present` (found but not indexed) or
`not_present`, so a missing Chrome/Firefox profile is a clear result rather
than an error. Each candidate
reports `evidence_id`, `entry_id`, inode (MFT), evidence path, user, browser,
profile, artifact type, size, allocation state, sidecars, signature status,
parser support, index state, record counts and warnings.

### Index flow

`queued → extracting → validating → parsing → indexing → ready` (final states
also `partial`, `failed`, `interrupted`).

1. The artifact is extracted from the evidence image into the case workspace
   with mode `0600`; symlinks and paths outside the case export directory are
   rejected.
2. The working copy signature is validated by reading 4 KiB only (SQLite header
   or ESE `0x89ABCDEF` magic at offset 4).
3. SQLite artifacts are opened with `mode=ro&immutable=1`, so SQLite never
   writes to the copy. `-wal`, `-shm` and `-journal` sidecars are copied next to
   the copy and replayed only on the copy; the sidecars actually used are
   recorded per artifact.
4. WebCache ESE is parsed with `dissect.esedb`. `Containers` is read for
   container names/IDs and every `Container_N` table is parsed defensively;
   no container ID is hard-coded. Corrupt pages/records become structured parse
   errors instead of crashes. ESE transaction logs (`V01.log`, `V01tmp.log`,
   `V0100003.log`, `V01.chk`, `.jfm`) are detected but **not** replayed, and a
   warning states this.
5. Records are batch-inserted into `var/cases/browser_artifacts.db` with FTS5
   search over visits, downloads and cache (LIKE fallback when FTS5 is absent).

Cache reuse is keyed by evidence identity, entry identity, content SHA-256,
parser version and schema version. A cache hit neither re-extracts nor
re-parses.

### Timestamp conversion

Every record keeps the raw value plus the conversion method:

| Method | Meaning |
| --- | --- |
| `windows_filetime` | 100 ns ticks since 1601-01-01 UTC (WebCache) |
| `chromium_1601_microseconds` | microseconds since 1601-01-01 UTC (Chromium) |
| `unix_seconds` / `unix_microseconds` | Firefox `visit_date` is microseconds |
| `iso8601` / `datetime` | already-typed values |

Zero/negative/out-of-range values return `null` with a warning instead of
crashing the job. Plausible years are 1995–2100.

### Normalized records

- `BrowserProfile`: profile id, evidence, user, browser, profile name, source
  path, artifact types, warnings.
- `BrowserVisit`: URL, normalized URL, scheme, host, conservative offline
  registrable domain, title, visit time + raw value, transition/visit type,
  referrer, visit/typed counts, hidden flag.
- `BrowserDownload`: start/end time and raw values, source and final URL, URL
  chain, referrer, tab URL, target path, filename, received/total bytes, state,
  danger type, interrupt reason, MIME type, opened flag, browser-provided hash.
- `BrowserCacheEntry`: container, URL, local path/filename, content type,
  created/accessed/modified/expiry times, size, allocation, bounded preview.

Fields that the source schema does not contain are left `null`; nothing is
invented.

### Web UI

The evidence page gains a **Browser Artifacts** tab with discovery, per-artifact
`Build index` / `Rebuild`, status polling, `Reveal` in the filesystem tree and
metadata. The explorer has five views: Downloads, History, Cache, Profiles and
Search all, with filters for user/profile, domain, filename/path, extension,
download state, time range, executable-only, sort direction and URL query-string
visibility. Record detail opens in a side panel; the panel is cleared whenever
the view or record changes. URLs render as plain text with a Copy action and are
never turned into clickable external links.

### Correlation with the filesystem index

Download `target_path`/`filename` is matched against the filesystem index:

- exact evidence-relative path after normalizing Windows separators/case →
  high confidence (`0.99`, adjusted when the size differs);
- single basename match → `0.7`;
- basename + unique size match among several candidates → `0.75` with a warning
  listing the size-mismatched candidates at `0.3`;
- multiple basename candidates → `0.4` each with an ambiguity warning;
- no match → `confidence: none` and an explicit warning.

The IE duplicate `[n]` suffix (`SysInternals[1].exe`) is stripped as an extra
basename variant. Correlated entries show MFT, size, allocated/deleted state,
size comparison, `Reveal` in the tree and file metadata. Correlation never
extracts, triages or looks anything up automatically.

### Privacy limits

Never parsed, decrypted, indexed or displayed: cookies, `Login Data`/passwords,
autofill secrets, tokens/session IDs, DPAPI values, cache response bodies.
URLs keep their query string in the forensic database and can be shown to the
analyst (`include_query_string` / "Show URL query strings"), but application
logs and error messages run through `redact_text()`/`redact_url()`, which strip
query strings, fragments and embedded credentials.

### Presets

| Rule ID | Meaning |
| --- | --- |
| `browser.executable_downloads` | executable/archive extensions |
| `browser.incomplete_downloads` | not in the complete state |
| `browser.ip_literal_urls` | source host is a bare IPv4 literal |
| `browser.http_downloads` | cleartext `http://` source |
| `browser.suspicious_schemes` | `file`, `ftp`, `data`, `blob`, `javascript` |
| `browser.deleted_targets` | correlated filesystem entry is unallocated |
| `browser.domain_filename_mismatch` | filename lacks the domain label |
| `browser.recent_window` | last 24 h of recorded activity |

Each preset carries a `rule_id`, reason and limitations. Presets are indicators,
never malware verdicts.

### Browser endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/evidence/{id}/browser` | discovery list |
| POST | `/evidence/{id}/browser/{entry_id}/index` | build/rebuild (CSRF) |
| GET | `/browser/artifacts/{artifact_id}/status` | polling status |
| GET | `/browser/artifacts/{artifact_id}` | explorer |
| GET | `/evidence/{id}/browser/downloads` | downloads query |
| GET | `/evidence/{id}/browser/history` | history query |
| GET | `/evidence/{id}/browser/cache` | cache query |
| GET | `/evidence/{id}/browser/profiles` | indexed profiles |
| GET | `/evidence/{id}/browser/search` | search all views |
| GET | `/browser/records/{record_type}/{record_id}` | record detail |
| GET | `/evidence/{id}/browser/downloads/{download_id}/correlate` | filesystem correlation |
| GET | `/evidence/{id}/browser/summary` | activity summary |

### Resource limits

| Variable | Default | Purpose |
| --- | --- | --- |
| `DFIR_BROWSER_DB` | `<var_dir>/cases/browser_artifacts.db` | index database |
| `DFIR_BROWSER_MAX_ARTIFACT_SIZE` | `2147483648` | max artifact bytes |
| `DFIR_BROWSER_MAX_RECORDS` | `500000` | max records per type per artifact |
| `DFIR_BROWSER_MAX_URL_LENGTH` | `4096` | URL cap (raw value kept) |
| `DFIR_BROWSER_MAX_TITLE_LENGTH` | `2048` | title cap |
| `DFIR_BROWSER_MAX_PATH_LENGTH` | `2048` | path cap |
| `DFIR_BROWSER_PARSER_TIMEOUT` | `300` | parser deadline (seconds) |
| `DFIR_BROWSER_INDEX_TIMEOUT` | `300` | job deadline (seconds) |
| `DFIR_BROWSER_MAX_CONCURRENT_JOBS` | `1` | concurrent jobs |
| `DFIR_BROWSER_MAX_QUEUED_JOBS` | `4` | queue depth |
| `DFIR_BROWSER_PAGE_SIZE_DEFAULT` / `_MAX` | `100` / `500` | pagination |
| `DFIR_BROWSER_MAX_QUERY_LENGTH` | `256` | filter length |
| `DFIR_BROWSER_BATCH_SIZE` | `500` | insert batch size |

### Troubleshooting

- **`backend unavailable` on WebCache** — `dissect.esedb` is missing. Install it
  with `pip install dissect.esedb==3.18`; Chromium/Firefox keep working.
- **`partial` with parse errors** — the database is dirty or truncated. Records
  that parsed are kept; errors are listed per record.
- **`browser_signature_mismatch`** — the filename matched a known artifact but
  the content is not SQLite/ESE; nothing was indexed.
- **WebCache transactional state** — ESE logs are not replayed, so the newest
  records may be missing. This is reported in the artifact warnings.
- **Chromium downloads missing** — the profile may store only `History` with
  `downloads` empty, or the browser version uses a different schema; check the
  artifact warnings.

### Credential stores (metadata only)

The explorer shows a **Credential stores** card for each profile. It reports
which credential files exist next to the browser profile and how many records
they hold:

| Store | Reported |
| --- | --- |
| `logins.json`, `logins-backup.json` | login count + hostnames only |
| `key4.db`, `key3.db`, `cert9.db` | presence and size only |
| `cookies.sqlite` | cookie count + distinct hosts |
| `formhistory.sqlite` | record count + field names |
| Chromium `Login Data`, `Web Data`, `Cookies`, `Local State` | count + hosts/field names, or presence only |

**Nothing secret is read.** Passwords, usernames, cookie values, encrypted
blobs, NSS keys and tokens are never decrypted or returned; the JSON payloads
contain only counts and host/field names. A regression test inserts synthetic
secrets and asserts they never appear in the response.

Endpoints: `GET /evidence/{id}/browser/credentials?artifact_id=` (HTML) and
`.../credentials/api`. MCP: `browser_credential_stores`.

### Evidence isolation

Every downloads/history/cache query and the activity summary are scoped to the
selected evidence (through its artifacts), so opening one case never shows
records from another evidence that shares the same index database. This is
covered by a regression test that inserts a second evidence's records and
asserts they are not returned.

## Read-only file content preview

Selecting a file in **Browse** shows a collapsible **Preview content** panel
between the metadata and static triage sections. Content is read from an
extracted working copy inside the case export directory; nothing is executed,
imported, `source`d, or opened with an external application.

### Supported content

- Plain text, logs, config files, XML, JSON/JSONL, CSV/TSV, INI/INF, YAML.
- Extension-less text files: `hosts`, `services`, `networks`, `protocol`,
  `lmhosts`, `makefile`, `dockerfile`, and similar.
- Scripts and source code (PowerShell history, `.bat`, `.cmd`, `.js`, `.ps1`,
  `.py`, `.c`, `.sql`, ...) shown **only as text**.
- Binary content: a clear message plus a bounded hex preview.
- Windows registry hives: metadata, `regf` header and a bounded hex view.

### Encoding and display

| Case | Detected as |
| --- | --- |
| UTF-8 BOM | `utf-8-sig` |
| UTF-16 LE/BE BOM | `utf-16-le` / `utf-16-be` |
| Valid UTF-8 | `utf-8` |
| Invalid UTF-8 | `latin-1` with a decode warning |

Line endings are normalized (`\r\n`, `\r` → `\n`) for display, whitespace is
preserved, the view is monospace with a line-number gutter, and every evidence
byte is HTML-escaped by the template. Evidence text is never assigned to
`innerHTML`; in-preview search only builds text nodes and `<mark>` elements.

Controls: **Find in preview** (highlight + match count), **Copy all**,
**Copy selected text** (clipboard only, client-side), **Collapse/Expand**, and
**Load next N bytes** / **Back to start** paging. URLs are not clickable and no
content is fetched from the network.

### Preview API

`GET /evidence/{evidence_id}/entries/{entry_id}/preview?offset=0&limit=65536&mode=auto`

Returns JSON with `evidence_id`, `entry_id`, `filename`, `evidence_path`,
`detected_type`, `preview_mode` (`text` | `hex` | `registry`), `encoding`,
`offset`, `returned_bytes`, `total_size`, `truncated`, `content`, `warnings`,
plus `mime_type`, `lines_returned`, `byte_limit`, `next_offset`, `has_more`,
`registry`, `trust`.

`GET .../preview/panel` renders the same data as an HTMX fragment.

Rules:

- `mode` is only `auto`, `text` or `hex`. Nothing accepts a filesystem path.
- `limit` defaults to 64 KiB, maximum 1 MiB; text views also stop at 10,000
  lines. Both are reported explicitly, never silently truncated.
- A registry hive in `auto` mode returns metadata and the header only; the full
  hive is never dumped. `mode=hex` is available for raw inspection.
- `offset` is a byte offset; an offset past EOF returns zero bytes and
  `truncated: false` instead of reading beyond the file.

### Registry hives in Browse

A hive entry is labelled **Windows Registry Hive** with its type, evidence
path, entry/MFT, size, allocation state and parse state. Actions:

- **Open in Registry Explorer** – switches to the Registry tab and opens the
  indexed hive directly (or the hive list focused on that entry when it is not
  parsed yet).
- **Parse hive** – starts the existing read-only registry workflow. Selecting a
  file never parses a hive automatically.
- **Raw hex preview** – safe bounded hex dump so the `regf` header can be
  checked.

### Preview safety limits

| Variable | Default | Meaning |
| --- | --- | --- |
| `DFIR_PREVIEW_DEFAULT_LIMIT` | `65536` | default bytes per request |
| `DFIR_PREVIEW_MAX_BYTES` | `1048576` | maximum bytes per request |
| `DFIR_PREVIEW_TEXT_MAX_LINES` | `10000` | maximum lines per text view |
| `DFIR_PREVIEW_BINARY_SAMPLE` | `8192` | bytes used for type detection |
| `DFIR_PREVIEW_REGISTRY_HEX_BYTES` | `4096` | bounded hive header hex view |
| `DFIR_PREVIEW_VERIFY_HASH_BYTES` | `8388608` | re-hash reused copies up to this size |
| `DFIR_PREVIEW_CACHE_ENTRIES` | `32` | in-process preview cache size |

Rejected: directories, entries without an MFT/inode, negative inodes, entry
paths containing traversal segments, symlinked or out-of-case working copies,
malformed evidence IDs, unknown entry IDs and unknown modes.

Working copies are reused across previews: a valid extraction with a matching
provenance sidecar is never re-extracted, and identical requests are served
from an in-process cache. Every preview writes one `file_preview` audit event
with evidence, entry, MFT, byte range, mode and returned size — never the
content itself.

### Preview troubleshooting

- **`extraction failed`** – the entry could not be extracted (deleted or
  partially overwritten file). The structured error code is shown.
- **`latin-1` + decode warning** – the bytes are not valid UTF-8; Latin-1 maps
  them 1:1 so no data is lost.
- **`preview_mode: hex` for a text file** – the content looked binary (NUL or
  control bytes). Use `mode=text` to force a text decode.
- **`registry` with a short header** – expected: only the header is inspected.

## Recycle Bin deletion metadata

Opening the `$Recycle.Bin/<SID>/` directory adds a **Deleted at (UTC)** column
to the file listing, with the original path under it, so the deletion time is
visible without opening each file.

Selecting a `$I` or `$R` file under `$Recycle.Bin/<SID>/` adds a **Recycle Bin
metadata** card at the top of the Browse detail panel (above the metadata and
preview sections). Windows stores a small `$I` record
next to the deleted content (`$R`), and that record is the only source that
carries the real deletion time.

| Field | Source |
| --- | --- |
| Deleted at (UTC) | `$I` header FILETIME |
| Original path | `$I` UTF-16LE path |
| Original size | `$I` header |
| Owner SID | Recycle directory name |
| `$I` version | `$I` header (v1 or v2) |
| `$R` content entry | sibling `$R` file in the same directory |

Version 1 `$I` files store a fixed 520-character path with no length field;
version 2 stores a length prefix plus the path (often including a trailing NUL,
which is normal and not reported as a defect). Unknown versions, short records,
implausible FILETIMEs and invalid UTF-16 are reported as warnings instead of
failing the request.

Important distinctions shown in the UI:

- The **deletion time** comes only from `$I`. Filesystem timestamps (created,
  modified, MFT modified, accessed) are shown separately under *Indexed
  timestamps* and are **not** the deletion time.
- If the `$R` content is gone, the panel says so instead of guessing.
- Only the `$I` header is read from an extracted working copy; `$R` content is
  never opened. The existing preview panel can still show it separately if the
  analyst asks.

### Recycle endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/evidence/{id}/recycle/{entry_id}` | HTMX panel |
| GET | `/evidence/{id}/recycle/{entry_id}/json` | structured metadata |

Bounded by `DFIR_RECYCLE_MAX_INFO_BYTES` (default 64 KiB). Directories,
non-recycle entries and unknown evidence IDs are rejected with a structured
error. No shell command, no path input, and no write to the evidence.

## ShellBags Explorer

ShellBags are recovered from the `BagMRU` keys that Windows writes into
`UsrClass.dat` (per-user, `...\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`)
and `NTUSER.DAT` (`Software\Microsoft\Windows\Shell\BagMRU`). The
**ShellBags** tab parses them automatically: hives are discovered from the
filesystem index, extracted read-only and parsed offline. No registry export
and no manual command is needed.

### What is recovered

| Field | Source |
| --- | --- |
| Folder / device tree | nested `BagMRU` subkeys |
| Full path | shell item names joined through the BagMRU hierarchy |
| Name | documented shell item layouts, else embedded UTF-16 data |
| Last write (UTC) | the `BagMRU` registry key's last-write time |
| Embedded timestamps | `0xBEEF` shell item extension, when present |
| Drive / volume label | item type `0x2F` |
| Device kind / path | MTP (`6ac27878-...`), USB (`usb#vid_...`), portable |
| User SID | `S-1-5-21-..._Classes` prefix of the hive path |

### MTP and portable devices

Portable-device storage and folders are stored as shell item **type `0x00`**.
Libraries such as regipy render these as `<UNKNOWN: 0x00>`. This parser reads
the raw item bytes instead and recovers the names, so the tree is preserved:

```
My Computer
  LG Q7                      (type 0x2E, MTP over USB)
    Internal storage         (type 0x00)
      DCIM                   (type 0x00)
        Camera               (type 0x00)
```

Items whose bytes contain no readable name are still shown, labelled
`(unnamed <type>)`, with the registry value index and a warning. Names are
never invented.

### Interface

- **Devices** list with kind, drive letter, volume label and item count.
- **Tree** with drill-down and breadcrumb navigation.
- **Search** by name/path, kind (device/folder/file), user SID, device and
  `datetime-local` range on the BagMRU last-write time.
- **Detail** panel: full path, shell item type, name source, embedded
  timestamps, exact hive/key/value and a button that opens the BagMRU key in
  the Registry Explorer.
- **Export** JSON or CSV (bounded by `DFIR_SHELLBAG_EXPORT_MAX_ROWS`).

### Interpretation rules

ShellBags record that a folder or device was **viewed in Explorer**. They are
strong evidence of access to a location, but they do **not** prove that a file
was copied, opened, deleted or exfiltrated. The UI and the export payload both
state this. The `BagMRU` last-write time is when the shellbag entry was last
updated, not necessarily when the folder was opened.

### ShellBags endpoints and tools

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/evidence/{id}/shellbags` | tab |
| POST | `/evidence/{id}/shellbags/index` | build/rebuild (CSRF) |
| GET | `/evidence/{id}/shellbags/status` | index state |
| GET | `/evidence/{id}/shellbags/tree` | tree fragment |
| GET | `/evidence/{id}/shellbags/devices` | device list |
| GET | `/evidence/{id}/shellbags/search` | search fragment |
| GET | `/shellbags/nodes/{node_id}` | node detail |
| GET | `/evidence/{id}/shellbags/export?format=json|csv` | export |
| GET | `/evidence/{id}/shellbags/api/{tree,devices,search}` | JSON API |

MCP tools: `shellbags_index_start`, `shellbags_index_status`,
`shellbags_list_devices`, `shellbags_tree`, `shellbags_search`,
`shellbags_get_node`.

### Resource limits

| Variable | Default | Meaning |
| --- | --- | --- |
| `DFIR_SHELLBAG_DB` | `<var_dir>/cases/shellbags.db` | index database |
| `DFIR_SHELLBAG_INDEX_TIMEOUT` | `300` | job deadline (seconds) |
| `DFIR_SHELLBAG_MAX_NODES` | `50000` | node cap per evidence |
| `DFIR_SHELLBAG_PAGE_SIZE_MAX` | `500` | maximum page size |
| `DFIR_SHELLBAG_MAX_QUERY_LENGTH` | `256` | search text cap |
| `DFIR_SHELLBAG_EXPORT_MAX_ROWS` | `10000` | export row cap |
| `DFIR_SHELLBAG_AUTO_INDEX` | `1` | parse on first tab open |

### Limitations

- Only `UsrClass.dat` and `NTUSER.DAT` are parsed; `ShellNoRoam` keys are read
  when present.
- Deleted shellbag records that were overwritten in the hive are not recovered.
- Embedded `0xBEEF` timestamp ordering varies by Windows version.
- A hive is parsed only up to `DFIR_SHELLBAG_MAX_NODES` and the job deadline.
- No cross-check against LNK or Jump Lists is performed automatically; use the
  existing timeline/related-artifacts views.

## Whole-disk images (GPT/MBR)

Some acquisitions are whole-disk images rather than a single volume. The
filesystem is then on a partition, so `fsstat` at sector 0 finds no filesystem.
That is **not** corruption and registration no longer fails with
`exposure_fsstat_failed`:

1. The exposure is accepted when a partition table is present.
2. `detect_layout` runs `mmls`, probes every data partition with `fsstat`, then:
   - prefers an **NTFS** volume (Windows disks);
   - otherwise takes the **largest non-EFI** data partition (Linux/macOS root).
3. The chosen partition offset is stored in the layout and used by every later
   `fls` / `istat` / `icat` call, so the tree, triage and preview all target the
   correct volume.

The evidence page and the layout warnings show which partition was selected and
which candidates were rejected.

### Image preview

Raster images are rendered inline instead of dumped as hex:

| Format | Detection |
| --- | --- |
| PNG, JPEG, GIF, BMP, WebP, TIFF | magic bytes only, with width/height parsed from the header |

- The panel shows the image, format, pixel size, byte size and a short hash.
- Bytes are served by `GET /evidence/{id}/entries/{entry_id}/image` with
  `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src
  'none'; sandbox` and `Cache-Control: no-store`.
- Only those raster formats are ever served. **SVG is never rendered as an
  image** (it can carry script); it stays in the text view. Other formats fall
  back to hex.
- Images larger than `DFIR_PREVIEW_MAX_IMAGE_BYTES` (default 32 MiB) are not
  inlined; the panel shows hex with an explicit warning.

### Viewing content that is too large

Preview is bounded, but nothing is silently cut off — every limit is reported
and there is a way past it:

| Situation | What the panel offers |
| --- | --- |
| File larger than the requested range | **Load next** (same size), **Load 256 KiB**, **Load 1 MiB** |
| More than `DFIR_PREVIEW_TEXT_MAX_LINES` (10 000) lines | The next offset is computed from the last shown line, so paging continues instead of stopping at the line cap |
| Want the whole file at once | **Download full copy** — streams the extracted working copy (bounded by `DFIR_PREVIEW_MAX_DOWNLOAD_BYTES`, default 512 MiB) with `Content-Disposition: attachment` and `nosniff` |
| SQLite cell longer than `DFIR_PREVIEW_SQLITE_CELL_CHARS` | Truncated in the grid, full value up to 2 000 chars in the cell tooltip |

The download route `GET /evidence/{id}/entries/{entry_id}/download` only ever
serves the validated working copy inside the case export directory; the caller
cannot supply a path. Too-large downloads return
`preview_download_too_large` with the exact size and limit.

### SQLite preview

Files whose header is `SQLite format 3\0` open in a database view instead of
hex:

- schema list (tables and views), column names/types, primary-key markers and a
  row count capped at 1000 (`1000+` beyond that);
- `PRAGMA page_size`, `encoding`, `user_version`, `journal_mode`;
- **Show rows** per table renders a paginated read-only grid. The row toolbar
  offers 50 / 200 / 500 rows, and **All columns** reveals columns hidden beyond
  the first six. Long cells render as an inline expander: click the summary to
  read the full value in the browser (text up to
  `DFIR_PREVIEW_SQLITE_CELL_FULL_CHARS`, default 4 000 chars; BLOBs as hex), no
  extra request and no navigation away from the table.

Safety:

- opened with `mode=ro&immutable=1` and `PRAGMA query_only=1`, so the working
  copy is never written and WAL files are not replayed;
- the table name must already exist in `sqlite_master`; identifiers are quoted
  and `LIMIT`/`OFFSET` are bound parameters, so no SQL injection surface;
- `sqlite3.set_progress_handler` aborts a query that exceeds
  `DFIR_PREVIEW_SQLITE_TIMEOUT`; rows, tables, columns and cell length are
  capped by `DFIR_PREVIEW_SQLITE_*` settings.

Endpoints: `GET /evidence/{id}/entries/{entry_id}/sqlite?table=&offset=&limit=`
(JSON) and `.../sqlite/panel` (HTMX fragment). MCP: `preview_sqlite_table`.

### Symbolic links

`/etc/os-release` on Linux is usually a **symlink** to `../usr/lib/os-release`;
`icat` on the link inode returns zeros, not the target text. `istat` does report
``symbolic link to: …``, so preview resolves the link inside the evidence:

- relative targets are resolved against the link's directory, ``..`` segments
  are normalised, and the result must stay inside the evidence;
- if the target is in the filesystem index it is previewed, with a warning that
  the content came from the link target;
- an escaping target, a link chain or a target missing from the index returns
  ``preview_mode: symlink`` with a reason instead of empty bytes.

The same resolution is used by **Extract file** and static triage, so extracting
``/etc/os-release`` writes the real 373-byte target instead of 21 zero bytes.
(Ext4 `istat` does not expose a file name, so the export is named
``..._file.bin``; the content and hash are correct.)

### Ext4 / Unix filesystems

`istat` uses a different layout on Ext4 (``inode:``, ``mode:``, ``size:``
instead of the NTFS ``Entry: … Sequence: …`` header). The parser handles both,
so preview, extraction, triage and the tree work on Ext4 partitions too.

### Deep links into a large directory

The tree child cache is keyed by parent, page **and page size**. Without the
page size, "reveal in tree" could reuse a cached 100-item page while asking for
all children of a large directory (for example `etc` with 236 entries), so the
target (such as `etc/os-release`) was reported as "not reachable through the
loaded tree".

### Managed EWF mounts after a restart

A managed `ewfmount` exposure lives inside the server process: when the process
stops, the FUSE mount disappears. `ensure_image` now re-creates the exposure
from the source when the recorded path is gone, and rebuilds a stale mount
directory that lost its `ewf1` (instead of returning
`exposure_missing`). This also fixes preview/export failing after a restart.

## Evidence picker

The register form has a **Browse…** button next to *Evidence path*. It opens a
dialog that walks the configured allowed roots, so you no longer have to
remember an absolute path.

- Only directories and `.E01`, `.raw`, `.img`, `.ad1` files are listed.
  Continuation segments (`.E02`, `.ad2`, …) are deliberately hidden — register
  the primary file and the rest is read automatically.
- Navigation is server-side and restricted to `DFIR_ALLOWED_ROOTS`; `..`
  traversal, relative paths, files-as-folders and symlinks that resolve outside
  the roots are rejected. Symlink escapes are skipped and reported as a warning.
- Hidden dot-entries are skipped, listings are capped (2000 entries) and the
  truncation is stated explicitly.
- Selecting a file fills the path field and closes the dialog; the form is still
  submitted server-side and re-validated by `SecurityPolicy`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/picker?path=` | HTMX fragment for the dialog |
| GET | `/picker/api?path=` | JSON listing (bound to the same allowlist) |

## Run the web UI

```bash
cd /home/ubuntu/ftools_v2/dfir-browser
.venv/bin/uvicorn dfir_browser.web.app:app --host 127.0.0.1 --port 8080
```

or:

```bash
.venv/bin/dfir-browser
```

From Windows:

```powershell
ssh -L 8080:127.0.0.1:8080 ubuntu@<VM_IP>
```

Open `http://127.0.0.1:8080`. The evidence page shows:

- evidence/exposure provenance and filesystem layout
- Filesystem index status, counts, progress, Build/Rebuild button and polling
- tabs: Browse (lazy tree), All entries, Deleted files, Search, Registry,
  Event Logs, Browser Artifacts
- Explorer-style tree with lazy children, reveal-in-tree, filters and
  keyboard/ARIA support
- paginated/sortable tables, a metadata/extract panel, and an inline static
  triage panel with a "triaged" badge on the tree node
- static triage is also reachable from Search and Deleted files

When the index is not ready, Browse shows a clear "Filesystem index required"
panel with the current status and a Build/Rebuild action. The legacy
`/browse` endpoint still returns a labelled **LIVE RESULT** for API
compatibility. All index-backed tabs require a queryable index.

### Web security

- Bind address defaults to `127.0.0.1:8080`; do not expose it directly.
- **There is no user authentication.** Use loopback plus an SSH tunnel.
- `TrustedHostMiddleware` allows `127.0.0.1`, `localhost` and `testserver` by
  default; configure `DFIR_ALLOWED_HOSTS`.
- Every state-changing POST (register, extract, index build/rebuild) requires a
  CSRF token bound to a signed, HttpOnly, SameSite=Strict session cookie.
- `Origin`/`Referer` are validated when present against
  `DFIR_ALLOWED_ORIGINS`.
- GET directory, entry, deleted, search and status routes are read-only.
- Evidence filenames, paths and metadata are autoescaped; there is no `|safe`
  and no HTML/JS rendering from evidence.

### Verified browser behavior

The tree and responsive layout were exercised in headless Chromium against the
real index, not just asserted in unit tests:

- root renders 33 children; opening `Users` → `Public` → `Downloads` issues one
  direct-children request per node;
- chevron clicks expand without changing selection; name clicks select exactly
  one node (`aria-selected` count = 1);
- selecting `SysInternals.exe` shows its full path, MFT 124567, deleted status,
  timestamps, istat attributes and the extract form; switching directories
  removes the old file metadata;
- `Show deleted entries` off removes `SysInternals.exe` from the Downloads
  children;
- Search `SysInternals.exe` → Reveal in tree expands the ancestor chain, selects
  the node and scrolls it into view;
- ArrowDown/ArrowUp move focus between visible treeitems; Collapse all leaves
  only the expanded volume root; Go to root shows the synthetic volume panel;
- the tree filter hides loaded non-matching nodes and clears cleanly;
- switching Browse → All entries → Browse restores open nodes and selection
  from `sessionStorage`;
- no horizontal overflow at 280, 320, 414, 768 or 1440 CSS pixels
  (`scrollWidth == clientWidth` at every width);
- the browser console and page-error logs were empty.

## Run the MCP server (stdio)

```bash
cd /home/ubuntu/ftools_v2/dfir-browser
.venv/bin/python -m dfir_browser.mcp_server
# or: .venv/bin/dfir-browser-mcp
```

Example client configuration:

```json
{
  "mcpServers": {
    "dfir-browser": {
      "command": "/home/ubuntu/ftools_v2/dfir-browser/.venv/bin/python",
      "args": ["-m", "dfir_browser.mcp_server"],
      "env": {
        "DFIR_VAR_DIR": "/home/ubuntu/ftools_v2/dfir-browser/var"
      }
    }
  }
}
```

The server exposes **thirty** tools. The original five are:

1. `evidence_register(path)` — stateful registry registration; starts
   auto-index when enabled
2. `evidence_inspect(evidence_id)` — read-only evidence/exposure/index status
3. `filesystem_list(evidence_id, inode=5, page=1, page_size=100)` — index-backed
   when ready, otherwise a clearly marked live fallback; returns `source`
4. `filesystem_stat(evidence_id, inode)` — live `istat`, read-only
5. `filesystem_extract(evidence_id, inode, case_id)` — creates a derived file;
   not read-only

The index additions are:

6. `filesystem_index_start(evidence_id, rebuild=false)` — starts a background
   scan; `rebuild=false` is idempotent while ready/running; `rebuild=true`
   replaces the derived generation
7. `filesystem_index_status(evidence_id)` — read-only status, counts,
   timestamps, completeness and errors
8. `filesystem_list_deleted(evidence_id, include_directories=false,
   extension=None, page=1, page_size=100)` — read-only deleted view
9. `filesystem_search(evidence_id, query, exact=false, extension=None,
   deleted_only=false, allocated_only=false, entry_type=None, page=1,
   page_size=100)` — read-only parameterized index search
10. `filesystem_list_tree_children(evidence_id, parent_entry_id=0,
    include_deleted=true, directories_only=false, page=1, page_size=100,
    sort="path", sort_dir="asc", filter=None)` — read-only lazy tree children
    for one directory, with pagination and `has_children`
11. `filesystem_tree_ancestors(evidence_id, entry_id)` — read-only ancestor
    chain from the volume root to the entry's parent
12. `start_file_triage(evidence_id, entry_id, case_id="case01", force=false)` —
    starts a background static triage job; `force=false` reuses a cached result
13. `get_file_triage(job_id, strings_page=1, strings_page_size=100)` — read-only
    job status, results and one page of strings
14. `lookup_file_hash_virustotal(evidence_id, entry_id,
    allow_external_lookup, force_refresh=false)` — **external** opt-in hash
    lookup; `allow_external_lookup` must be `true`, the hash is resolved
    server-side, and the API key is never an argument or a response field

Registry and Amcache additions:

15. `registry_list_hives(evidence_id, include_deleted=false, page=1, page_size=100)`
16. `registry_index_start(evidence_id, entry_id, recover_with_logs=false, rebuild=false)`
17. `registry_index_status(hive_id)`
18. `registry_list_subkeys(hive_id, parent_key_id=null, page=1, page_size=100)`
19. `registry_get_key(hive_id, key_id, include_values=true, binary_preview_bytes=64)`
20. `registry_search(hive_id, query, search_key_names=true, search_value_names=true, string_values=true, exact=false, page=1, page_size=100)`
21. `amcache_search(hive_id, query, exact=false, page=1, page_size=100)`
22. `amcache_compare_triage(hive_id, amcache_record_id, filesystem_entry_id)`
23. `amcache_lookup_virustotal(hive_id, amcache_record_id, allow_external_lookup, force_refresh=false)`

EVTX additions:

24. `evtx_list_logs(evidence_id, include_deleted=false, indexed_only=false, page=1, page_size=100)`
25. `evtx_index_start(evidence_id, entry_id, rebuild=false)`
26. `evtx_index_status(log_id)`
27. `evtx_query_events(evidence_id, log_id=null, channels=null, providers=null, event_ids=null, levels=null, user_sid=null, computer=null, process_id=null, time_from=null, time_to=null, text=null, preset=null, sort_dir="asc", page=1, page_size=100)`
28. `evtx_get_event(log_id, record_id, include_raw_xml=false)`
29. `evtx_get_context(log_id, record_id, before=5, after=5)`
30. `evtx_activity_summary(evidence_id, log_ids=null, time_from=null, time_to=null, top_n=20)`

Browser artifact additions:

31. `browser_list_artifacts(evidence_id, browser=null, artifact_type=null, include_deleted=false, page=1, page_size=100)`
32. `browser_index_start(evidence_id, entry_id, recover_sidecars=true, rebuild=false)`
33. `browser_index_status(artifact_id)`
34. `browser_list_profiles(evidence_id, browser=null, page=1, page_size=100)`
35. `browser_query_downloads(evidence_id, profile_ids=null, query=null, domain=null, filename=null, extension=null, states=null, time_from=null, time_to=null, executable_only=false, preset=null, include_query_string=false, page=1, page_size=100)`
36. `browser_query_history(evidence_id, profile_ids=null, query=null, domain=null, time_from=null, time_to=null, include_query_string=false, page=1, page_size=100)`
37. `browser_query_cache(evidence_id, profile_ids=null, query=null, domain=null, time_from=null, time_to=null, include_query_string=false, page=1, page_size=100)`
38. `browser_search_all(evidence_id, query=null, domain=null, time_from=null, time_to=null, include_query_string=false, page=1, page_size=100)`
39. `browser_get_record(record_type, record_id)`
40. `browser_correlate_download(evidence_id, download_id, page=1, page_size=50)`
41. `browser_activity_summary(evidence_id, profile_ids=null, time_from=null, time_to=null, top_n=20)`

File preview addition:

42. `preview_file_content(evidence_id, entry_id, mode="auto", offset=0, limit=65536)`
43. `recycle_bin_metadata(evidence_id, entry_id)`

ShellBags additions:

44. `shellbags_index_start(evidence_id, rebuild=false)`
45. `shellbags_index_status(evidence_id)`
46. `shellbags_list_devices(evidence_id)`
47. `shellbags_tree(evidence_id, parent_id=null, hive_id=null, page=1, page_size=100)`
48. `shellbags_search(evidence_id, query=null, kind=null, user_sid=null, device_id=null, hive_id=null, time_from=null, time_to=null, page=1, page_size=100)`
49. `shellbags_get_node(node_id)`

MCP annotations mark read-only tools, stateful index registration/start, and
the derived-file extract tool. No `run_command`, shell, or arbitrary-command
tool exists. Every response is marked as untrusted evidence data.

## Truncated live directory listings

The live `fls` fallback is capped by `DFIR_MAX_OUTPUT_BYTES` (256 KiB). It
always reports `complete`, `truncated` and `warning`; a partial final line is
dropped. The GUI shows **INCOMPLETE LISTING**. The full index scan does not use
this cap; it streams with the separate index limits listed above and marks the
index `incomplete` if a limit is hit.

## Audit log

`var/audit/commands.jsonl` is append-only JSONL, mode `0600`, protected by a
thread lock and `flock`. It contains command metadata:

- UTC timestamp, request/correlation id, evidence id
- tool name, sanitized argv
- exit code, duration, timeout flag
- stdout/stderr truncation flags and bytes seen
- success/failure

The index scan additionally records entries processed, indexed rows, parse
errors, completeness, scan id and rebuild flag. Audit events cover index
start/rebuild/finish/failure, search summaries, deleted-list summaries and
extraction. The audit log never contains command stdout/stderr content, file
content, passwords, CSRF tokens or session secrets; search summaries record
query length and filters, not the query text.

## Registry persistence

`var/registry.json` uses schema version 2, mode `0600`. Writes use a temporary
file in the same directory followed by `os.replace`, with thread and
cross-process `flock` serialisation. A malformed or newer-schema registry raises
a clear error and is never silently reset.

## Tests and smoke checks

```bash
cd /home/ubuntu/ftools_v2/dfir-browser
.venv/bin/pytest -q
.venv/bin/python scripts/smoke_evidence.py
.venv/bin/python scripts/index_smoke.py
.venv/bin/python scripts/mcp_smoke.py
```

The suite currently runs 392 tests: tree, static triage, VirusTotal secrets,
client, cache/rate limiting, registry/Amcache parser, store, web and MCP coverage, EVTX,
browser artifacts (WebCache ESE, Chromium/Firefox SQLite), file content preview,
ShellBags,
discovery/normalization/index/web/MCP coverage, plus real-evidence integration
tests. The integration tests use the real E01 and
mounted `ewf1`, register with an explicit source-hash-pinned mapping, run a
full index, assert the acceptance paths, walk the tree
(root → Users → Public → Downloads), check reveal/ancestors and hash the E01
before/after. Skip them without evidence:

```bash
DFIR_SKIP_EVIDENCE_TESTS=1 .venv/bin/pytest -q
```

Build and smoke-test the wheel:

```bash
.venv/bin/pip wheel . --no-deps -w dist
.venv/bin/python scripts/wheel_smoke.py \
  --wheel dist/dfir_browser-0.14.0-py3-none-any.whl
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DFIR_VAR_DIR` | `./var` | Registry, cases, exports, mounts, audit, secret, index |
| `DFIR_EVIDENCE_ALLOWLIST` | `/home/ubuntu/test:/home/ubuntu/evidence` | Colon-separated allowed roots |
| `DFIR_EWF_MAPPINGS` | unset | Explicit E01 -> exposure JSON (overrides file) |
| `DFIR_EWF_MAPPING_FILE` | `<var_dir>/ewf_mappings.json` | Explicit mapping file |
| `DFIR_EWF_AUTOMOUNT` | `0` | Allow managed `ewfmount` exposures |
| `DFIR_CMD_TIMEOUT` | `60` | Default subprocess timeout (seconds) |
| `DFIR_EXTRACT_TIMEOUT` | `600` | `icat` streaming timeout (seconds) |
| `DFIR_HASH_TIMEOUT` | `900` | Bound for source/extracted SHA-256 hashing |
| `DFIR_MAX_OUTPUT_BYTES` | `262144` | Live command stdout/stderr cap |
| `DFIR_MAX_METADATA_BYTES` | `65536` | Raw `istat` output cap |
| `DFIR_AUTO_INDEX` | `1` | Start a background index after registration |
| `DFIR_INDEX_DB` | `<var_dir>/index/filesystem.db` | SQLite index path |
| `DFIR_INDEX_TIMEOUT` | `1800` | Full scan duration limit (seconds) |
| `DFIR_INDEX_MAX_ENTRIES` | `2000000` | Scan entry limit |
| `DFIR_INDEX_BATCH_SIZE` | `1000` | SQLite insert batch size |
| `DFIR_INDEX_MAX_LINE_BYTES` | `65536` | Maximum single `fls` line |
| `DFIR_INDEX_MAX_RAW_ERROR_BYTES` | `4096` | Bounded raw parse-error capture |
| `DFIR_INDEX_PAGE_SIZE_DEFAULT` | `100` | Default UI/MCP page size |
| `DFIR_INDEX_MAX_PAGE_SIZE` | `500` | Maximum page size |
| `DFIR_INDEX_SCANNER_VERSION` | `fls-r-p-l-v1` | Scanner configuration version |
| `DFIR_DEBUG_RAW` | `0` | Persist live raw `fls`/`istat` output under `var/debug` |
| `DFIR_HOST` / `DFIR_PORT` | `127.0.0.1` / `8080` | Web bind address |
| `DFIR_ALLOWED_HOSTS` | `127.0.0.1,localhost,testserver` | TrustedHost allowlist |
| `DFIR_ALLOWED_ORIGINS` | loopback origins for the port | CSRF Origin/Referer allowlist |
| `DFIR_SECRET_KEY_FILE` | `<var_dir>/secret.key` | CSRF signing secret |
| `DFIR_AUDIT_LOG` | `<var_dir>/audit/commands.jsonl` | Command/event audit JSONL |
| `DFIR_TRIAGE_DB` | `<var_dir>/cases/triage.db` | Triage job/result database |
| `DFIR_TRIAGE_PROFILE` | `static-triage-v1` | Triage profile/cache version |
| `DFIR_TRIAGE_MAX_FILE_SIZE` | `268435456` | Maximum triaged file size (bytes) |
| `DFIR_TRIAGE_MAX_STRINGS` | `10000` | Maximum stored strings per job |
| `DFIR_TRIAGE_MAX_STRING_LENGTH` | `4096` | Maximum characters per string |
| `DFIR_TRIAGE_MIN_STRING_LENGTH` | `6` | Minimum characters per string |
| `DFIR_TRIAGE_ANALYZER_TIMEOUT` | `30` | Per-analyzer timeout (seconds) |
| `DFIR_TRIAGE_JOB_TIMEOUT` | `120` | Whole-job deadline (seconds) |
| `DFIR_TRIAGE_YARA_TIMEOUT` | `30` | YARA scan timeout (seconds) |
| `DFIR_TRIAGE_MAX_CONCURRENT_JOBS` | `2` | Worker threads for triage |
| `DFIR_TRIAGE_MAX_QUEUED_JOBS` | `8` | Queued+running job cap |
| `DFIR_TRIAGE_ENTROPY_CHUNK_SIZE` | `4096` | Entropy chunk size (bytes) |
| `DFIR_TRIAGE_ENTROPY_MAX_BYTES` | `16777216` | Bytes considered for chunks |
| `DFIR_TRIAGE_MAX_FINDINGS` | `2000` | Maximum suspicious-string findings |
| `DFIR_TRIAGE_MAX_YARA_MATCHES` | `200` | Maximum YARA matches stored |
| `DFIR_TRIAGE_MAX_TOOL_OUTPUT` | `1048576` | Per-tool stdout/stderr cap |
| `DFIR_TRIAGE_MAX_EXIFTOOL_ITEMS` | `300` | Maximum ExifTool tags stored |
| `DFIR_TRIAGE_YARA_RULES` | `./rules/yara` | YARA rule directory override |
| `VT_API_KEY` | unset | VirusTotal API key (takes precedence over the UI store) |
| `DFIR_VIRUSTOTAL_DB` | `<var_dir>/cases/virustotal.db` | VirusTotal report cache |
| `DFIR_VIRUSTOTAL_SECRET_DIR` | `<var_dir>/secrets` | UI key store directory (`0700`) |
| `DFIR_VIRUSTOTAL_CACHE_TTL` | `86400` | Found-report cache TTL (seconds) |
| `DFIR_VIRUSTOTAL_NOTFOUND_TTL` | `3600` | Not-found cache TTL (seconds) |
| `DFIR_VIRUSTOTAL_RATE_LIMIT` | `4` | Outbound requests per minute |
| `DFIR_VIRUSTOTAL_TIMEOUT` | `15` | VirusTotal request timeout (seconds) |
| `DFIR_VIRUSTOTAL_MAX_RESPONSE_BYTES` | `2000000` | Response size cap |
| `DFIR_REGISTRY_DB` | `<var_dir>/cases/registry.db` | Registry index database |
| `DFIR_REGISTRY_MAX_HIVE_SIZE` | `536870912` | Maximum hive working-copy size |
| `DFIR_REGISTRY_MAX_KEYS` | `300000` | Key limit per hive |
| `DFIR_REGISTRY_MAX_DEPTH` | `64` | Key nesting limit |
| `DFIR_REGISTRY_MAX_VALUE_BYTES` | `8388608` | Raw value processing cap |
| `DFIR_REGISTRY_MAX_TEXT_LENGTH` | `65536` | Decoded text cap |
| `DFIR_REGISTRY_BINARY_PREVIEW_BYTES` | `64` | Binary preview default |
| `DFIR_REGISTRY_BUILD_TIMEOUT` | `180` | Registry build timeout (seconds) |
| `DFIR_REGISTRY_MAX_AMCACHE_RECORDS` | `100000` | Amcache record cap |
| `DFIR_REGISTRY_PAGE_SIZE_DEFAULT` | `100` | Registry page size |
| `DFIR_REGISTRY_PAGE_SIZE_MAX` | `500` | Registry max page size |
| `DFIR_EVTX_DB` | `<var_dir>/cases/evtx.db` | EVTX event index database |
| `DFIR_EVTX_MAX_FILE_SIZE` | `2147483648` | Maximum EVTX file size |
| `DFIR_EVTX_MAX_RECORDS` | `500000` | Maximum records per log |
| `DFIR_EVTX_MAX_EVENT_XML_BYTES` | `524288` | Per-record XML cap |
| `DFIR_EVTX_MAX_FIELD_LENGTH` | `8192` | Decoded field cap |
| `DFIR_EVTX_MAX_RAW_XML_BYTES` | `65536` | Stored/returned raw XML cap |
| `DFIR_EVTX_PARSER_TIMEOUT` | `300` | Parser timeout (seconds) |
| `DFIR_EVTX_INDEX_TIMEOUT` | `300` | Whole-job timeout (seconds) |
| `DFIR_EVTX_MAX_CONCURRENT_JOBS` | `1` | Concurrent EVTX jobs |
| `DFIR_EVTX_PAGE_SIZE_DEFAULT` | `100` | Default page size |
| `DFIR_EVTX_PAGE_SIZE_MAX` | `500` | Maximum page size |
| `DFIR_EVTX_CONTEXT_BEFORE` / `_AFTER` | `5` / `5` | Default context size |
| `DFIR_EVTX_CONTEXT_MAX` | `50` | Maximum context per side |
| `DFIR_EVTX_BATCH_SIZE` | `500` | Batch insert size |

## Layout detection on this evidence

`mmls` exits 1 on the volume image and returns no partition table. That is not
treated as corrupt evidence: the core falls back to `fsstat -o 0`, which
identifies NTFS at sector 0:

```json
{"scope": "volume", "filesystem": "NTFS", "offset_sectors": 0, "method": "fsstat"}
```

## Measured performance on the test evidence

Measured by `scripts/index_smoke.py` and direct tree queries on this VM with
`/home/ubuntu/test/temp_extract_dir/SysInternals.E01` and
`/home/ubuntu/mnt/ewf/ewf1` (representative final run; page-cache state
affects the first queries):

- full index wall time: ~32 s including the tree-link pass and tree index
  creation (fresh schema v2)
- entries seen/indexed: 132,978 / 132,978
- deleted files / directories: 49,471 / 19,295
- allocated files / directories: 51,457 / 12,755
- parse errors: 0
- SQLite database: 289,439,744 bytes (~276 MiB) with tree indexes; a live
  rebuild can leave freed pages until `VACUUM`
- root children: ~2.0 ms (33 children)
- `Users` children: ~1.1 ms
- `Users/Public/Downloads` children: ~1.0 ms
- `$OrphanFiles` first page (1,096 total): ~2.0 ms
- root sorted by size / modified: ~2.8 ms / ~1.2 ms
- ancestor chain (Users/Public/Downloads): ~3.3 ms warm; the first call in a
  fresh process can take ~1.9 s while SQLite warms the page cache
- deleted first page (49,471 total): ~21 ms
- deleted contains search for `Sysinternals.exe`: ~300 ms (cold)
- exact indexed search for `Sysinternals.exe`: ~2.9 ms

These numbers are observations on this VM, not performance guarantees.

## Known limitations

- Single-user, unauthenticated web UI; use loopback binding plus an SSH tunnel.
  The CSRF cookie is not `Secure` because the default transport is HTTP on
  loopback.
- Explicit mappings are administrator-supplied trust anchors. The app pins the
  source container SHA-256 and verifies the exposure size/read-only state/
  `fsstat`/`img_stat`, but it does not hash the entire 14.7 GB raw exposure and
  compare it to the EWF media digest.
- Managed mounts depend on FUSE permissions; cleanup applies only to mounts
  created by the current process. Stale mounts after a hard kill may require
  manual inspection.
- The index is derived data: rebuilding replaces its generation but never
  modifies evidence or extracted files. SQLite is not auto-vacuumed, so a
  rebuild can leave freed pages in the database file; run `VACUUM` manually if
  disk usage matters.
- Parse errors or scan limits mark the index `incomplete`; results are still
  queryable but are clearly flagged and may be missing entries. Contains search
  over large deleted sets can take hundreds of milliseconds; exact search uses
  the NOCASE indexes.
- The parser is tuned for The Sleuth Kit 4.12.1 output. Non-UTF-8 filenames are
  decoded with replacement characters; `fls` uses tabs as delimiters, so a
  filename containing a literal tab is ambiguous.
- `fls -r -p` emits normalized paths, not parent MFT numbers. Duplicate
  directory paths (for example several deleted `$OrphanFiles/INetCache`
  entries) cannot be distinguished by path alone; their children are attached
  to one canonical row (allocated first, then lowest row id). The path remains
  visible in metadata and search results.
- Tree entry IDs are SQLite row IDs scoped to the active scan generation. A
  rebuild replaces the generation, so an old `?entry=` URL or stale search
  result may resolve to `entry_not_found`; the UI shows a clear error instead
  of guessing.
- The tree filter matches only nodes already loaded in the browser. It is not
  a recursive search; use the Search tab for cross-index queries.
- Live `fls` fallback is capped by `DFIR_MAX_OUTPUT_BYTES`; the full index scan
  has separate entry/time/line limits.
- `ewfverify` is not run automatically. Run it separately for a full media
  verification pass.
- No timeline, browser-history parser or malware execution was added.
  Extractions, triage copies and registry working copies are plaintext under
  `var/cases`; the audit log has no rotation.
- Registry parsing is read-only and does not replay transaction logs. A dirty
  hive is parsed as-is with an explicit warning; recovered data is not claimed.
  SAM/SECURITY are metadata-only and credential material is never decrypted.
- Amcache schema variation is handled heuristically from real keys. A FileId
  whose format is not unambiguous is preserved raw with
  `hash_algorithm="unknown"` and is excluded from hash comparison and
  VirusTotal lookup rather than guessed.
- The registry key tree is lazily loaded and indexed per hive; very large hives
  may stop at the configured key/depth/time limits and are marked `partial`
  with a warning. Binary values are only returned as a bounded preview.
- EVTX fixtures in this repository are synthetic. Real-record parsing is covered
  by integration tests against the evidence image and by synthetic XML fed to
  the normalizer; the committed `.evtx` file is an empty, valid container with
  no user data.
- Rendered Windows messages are unavailable without message resource DLLs; the
  UI reports `message_unavailable` and never fabricates text. FTS5 is used when
  present, otherwise a `LIKE` fallback applies. Text search matches stored
  fields, so a value that only exists inside a message DLL string is not found.
- Triage is static only. There is no dynamic sandbox, no unpacking, no
  emulation and no VirusTotal/network lookup. A triage job is evidence, not a
  verdict: suspicious strings and YARA hits are indicators that must be
  correlated, and "no active YARA rules" is not a clean result.
- Triage depends on `file`, `exiftool`, `pefile` and `yara-python`. If any is
  missing the analyzer reports `unavailable` and the job becomes `partial`;
  the remaining analyzers still run.
- Strings are byte-scanned, not semantically parsed; a literal tab or a
  non-UTF-8 filename segment can split or garble a string. Only the first page
  of very large directories or string sets is rendered in the browser.
- Every cache hit still extracts the file once to compute the SHA-256 cache
  key; analyzers are not re-run. Rebuilding the index changes entry row IDs, so
  old `?entry=` links and old triage jobs may no longer resolve.
- Triage runs in-process threads, not a separate queue service. A hard kill
  mid-job leaves the job `interrupted` on next startup rather than resuming it.
- VirusTotal is a third-party service. A hash lookup still discloses that a
  specific hash exists in the analyst's case, consumes API quota, and is subject
  to VirusTotal's terms. The UI reports are snapshots and are never a verdict.
  The stored key is protected only by filesystem permissions, not encryption.
  The local 4/min limiter is per process and per key, not a distributed quota
  manager.
