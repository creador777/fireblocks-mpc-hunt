# Scalable Corpus Windows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore scheduled fuzzing for corpora larger than 100,000 files without moving private data, while preventing the aggregator from producing a corpus the reader cannot consume.

**Architecture:** Treat the first two SHA-1 digits as 256 logical buckets over the existing flat directory. Scan all entries for structural and capacity validation, select one non-empty bucket deterministically per shard, and hash only that bucket before choosing its local 24-unit window. Reuse the same inventory validator at the aggregate boundary and expose materializer failures through a closed sanitizer.

**Tech Stack:** Python 3 standard library, Bash, GitHub Actions YAML, `unittest`, local bare-Git integration tests.

**Spec:** `docs/superpowers/specs/2026-08-17-scalable-corpus-windows.md`

## Global Constraints

- Preserve the flat private-brain path `corpus/<harness>/<sha1>`.
- Preserve the 24-unit total window and pinned-wave retry determinism.
- Do not expose corpus paths, names, bytes, manifests, or raw logs publicly.
- Do not push, deploy, delete private data, or spend paid credits.

---

### Task 1: Logical-prefix materialization

**Files:**
- Modify: `tests/test_materialize_window.py`
- Modify: `scripts/materialize_window.py`

**Interfaces:**
- Consumes: existing positional CLI `DEST SHARD COUNT WAVE COMMON PRIVATE...`
- Produces: `scan_private_inventory(paths)`, deterministic prefix scheduling, and the existing tuple fields plus private-only prefix metadata.

- [x] **Step 1: Write failing behavioral tests**

Add tests that temporarily lower the safety constants and prove: an inventory
larger than the selected-bucket cap succeeds when each prefix is bounded; retry
selection is identical; separate shards select separate prefixes; bad
structure anywhere fails; a selected bad hash fails; an unselected bad hash is
deferred; and inventory/bucket caps return different codes.

- [x] **Step 2: Run the focused suite and verify RED**

Run: `python3 -m unittest -v tests.test_materialize_window`

Expected: new tests fail because the implementation still rejects the merged
inventory at the legacy global limit and exposes no prefix metadata.

- [x] **Step 3: Implement the minimum prefix scheduler**

Implement a streaming structural inventory scan, derive sorted non-empty
prefixes from valid names, choose prefix and local rotation from the wave
ordinal, hash only matching entries, keep copy-time rehashing, and add the
schedule version/prefix/rotation to the private manifest.

- [x] **Step 4: Run the focused suite and verify GREEN**

Run: `python3 -m unittest -v tests.test_materialize_window`

Expected: all materializer tests pass.

### Task 2: Aggregate-boundary capacity gate

**Files:**
- Create: `scripts/validate_pool_capacity.py`
- Create: `tests/test_pool_capacity.py`
- Modify: `scripts/aggregate_ingest.sh`
- Modify: `tests/test_brain_publish_aggregate_e2e.sh`

**Interfaces:**
- Consumes: zero or more flat private corpus directories.
- Produces: exit 0 for a structurally valid, consumable pool; exit 2 with only a closed status code for a rejected pool.

- [x] **Step 1: Write failing validator tests**

Exercise real temporary directories for valid multi-prefix inventory, malformed
names, wrong types, inventory overflow, byte overflow, and one overfull prefix.

- [x] **Step 2: Verify RED**

Run: `python3 -m unittest -v tests.test_pool_capacity`

Expected: import or behavior failure because the validator does not exist.

- [x] **Step 3: Implement and wire the validator**

Reuse the materializer's structural inventory scanner. Before aggregate commit,
derive each known harness directory through `corpus_dir_for` and validate every
existing directory. Do not hash the trusted historical pool again; publisher
and aggregator already hash every new candidate.

- [x] **Step 4: Verify GREEN and E2E**

Run: `python3 -m unittest -v tests.test_pool_capacity`

Run: `bash tests/test_brain_publish_aggregate_e2e.sh`

Expected: validator tests and the real publish-to-aggregate flow pass.

### Task 3: Closed failure observability

**Files:**
- Create: `scripts/report_materialize_failure.py`
- Create: `tests/test_report_materialize_failure.py`
- Modify: `.github/workflows/hunt.yml`
- Modify: `tests/test_cloud_window_workflow.py`

**Interfaces:**
- Consumes: a bounded materializer stderr sidecar.
- Produces: exactly one allowlisted `status=fail_closed code=...` line, otherwise `materializer_internal`.

- [x] **Step 1: Write failing sanitizer and workflow tests**

Test a known code, multiple lines, non-ASCII data, oversized input, and a line
containing a private path. Test the workflow behavior: separate stdout/stderr,
sanitizer invocation, sidecar cleanup, materialize step id, and finalizer gate.

- [x] **Step 2: Verify RED**

Run: `python3 -m unittest -v tests.test_report_materialize_failure tests.test_cloud_window_workflow`

Expected: missing sanitizer and missing workflow gates.

- [x] **Step 3: Implement sanitizer and workflow wiring**

Read at most 4 KiB as strict ASCII, require exactly one complete line and an
allowlisted code exported by `materialize_window.py`, print one line, clean both
sidecars, and skip finalization only when the materialize step failed.

- [x] **Step 4: Verify GREEN**

Run: `python3 -m unittest -v tests.test_report_materialize_failure tests.test_cloud_window_workflow`

Expected: all tests pass and no private marker reaches stdout/stderr.

### Task 4: CI coverage and complete verification

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/test_workflow_policy.py`

**Interfaces:**
- Consumes: new Python test modules.
- Produces: defensive CI that cannot omit materializer, pool-capacity, failure-sanitizer, or feedback-closure coverage.

- [x] **Step 1: Add a failing CI-wiring policy test**

Assert that the explicit CI `unittest` command includes
`tests.test_materialize_window`, `tests.test_pool_capacity`,
`tests.test_report_materialize_failure`, and
`tests.test_corpus_feedback_closure`.

- [x] **Step 2: Verify RED, then update CI and verify GREEN**

Run: `python3 -m unittest -v tests.test_workflow_policy`

Expected before/after: fail for missing modules, then pass after editing CI.

- [x] **Step 3: Run syntax, YAML, focused tests, and integration tests**

Run the commands from `.github/workflows/ci.yml`: Bash/Python syntax, the Linux
test image, explicit Python suites, YAML parse, brain path contract, private
publisher, publish/aggregate E2E, telemetry pipeline, and runner tests.

- [x] **Step 4: Review the diff and record residual risk**

Confirm there are no personal paths or credentials, no private output expansion,
no private-repo mutation, and no push. Record that full-checkout growth remains
outside this fix.
