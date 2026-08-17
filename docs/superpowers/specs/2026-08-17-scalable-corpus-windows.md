# Scalable Corpus Windows Specification

## Problem

The private corpus is a flat, content-addressed directory. It grew beyond the
legacy 100,000-file cutoff, after which every shard failed before fuzzing
because `materialize_window.py` treated that value as both the
complete-inventory limit and the working-window limit.

The workflow also redirected the materializer's already-sanitized failure to a
private file, then emitted only a generic exit code. The always-running
finalizer produced a second failure and obscured the primary cause.

## Required behavior

1. Keep the existing private-brain layout and publishing protocol unchanged:
   `corpus/<harness>/<sha1>`.
2. Partition valid private unit names logically by their first two hexadecimal
   digits. A shard validates the complete inventory's structure and declared
   sizes, then hashes and selects units only from its scheduled prefix bucket.
3. Derive the schedule only from the pinned wave inputs:
   `ordinal = wave_number * wave_shard_count + shard_index`.
   Choose a non-empty prefix by `ordinal % prefix_count`; rotate its local
   windows by `ordinal // prefix_count`.
4. Preserve the 24-unit total window, common-seed validation, overlap
   validation, retry determinism, and copy-time rehashing.
5. Keep independent safety limits for total inventory, selected bucket, unit
   size, and total declared inventory bytes. Capacity validation must run in
   the aggregate job before the private pool is committed and pushed.
   The initial fail-closed limits are 1,000,000 physical files per harness,
   100,000 files and 128 MiB per two-hex bucket, 1 MiB per unit, and 512 MiB
   declared bytes per harness.
6. On materialization failure, publish exactly one allowlisted status line or
   the fallback `status=fail_closed code=materializer_internal`. Never publish
   paths, unit names, bytes, manifests, or raw logs.
7. Skip the evidence finalizer when materialization never completed. Continue
   running it after every post-fuzzer failure.
8. Execute the materializer and feedback-closure tests in defensive CI.

## Compatibility and limits

- No private corpus files are moved, deleted, or rewritten.
- The reader remains compatible with every existing ingest branch and the
  current append-only aggregator.
- Structural validation remains global; content validation becomes lazy by
  prefix. A corrupt unit with a valid name in an unselected prefix is rejected
  when that prefix is scheduled. Every newly published unit is still hashed by
  both publisher and aggregator before it reaches the pool.
- This fixes the correctness cutoff and bounds per-shard hashing. Full Git
  checkout cost still grows with the repository and is a separate future
  optimization.
- Coverage is deterministic for a fixed shard count. Changing the configured
  shard count between waves can create gaps or overlaps in the ordinal stream;
  retries of a pinned wave remain stable.

## Rollout and rollback

This change requires no private-brain migration: the flat paths and append-only
publisher remain unchanged. Deploy the public reader, workflow, and aggregate
guard together, then run a one-shard canary before re-enabling the regular
schedule. If the canary fails, disable `FIREBLOCKS_HUNT_ENABLED` and revert the
public commit. The private pool is not rewritten, so rollback does not require
restoring corpus data.
