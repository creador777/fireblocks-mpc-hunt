# Fireblocks MPC Hunt

Reproducible, bounded security testing for the public
[`fireblocks/mpc-lib`](https://github.com/fireblocks/mpc-lib) source target.

The current harness exercises CMP ECDSA online signing with at least one honest
participant, authenticated peer identities, deterministic synthetic fixtures,
independent signature verification, persistent-state checks, ASan and UBSan.

## Safety contract

- Only the commit recorded in `UPSTREAM.lock` is built.
- Fuzz execution receives no GitHub credential and runs without network access.
- Raw fuzzer logs and inputs are never printed by workflow steps.
- Public output is restricted to exactly seven fields:
  `harness`, `shard`, `exit_code`, `sanitizer`, `summary`,
  `stack_normalized` and `sha256`.
- Private evidence is streamed into a GPG-encrypted bundle before upload.
- Plaintext evidence must be removed and its removal verified before any upload.
- Corpus publication targets only the separate private
  `creador777/fireblocks-mpc-brain` repository and fails closed.
- Pull-request workflows never receive private corpus or publication secrets.

`CLEAN-REJECT` and `CLEAN-SIGN` are protocol outcomes, not vulnerability claims.
A sanitizer report alone is not treated as a bounty finding.

## Private brain configuration

The hunt workflow expects two different fine-grained credentials, each scoped
only to the private brain repository:

- `FIREBLOCKS_BRAIN_READ_TOKEN`: read-only contents access;
- `FIREBLOCKS_BRAIN_WRITE_TOKEN`: contents write access.

The workflow rejects missing or identical credentials. It has no public-repo
fallback. Credentials are never persisted by checkout.

Scheduled execution remains inert unless
`FIREBLOCKS_HUNT_ENABLED=true`. Scheduled wave size and per-shard budget are
controlled by `FIREBLOCKS_SHARD_COUNT` and `FIREBLOCKS_BUDGET_SECONDS`.
Accepted wave sizes are 1, 5, 15 and 25. Accepted budgets are 300, 3600 and
20700 seconds.

## Canary sequence

Enable scale only after reviewing the preceding wave:

1. one shard for 300 seconds;
2. five shards for 300 seconds;
3. fifteen shards for 3600 seconds;
4. twenty-five shards only after the previous waves are leak-free and stable.

Manual dispatch is available for canaries. Merely publishing this repository
does not enable the schedule.
