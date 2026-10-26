# Transaction Journal State Machine

**Status:** implemented as a pure Rust core model; no privileged installer or filesystem executor exists.

## Purpose

An interrupted package operation must not guess whether a write finished. The core records explicit transaction phases and exposes a conservative recovery classification. The journal is evidence of intended state transitions, not cryptographic proof of filesystem state.

## States and transitions

```text
planned -> acquiring -> verifying -> staging -> ready_to_commit -> committing -> committed
   |           |           |          |             |                 |
   +---------- +-----------+----------+-------------+-----------------> failed
                                                   -> rolling_back -> rolled_back
                                                                        |
                                                                        v
                                                                      failed
```

The transition rules are encoded in the Rust library. Unknown schema versions, malformed IDs, invalid history, illegal transitions, control characters in notes, oversized journals and unknown JSON fields fail closed.

## Journal contract

Each journal contains:
- schema version and a bounded caller-generated transaction identifier;
- current state;
- an ordered event list with a monotonic sequence, previous state, next state and optional bounded note.

Every load revalidates the whole history from the initial Planned event. A journal must not be accepted merely because its final state says Committed.

## Recovery policy

- Before committing: discard uncommitted staging and create a new transaction plan. Do not auto-commit after a crash.
- In Committing, RollingBack or Failed: reconcile recorded intent against the package database and actual filesystem before further mutation. The core intentionally does not guess.
- Committed or RolledBack: no transaction recovery is required; independent integrity checks may still report discrepancies.

## Security limits

The state machine does not yet write an fsync'd journal, acquire locks, verify repository signatures, stage files, atomically switch paths, recover the filesystem, or prevent two package processes from racing. These are executor requirements and remain release blockers. Tests prove only the modeled transition invariants.

## Next integration gate

Connect the journal to a transaction executor that operates on a temporary root in tests. Inject process termination before and after each durable step; corrupt or truncate the journal; simulate disk full, permission errors and file conflicts; then prove recovery yields a complete old state, complete new state, or an explicit unrecoverable error—never silent partial success.
