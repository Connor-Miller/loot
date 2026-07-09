# 03 — Establish the Rust run/verify handoff loop
GitHub: #74

Type: task
Status: resolved
Blocked by: —

## Question

Claude cannot run `cargo`/`rustc` in this environment, but some CA4 decisions may
need empirical input (a resolver prototype, a test run, inspecting how the
attestation lane actually behaves). Establish the concrete loop so those
decisions aren't blocked:

- What Connor runs in his Rust environment (e.g. `cargo test -p loot-core`, a
  scratch binary, a `loot attest` + resolver spike) and what output to paste back
  into the relevant ticket.
- Confirm the shipped attestation lane can be exercised end-to-end today
  (`loot attest <change> [role]` writes to `.loot/attestations`).

## Notes

HITL handoff: Claude writes the checklist/runbook; Connor executes and reports.
Resolving this unblocks any prototype-backed decision downstream. Independent of
tickets 01/02.

## Answer

No CA4 *decision* ended up needing empirical input (01 resolved the resolver as a
pure function — see ADR 0025 — so no prototype was required). So this loop exists
for the **implementation** phase: a ready runbook for whoever builds CA4 in a
Rust-capable environment. The loop is *defined* here; every step below is *run*
by Connor / the Rust agent.

### The loop

1. **Baseline (start green).** Before touching code, confirm `main` builds and
   tests pass, so any later failure is yours:

   ```
   cargo build
   cargo test            # full suite incl. HTTP relay integration (~25s)
   cargo test -p loot-core   # fast inner loop, no I/O
   ```

2. **Inner dev loop** while implementing `loot_core::buoy::resolve` and `cmd_buoy`:
   `cargo test -p loot-core buoy` (unit tests from the CA4 test plan), then the
   full `cargo test` before opening a PR.

3. **CLI smoke** once `cmd_buoy` exists — exercises the exit-code contract
   (0 resolved / 2 no-buoy / 3 ambiguous / 1 error):

   ```
   cargo build --release
   export PATH="$PWD/target/release:$PATH"
   cd "$(mktemp -d)"
   loot init --identity alice
   printf 'x\n' > a.txt && loot status -m one && loot new
   loot buoy reviewed; echo "exit=$?"        # expect: no buoy, exit=2
   CID=$(loot log | ...pick a change id...)
   loot attest "$CID" reviewed
   loot buoy reviewed; echo "exit=$?"         # expect: that change, exit=0
   loot buoy --porcelain reviewed             # expect: B<TAB><id><TAB>reviewed
   ```

### Paste-back format

For each command whose result matters, paste into the relevant ticket/PR:

```
$ <command>
<last ~15 lines of output>
exit=<code>
```

That's enough for me to read the result back into the map or a ticket without a
Rust environment. For a failing `cargo test`, include the failing test name and
its assertion output.

### Facts confirmed from reading the code (no run needed)

- The attestation lane ships: `loot attest <change-id> [role]` (default role
  `reviewed`), stored in `.loot/attestations`; engine exposes `all_attestations()`
  / `attestations_for()`. So step 3's `attest` works today; only `buoy` is new.

