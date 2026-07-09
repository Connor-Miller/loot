# Hard embargo mechanism (#14 design)
GitHub: #59

Type: grilling
Status: open
Blocked by: —

## Question

Pick the mechanism that makes embargo adversary-proof (closes the honest-clock/key-custody gap in CONTEXT.md's threat model). Leading candidate from charting: an **escrow service on the relay holding recipient-wrapped keys** (SealedGrant reuse — the service holds only ECIES-wrapped blobs, so it cannot read either; holders cannot read early because the key material simply isn't on their machine until the service releases it at `reveal_at`). Alternatives to weigh: time-lock encryption (no trusted party, research-grade), threshold release among peers. Also decide: what does the *demo* trust — the same VPS the dev runs is still self-trust, so state the operator≠holder argument honestly. Resolution likely graduates 2–3 implementation issues; consider /design-an-interface for the escrow seam (`Escrow::flush` → network call is the designed swap point).
