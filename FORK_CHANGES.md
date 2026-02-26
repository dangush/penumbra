# Penumbra Fork Changes for Cycles Protocol

Base: Penumbra `v2.0.4` (commit `6cefeb7f4`)
Branch: `v2.0.4-audit`

## Summary

| Change | Security Impact | Commit |
|--------|-----------------|--------|
| Redirect to Informal Systems forks of decaf377, decaf377-rdsa, poseidon377 | Medium — forks contain Cycles-specific modifications | `6df4a462e` |
| Bech32 HRPs `penumbra*` → `cycles*` (addresses, validator keys, asset registry) | Low — encoding only, ensures domain separation from Penumbra mainnet | `f046b480c`, `bd687e260` |
| Expose `tct::Hash` publicly | Medium — extends public API surface | `d8e3c8651` |
| Rseed type `[u8; 32]` → `Fq` | High — changes note blinding derivation | `947e22b94` |
| RCM domain separator → Poseidon with `cycles.derive.rcm` | High — changes commitment randomness | `947e22b94` |
| Upgrade frost-core to 2.2.0 and expose serialization types | Medium — API changes in threshold signing | `ebf3f7ee8` |
| Feature gates for WASM/CosmWasm compatibility | Low — compile-time only, all enabled by default | `a1fa2ee09` |
| CI adapted for fork (exclusions, disabled jobs, test ignores) | None | `bd687e260` |

All commit hashes reference the `v2.0.4-audit` branch.

## Forked Dependencies

| Crate | Fork Repo | Cargo.lock SHA |
|-------|-----------|----------------|
| decaf377 | [informalsystems/decaf377](https://github.com/informalsystems/decaf377) | `0945efd1` |
| decaf377-rdsa | [informalsystems/decaf377-rdsa](https://github.com/informalsystems/decaf377-rdsa) | `140b31b2` |
| poseidon377 | [informalsystems/poseidon377](https://github.com/informalsystems/poseidon377) | `a0c3e643` |

Note: These SHAs are pinned via `Cargo.lock`, not via `rev =` in `Cargo.toml`. Builds are
reproducible as long as `Cargo.lock` is respected (i.e. no `cargo update`). The forks are not
identical to upstream — they contain modifications required by Cycles (e.g. `Fq`-based rseed
support in decaf377, rand feature gating).

## Detailed Changes

### 1. Dependency Redirects (`6df4a462e`)

Workspace `Cargo.toml` points `decaf377`, `decaf377-rdsa`, and `poseidon377` to Informal Systems
forks via git URLs. These forks carry Cycles-specific modifications — auditors should review the
fork diffs against their upstream counterparts.

### 2. Bech32 Prefix Rename (`f046b480c`, `bd687e260`)

All human-readable parts changed from `penumbra*` to `cycles*`:
- `penumbra` → `cycles` (addresses)
- `penumbravalid` → `cyclesvalid` (validator identity keys)
- `penumbragovern` → `cyclesgovern` (governance keys)
- `penumbrafullviewingkey` → `cyclesfullviewingkey`
- `penumbrawalletid` → `cycleswalletid`
- `penumbraspendkey` → `cyclesspendkey`
- `penumbracompat1` → `cyclescompat1`

Hardcoded test keys regenerated to match. Validator identity regex patterns in the asset
registry (`registry.rs`) and token types (`delegation_token.rs`, `unbonding_token.rs`) also
updated from `penumbravalid1` to `cyclesvalid1`.

### 3. Expose `tct::Hash` (`d8e3c8651`)

Re-exports `internal::hash::Hash` from the TCT crate's public API. Required by Cycles for
direct tree hash operations.

### 4. Rseed Type and RCM Domain Separator (`947e22b94`)

**Rseed type change:** `Rseed` inner type changed from `[u8; 32]` to `Fq`. This allows direct
use in arithmetic circuits without an intermediate conversion step. `From` impls provided for
`[u8; 32]`, `&[u8; 32]`, and `&[u8]` to maintain ergonomic construction from byte arrays.

**RCM derivation change:** Note commitment randomness (`derive_note_blinding`) changed from
PRF-expand with domain separator `Penumbra_DeriRcm` to a Poseidon hash with domain separator
`cycles.derive.rcm`. This is a **cryptographic domain separation** — notes created by Cycles
are not valid on Penumbra and vice versa.

**Files affected:** `rseed.rs`, `note.rs`, `backref.rs`, `note_manager.rs`, `note_record.rs`,
`storage.rs`, bench files, test vector generation.

### 5. FROST Upgrade (`ebf3f7ee8`)

Upgrade `frost-core` and `frost-rerandomized` from 0.7 to 2.2.0 (pinned to exact version in
`decaf377-frost/Cargo.toml`). Adapt `decaf377-frost` to the new API. Add proto definitions for
frost key shares. Cycles requires publicly exposed frost types and their serialization impls
for threshold signing, which were private in the 0.7 API.

### 6. Feature Gates (`a1fa2ee09`)

Optional feature flags added across crypto and core crates:
- `rand` — gates randomness-dependent code (`generate`, `dummy`, `new` constructors)
- `r1cs` — gates constraint system types (`NoteVar`, proof circuits)
- `ibc` — gates IBC-specific types (`Ics20Withdrawal`)
- `tendermint` — gates tendermint type conversions

This allows downstream consumers (CosmWasm contracts) to depend on these crates without pulling
in networking, randomness, or proving system dependencies that don't compile for WASM targets.

No behavioral changes when built with default features. When features are disabled
(e.g. `default-features = false` for WASM targets), gated code is excluded from compilation.

### 7. CI Adaptations (`bd687e260`)

- Exclude binary crates requiring LFS (`pd`, `pcli`, `pclientd`, `pmonitor`, `pindexer`)
- Exclude custody chain crates (`penumbra-sdk-custody`, `penumbra-sdk-wallet`, `penumbra-sdk-app-tests`, `elcuity`)
- Reduce WASM compatibility checks to Cycles-relevant crates only
- Disable Penumbra-specific CI jobs via `if: false` (bluesky, buf-push, containers, crates, docs-lint, notes, release, smoke)
- Active workflows: `rust.yml` (lint, check, test, WASM compat) and `buf-pull-request.yml` (protobuf)
- Ignore divergent `effect_hash_test_vectors` test (hashes differ due to rseed/RCM changes)
- Switch rust cache from BuildJet (`astriaorg/buildjet-rust-cache`) to `Swatinem/rust-cache@v2`
