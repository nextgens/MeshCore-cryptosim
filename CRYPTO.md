# MeshCore Cryptography Protocol proposal

This document describes the behavior implemented across:
- `simulator.cpp` (CLI + simulation loop)
- `mesh-crypto.cpp` (ratchet/packet crypto/protocol state machine)
- `fec.cpp` (fountain FEC over GF(256))
- `prng.cpp` (ASCON sponge / PRNG helpers)

## Overview

The simulator uses:
- `ed25519_key_exchange()` for DH material; that implementation should be fixed before going live (MATTA-2026-001 and #1632)
- ASCON-based KDF/encrypt/decrypt helpers
- ASCON sponge PRNG (`squeeze` directly for output bytes, `absorb` for ratchet-mix input)
- 6-byte authenticated header (`AD`)
- Fountain FEC over 32-byte candidate ephemerals (16 x 2-byte symbols) in GF(256)
- ACK-gated ratchet transitions (no packet buffering whatsoever)
- Optional 3XDH-style ratchet input (enabled by default)

## Wire Format

Packet layout:

```text
[AD:6 bytes][TAG:8 bytes][ciphertext:variable]
```

We could send the TAG last.

`AD` bytes:

```text
AD[0] = (type_flags << 4) | (epoch & 0x0f)
AD[1] = send_counter_hi
AD[2] = send_counter_lo
AD[3] = hint = ephemeral_candidate[0]
AD[4] = fec_0 (coded symbol high byte)
AD[5] = fec_1 (coded symbol low byte)
```

Type/flags (high nibble):
- bit0: `ACK_REMOTE_CANDIDATE`

In the future this could be used to have different FEC patterns, different TAG lengths, ... or notifying that we send larger PQC ephemerals

FEC wire size is exactly 2 bytes (`fec_0`, `fec_1`).

## Epoch Semantics

Wire epoch values:
- `0x00`: bootstrap only
- `0x0f`: reserved/rejected ; we could reserve more if that's useful but I feel like the flags nible is enough
- active: `0x01..0x0e`

Wrap:
- `epoch_next(0x0e) = 0x01`
- `epoch_prev(0x01) = 0x00` (late bootstrap tolerance)

## Peer State (relevant)

- `RK` (Ratchet key - stored, derives `CKs`/`CKr` on-demand)
- `CKr_prev` (stored directly, 32 bytes)
- `ephemeral_current_priv/pub`
- `ephemeral_candidate_priv/pub`
- `remote_ephemeral`
- `remote_candidate_pending` (decoded candidate waiting for ratchet)
- `epoch`, `send/recv counters`
- packed ratchet flags byte:
  - `REMOTE_CANDIDATE_READY`
  - `ACK_REMOTE_CANDIDATE`
  - `SAW_PEER_ACK`

Candidate generation rule:
- when generating a fresh candidate ephemeral, the implementation retries until `hint = candidate_pub[0]` differs from the previous candidate hint, removing same-hint round ambiguity.

FEC receive state is kept in a sidecar context (`FecRxState`), not inside `PeerState`:
that way we save memory overall (allocate the FEC decoder when actually used)
- active round `(hint, epoch)`
- collected `(send_counter, fec_symbol)` equations
I am not hung up on this, we could put it elsewhere.

Bootstrap static keys are copied into crypto globals from `simulator.cpp` bootstrap:
- `A_static_pub/priv`
- `B_static_pub/priv`
In the live implementation that will be LocalIdentity().prv_key

## Fountain FEC

Source block: 32-byte candidate ephemeral => 16 symbols of 2 bytes.

Constants:
- `FEC_SOURCE_SYMBOLS = 16`
- `FEC_MAX_EQUATIONS = 64`

Equation input:
- `(hint, epoch_low_nibble, send_counter)`

Mask schedule:
- counters `[0, fec_head)`: systematic rows
- counters `[fec_head, fec_head + fec_mid_recovery)`: recovery rows
- then remaining systematic rows
- then recovery rows for all later counters

Runtime knobs:
- `--fec-head NUM` (default `10`)
- `--fec-mid-recovery NUM` (default `4`)

Decode policy:
- only attempt solve when at least 16 equations are collected
- solve via Gaussian elimination over GF(256) (AES polynomial `0x11b`)
- collection and decode happen only after packet authentication succeeds
- decoder coefficients are reconstructed from `(hint, epoch, send_counter)` when decode is attempted
- sidecar equation cache is cleared after successful decode or round switch

I have not done sims; it may be better to do GF^2 or to further tweak the systematic interleaving

## ACK-Gated Ratchet

Goal: avoid unauthenticated pre-TAG ratchet changes and avoid buffering.

Rule:
- A node sets `ACK_REMOTE_CANDIDATE` in outgoing packets after it decoded peer candidate for current epoch.
- First-mover ratchet is performed only when both are true:
  1. `PEER_FLAG_REMOTE_CANDIDATE_READY` is set
  2. `PEER_FLAG_SAW_PEER_ACK` is set (authenticated ACK seen from peer)
- `PEER_FLAG_SAW_PEER_ACK` is set only from authenticated packets in the local current epoch (not from `epoch+1` transition packets).

So epoch+1 sending is gated by authenticated peer confirmation.

## Ratchet DH / 3XDH

Both first and second mover use the same ratchet input construction.

If `3XDH` mode is disabled:

```text
dh1 = key_exchange(remote_candidate_pub, local_candidate_priv)
RK' = KDF(RK, RK_old, dh1, "DH-RK")
```

If `3XDH` mode is enabled (default):

```text
dh1 = key_exchange(remote_candidate_pub, local_candidate_priv)   // E_local x E_remote
dh2 = key_exchange(remote_static_pub,   local_candidate_priv)    // E_local x S_remote
dh3 = key_exchange(remote_candidate_pub, local_static_priv)       // S_local x E_remote
IKM = dh1 || sort_lexicographically(dh2, dh3)
RK' = KDF(RK, RK_old, IKM, "3XDH-RK")
```

Lexicographic ordering of `(dh2, dh3)` keeps both sides deterministic.

Why 3XDH? Because we need authentication! We could rely solely on what is provided by the tag...
 but if we err on the side of airtime-conservative (short tag, small security level) we will want
 to spend the extra cycles to get real, crypto-secure authentication.

## Ratchet Paths

### First mover (`ratchet_on_fec_decode`, called on TX path after ACK gate)

Steps:
1. Save `CKr_prev = CKr` (current receiver chain key before ratchet)
2. Build ratchet IKM (plain DH or 3XDH, depending on mode)
3. `RK` update
4. `CKs = KDF(RK, NULL, "CKs-first")`
5. `CKr = KDF(RK, NULL, "CKr-second")`
6. promote local candidate -> current
7. set `remote_ephemeral = decoded_remote_candidate`
8. generate fresh candidate
9. `epoch = epoch_next(epoch)`
10. reset counters/FEC state/ACK flags

### Second mover (`ratchet_on_epoch_advance`, on authenticated epoch+1)

Precondition:
- `PEER_FLAG_REMOTE_CANDIDATE_READY` is set

Steps:
1. Build ratchet IKM using same construction as first mover
2. `RK` update
3. `CKr_prev = CKr`
4. `CKs = KDF(RK, NULL, "CKr-second")`
5. `CKr = KDF(RK, NULL, "CKs-first")`
6. promote local candidate -> current
7. set `remote_ephemeral = decoded_remote_candidate`
8. generate fresh candidate
9. `epoch = epoch_next(epoch)`
10. rotate recv counters; reset FEC state/ACK flags

## Decryption Epoch Handling

For authenticated decryption key selection:
- `epoch == epoch_next(local_epoch)`: second-mover path (requires decoded candidate)
- `epoch == local_epoch`: use `CKr`
- `epoch == epoch_prev(local_epoch)`: use `CKr_prev`
- else reject

Replay tolerance is a constant define:
- `REPLAY_TOLERANCE = 16`

If `epoch+1` arrives before decoded candidate is ready:
- packet is rejected (`Epoch+1 seen but candidate not decoded yet`)

For `epoch+1` packets:
- receiver derives a tentative second-mover state
- decrypt/authenticate with tentative `CKr`
- commit the ratchet state only if authentication succeeds
- on authentication failure, state remains unchanged (no buffering required)

## Security/Integrity Notes

- No ratchet commit from unauthenticated data (including `epoch+1` path).
- No FEC-triggered state advance before TAG verification in normal path.
- ACK signal is authenticated because it is inside AD and covered by packet key/tag.
- Each ratchet derives extra mix material and absorbs it into the ASCON PRNG state.
 That's definitely guilty of the cardinal sin of feeding your PRNG with its own output
 but IMHO this is safe (since there is DH and the other side's ephemeral in the mix).
  Overall I believe that this improves matters: it will eventually save us even if our
   own local RNG is faulty as we "gain" entropy from peers in a way they can't directly
    influence (it runs through DH and a KDF). To ensure the other side doesn't know what
    we have fed we also mix-in our ephemeral secret.

## Bootstrap

At startup:
1. static keys generated and used as initial `ephemeral_current`
2. bootstrap DH -> `RK` with domain `"BOOTSTRAP"`
3. directional chains initialized (`CK-A`/`CK-B`)
4. first candidates generated
5. `remote_ephemeral` initialized to peer static

We can't do much better if we want backward compat.

The real implementation would use the LSB of existing padding (that is not being checked!)
 to signal v2 compatibility and get thing rolling, no need to advertise capability in adverts.
