# MeshCore Cryptographic Protocol Specification

**Version:** 1.0
**Purpose:** Minimal specification for cryptographic review

---

## 1. Primitives

### 1.1 Core Cryptographic Primitives

| Primitive | Domain | Output | Notes |
|-----------|--------|--------|-------|
| `ASCON-128` | Sponge | Variable | KDF, PRNG, AEAD |
| `Ed25519` | DH | 32 bytes | Ephemeral key exchange |
| `GF(2^256)` | Field | - | AES polynomial `0x11b`, FEC |

### 1.2 Derived Constructions

**KDF (ASCON sponge):**
```
KDF(secret, info, label) -> 32 bytes
```
- Absorb: `label || 0x00 || secret || 0x01 || info`
- Squeeze: 32 bytes

**AEAD (ASCON-based):**
```
Encrypt(key, nonce, plaintext, ad) -> ciphertext || tag[8]
Decrypt(key, nonce, ciphertext, ad, tag) -> plaintext || auth_bit
```
- `key`: 32 bytes (chain key)
- `nonce`: 16 bytes
- `tag`: 8 bytes (truncated)

**PRNG (ASCON sponge):**
```
prng_seed(seed)         // Initialize sponge state
prng_next_byte()        // Squeeze 1 byte
prng_next()             // Squeeze 4 bytes
prng_absorb(data, label) // Mix external entropy
```

---

## 2. Protocol State

### 2.1 Long-term Key

```
RK: 32 bytes  // Ratchet key, persists across epochs
```

### 2.2 Per-Epoch State (per peer)

```
// Chain keys (derived on-demand from RK)
CKs: 32 bytes  // Sender chain key (encrypts outbound)
CKr: 32 bytes  // Receiver chain key (decrypts inbound)
CKr_prev: 32 bytes  // Previous receiver chain key (epoch-1 tolerance)

// Ephemeral keypairs (Ed25519)
ephemeral_current_priv/pub: 32/32 bytes  // Active epoch
ephemeral_candidate_priv/pub: 32/32 bytes  // Next epoch, FEC-encoded

// Peer's known ephemerals
remote_ephemeral: 32 bytes  // Peer's current public key
remote_candidate_pending: 32 bytes  // Peer's decoded candidate (optional)

// Counters
epoch: 4 bits  // {0x00=bootstrap, 0x01..0x0e=active, 0x0f=reserved}
send_counter: 16 bits  // Packet counter (wrapped in AD)
recv_counter: 16 bits  // Last accepted packet counter
```

### 2.3 Ratchet Flags

```
REMOTE_CANDIDATE_READY: 1 bit  // Decoded peer's candidate for current epoch
ACK_REMOTE_CANDIDATE: 1 bit  // Signal in outbound AD[0] high nibble
SAW_PEER_ACK: 1 bit  // Saw authenticated ACK from peer in current epoch
```

### 2.4 FEC Receive State (sidecar)

```
active_hint: 1 byte  // Expected ephemeral_pub[0]
active_epoch: 4 bits // Expected epoch
equations[64]: (send_counter, fec_symbol[2])  // Collected systematic + recovery
```

---

## 3. Wire Format

### 3.1 Packet Structure

```
+--------+--------+--------------------+
|   AD   |  TAG   |   ciphertext       |
| 6 bytes| 8 bytes| variable           |
+--------+--------+--------------------+
```

### 3.2 AD Field (6 bytes)

```
AD[0] = (type_flags << 4) | (epoch & 0x0f)
  - bit 0 of type_flags: ACK_REMOTE_CANDIDATE
  - bits 1-3: reserved
  - low nibble: epoch (0x01..0x0e)

AD[1-2] = send_counter (big-endian, 16 bits)
AD[3]   = hint = ephemeral_candidate_pub[0]
AD[4-5] = fec_symbol (2 bytes, coded symbol for candidate recovery)
```

### 3.3 Nonce Construction

```
nonce = send_counter (2 bytes) || epoch (1 byte) || peer_id (13 bytes)
```

---

## 4. State Transitions

### 4.1 Bootstrap (Initial State)

```
Input: A_static_priv/pub, B_static_priv/pub

1. Set ephemeral_current = static keypair
2. Set remote_ephemeral = peer's static public key
3. DH = Ed25519_DH(remote_ephemeral, ephemeral_current_priv)
4. RK = KDF(NULL, DH, "BOOTSTRAP")
5. CKs = KDF(RK, NULL, "CKs-direction")  // Direction-specific label
6. CKr = KDF(RK, NULL, "CKr-direction")
7. Generate ephemeral_candidate (retry until hint differs from previous)
8. epoch = 0x01, send_counter = 0, recv_counter = 0
```

### 4.2 First-Mover Ratchet (TX Path, After FEC Decode + ACK Gate)

**Preconditions:**
- `REMOTE_CANDIDATE_READY` is true (decoded peer's candidate)
- `SAW_PEER_ACK` is true (authenticated ACK observed)
- FEC decode of peer's candidate succeeded

**Steps:**
```
1. CKr_prev = CKr

2. // Ratchet IKM (3XDH mode, default)
   dh1 = Ed25519_DH(remote_candidate_pending, ephemeral_candidate_priv)
   dh2 = Ed25519_DH(peer_static_pub, ephemeral_candidate_priv)
   dh3 = Ed25519_DH(remote_candidate_pending, local_static_priv)
   IKM = dh1 || sort_lex(dh2, dh3)  // 64 bytes

   // Or plain DH mode (disabled by default):
   // IKM = Ed25519_DH(remote_candidate_pending, ephemeral_candidate_priv)

3. RK' = KDF(RK, IKM, "3XDH-RK" or "DH-RK")

4. CKs = KDF(RK', NULL, "CKs-first")
5. CKr = KDF(RK', NULL, "CKr-second")

6. ephemeral_current = ephemeral_candidate
7. remote_ephemeral = remote_candidate_pending
8. Generate fresh ephemeral_candidate (retry until hint differs)
9. epoch = epoch_next(epoch)  // wraps 0x0e -> 0x01
10. send_counter = 0, recv_counter = 0
11. Clear flags, FEC state
```

### 4.3 Second-Mover Ratchet (RX Path, On Authenticated Epoch+1)

**Preconditions:**
- Received packet with `epoch == local_epoch + 1`
- `REMOTE_CANDIDATE_READY` is true

**Steps:**
```
1. // Build ratchet IKM (same as first-mover)
   dh1 = Ed25519_DH(remote_candidate_pending, ephemeral_candidate_priv)
   dh2 = Ed25519_DH(peer_static_pub, ephemeral_candidate_priv)
   dh3 = Ed25519_DH(remote_candidate_pending, local_static_priv)
   IKM = dh1 || sort_lex(dh2, dh3)

2. RK' = KDF(RK, IKM, "3XDH-RK")

3. CKr_prev = CKr
4. CKs = KDF(RK', NULL, "CKr-second")  // Note: swapped!
5. CKr = KDF(RK', NULL, "CKs-first")   // Second mover uses CKs-first for rx

6. ephemeral_current = ephemeral_candidate
7. remote_ephemeral = remote_candidate_pending
8. Generate fresh ephemeral_candidate
9. epoch = epoch_next(epoch)
10. rotate recv counters, clear FEC state
```

### 4.4 FEC Encoding (Per Packet)

```
Input: ephemeral_candidate_pub (32 bytes)

1. Split into 16 symbols of 2 bytes each
2. Derive mask from (hint, epoch, send_counter)
3. If send_counter < fec_head: systematic row
4. Else if send_counter < fec_head + fec_mid_recovery: recovery row
5. Else: alternating systematic/recovery
6. Output: AD[4-5] = fec_symbol
```

### 4.5 FEC Decoding (Gather Phase)

```
Input: (hint, epoch, send_counter, fec_symbol) from authenticated packet

1. Verify hint matches expected for (peer, epoch)
2. Add equation to equations[] cache
3. If len(equations) >= 16:
   - Gaussian elimination over GF(2^8)
   - On success: remote_candidate_pending = decoded[0:32]
   - Set REMOTE_CANDIDATE_READY = true
```

---

## 5. Decryption and Authentication

### 5.1 Key Selection (RX Path)

```
Given received packet with AD epoch = E:

if E == local_epoch + 1:
    if REMOTE_CANDIDATE_READY:
        use tentative CKr (second-mover path, Section 4.3)
        commit state only if tag verifies
    else:
        REJECT: "Epoch+1 seen but candidate not decoded"

elif E == local_epoch:
    use CKr

elif E == local_epoch - 1:
    use CKr_prev
    if recv_counter < last_accepted - REPLAY_TOLERANCE: REJECT

else:
    REJECT: "Epoch out of window"
```

### 5.2 AEAD Decryption

```
1. Extract AD[0:6], TAG[8], ciphertext
2. Select key = CKr (or CKr_prev, or tentative) per Section 5.1
3. Construct nonce from AD[1:3] (send_counter), AD[0]&0x0f (epoch)
4. auth = Decrypt(key, nonce, ciphertext, AD, TAG)
5. If auth fails: REJECT, do not update state
6. If auth succeeds: accept plaintext, update recv_counter
```

---

## 6. Invariants

### 6.1 State Invariants

1. **Epoch bounds:** `epoch ∈ {0x00} ∪ [0x01, 0x0e]` at all times
2. **Candidate uniqueness:** `ephemeral_candidate_pub[0] ≠ previous_candidate_pub[0]`
3. **Chain key secrecy:** `CKs`, `CKr` are never transmitted; only `RK` persists
4. **FEC sidecar isolation:** FEC state is not part of `PeerState`; cleared on epoch transition

### 6.2 Protocol Invariants

5. **ACK gating:** First-mover ratchet requires both `REMOTE_CANDIDATE_READY ∧ SAW_PEER_ACK`
6. **Authenticated state transition:** No ratchet state committed before tag verification
7. **No buffering:** Packets rejected before candidate decode are dropped (no queue)
8. **Counter reset:** `send_counter` and `recv_counter` reset to 0 on each epoch transition
9. **Directional symmetry:** Both peers compute identical IKM (lexicographic DH sort)

### 6.3 Security Invariants

10. **Forward secrecy:** Compromise of `RK` does not reveal past epoch keys
11. **Post-compromise security:** Each epoch ratchets with fresh DH material
12. **Authenticity:** 3XDH includes static keys; IKM binds to both endpoints
13. **PRNG healing:** `prng_absorb()` mixes ratchet output; peer entropy propagates

---

## 7. Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `TAG_LEN` | 8 bytes | AEAD authentication tag |
| `REPLAY_TOLERANCE` | 16 | Packets accepted from epoch-1 |
| `FEC_SOURCE_SYMBOLS` | 16 | 32-byte candidate → 16 × 2-byte symbols |
| `FEC_MAX_EQUATIONS` | 64 | Max collected equations per round |
| `FEC_HEAD` | 10 | Systematic rows before recovery |
| `FEC_MID_RECOVERY` | 4 | Recovery rows in middle band |

---

## 8. Open Questions for Review

1. **Truncated tag (8 bytes):** Security margin against birthday attacks?
2. **PRNG self-feeding:** Is absorbing ratchet output into ASCON sponge safe-ish?
3. **FEC systematic interleaving:** Optimal for expected loss patterns?
4. **GF(2^8) vs GF(2^16):** Is 2-byte symbol size optimal? What about parameters?
5. **3XDH authentication:** Is static key binding necessary with AEAD already present? What kind of transcript would make sense to be mixed in?
6. **Epoch wrap (0x0e → 0x01):** Any edge cases with late packets?
