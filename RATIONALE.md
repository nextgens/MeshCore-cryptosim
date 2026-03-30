Given:
- that air-time is sacred (payload size matters)
- that links are unreliable (packet loss, reordering, ...)
- that the availablitly of a peer cannot be taken for granted (extended downtimes, ...)
- that there is no shared state (even clocks act wonky and cannot even be relied upon to be monotonic)
- that there is limited cycles available
- that there is a finite amount of RAM we can allocate per peer on devices
- that devices are terrible at gathering entropy (speed, quality, ...)
- that we have ed25519 keys already provisionned on nodes
- that we want backward compatibility

This is my attempt at improving the status quo for direct messages (with other parts of crypto-code to follow if this is adopted).

This is a staggered ratcheted self-healing crypto protocol that uses ascon_xof for about everything (KDF, PRNG, stream-based encryption/authentication, ...).

It aims to provide:
- Replay protection (within an acceptable configurable window)
- Decryption even on very lossy links
- __Eventual__ forward secrecy (no clock and no guaranted availablity so no strict PFS interval): compromise of keys at a point in time will not enable decryption of previous messages
- Post compromise security: if keys are compromised __eventually__ the protocol will self-heal provided some messages reach the other side: you are guaranteed to converse with a single party over time (that party may be the attacker though)
- strong authentication (assuming the existing static long term keys are verified out of band : TOFU)
- a much faster and much safer PRNG (that persists entropy accross boots and feeds from remote's)
- a better level of security in general (precise security margin tbd: mostly depends on the size of tags)

This explicitly does not aim to be PQ-proof:
- we could use more rounds and larger keys easily, it just costs more cycles
- we cannot transmit ML-KEM-512 keys ~800bytes within a reasonable number of exchanges. MAX_PACKET_PAYLOAD is 184; if we sent things 2 bytes at the time (like I am proposting to do for the 32bytes ephemerals) it would take over 400 messages!
That being said, the proposal includes all the bricks required if we eventually wanted to (the type nible could specify another format for AAD with more FEC bytes where we could fit a larger key)

For reference, NIST currently says you need 112 bits of security, this would mean 14 bytes tags. Currently this is configured for 64bits (8 bytes tags). There are some protocols that go as low as 32bits (5G), we could too (provided we do keep 3XDH enabled!).

The wire format would look like this:
```text
[AD:6 bytes][TAG:8 bytes][ciphertext:variable]
```
with AD being:
```text
AD[0] = (type_flags << 4) | (epoch & 0x0f)
AD[1] = send_counter_hi
AD[2] = send_counter_lo
AD[3] = hint = ephemeral_candidate[0]
AD[4] = fec_0 (coded symbol high byte)
AD[5] = fec_1 (coded symbol low byte)
```

So the total wire-overhead per message of what is proposed is 6 (AAD)+ 8 (TAG) : 14 bytes on top of plaintext.
The existing protocol uses a block cipher (padding to AES blocks: 16 bytes) and 2 bytes MAC, this uses a stream cipher (with no padding). On average we "win" 8 bytes by not padding and we can re-use the existing wire format with the +2MAC field.

Therefore our "real" overhead over the existing protocol is just 4 bytes per message on average.

In terms of cycles, we're probably faster per message (except during ratcheting which happens once every ~18 messages in the same direction). We could go even faster by caching CK-R and CK-S at the cost of 64 bytes per peer or by shipping an ESP32 optimized ascon permutation (this just means merging two different parts of the reference implementation; we may do it later). In terms of RAM usage it should be reasonable (see PeerState: ~250bytes per peer, a bit more when there are actual exchanges). PeerState would need to be persisted to flash every time we ratchet, so would the PRNG seed.

The cool bits are:
0) use continuous staggered ratcheting: each packet has its own key, each ratchet has its own anti-replay window, we get PFS and PCS (so long that we have moved to different ratchets)
1) use AAD instead of a nonce/IV (what you need is a unique IV/AAD/plaintext per key)
2) stuff AAD with FEC data that can be used for eventual rekeying (no explicit rekey means less airtime)
3) provide strong authentication through 3XDH: we send an ephemeral (32 bytes) but no signature (so we save 64 bytes)
4) move from a block cipher to a stream cipher (we save ~8 bytes on average per message at the cost of disclosing plaintext length)
5) (ab)use the lack of padding verification in v1 packets to signal v2 compat in-band

What remains to be decided:
- Do we shave off an extra 1-2 bytes from the counter? If we do we are in dangerous territory (keystream reuse)
- Do we try to remove the hint (1 byte) and encode it in the nimble at the begining instead?
- Are we ok with the TAG size?
- Are we ok with the cycles per message? we could remove one layer of KDF if we had to
- Are we ok with cycles while ratcheting? If not we could do just DH instead of 3XDH provided we didn't go too low on the TAG size
- Are we ok with the complexity of the FEC scheme? GF^2 would probably do well enough if not better
- Are we ok with the FEC parameters? I haven't simulated the interleaving maybe we should before we ship it
- Are we ok with the counter being this big? If it wraps (with one way links) we get out of sync
- CXOF instead of XOF?

Points of attention:
- As designed epoch0 only happens once: if a peer restores its long-term key without PeerState it will not work. Making it work means opening the door to downgrade attacks.
