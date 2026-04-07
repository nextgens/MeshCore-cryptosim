#include <stdio.h>
#include <string.h>

#include "mesh-crypto.h"
#include "prng.h"

#include "lib/ascon/ascon.h"
#include "lib/ed25519/ed_25519.h"

bool g_use_3xdh = true;
uint8_t g_static_pub_A[32];
uint8_t g_static_priv_A[32];
uint8_t g_static_pub_B[32];
uint8_t g_static_priv_B[32];
bool g_static_keys_ready = false;

uint8_t epoch_next(uint8_t e)
{
    if (e == EPOCH_BOOTSTRAP) return EPOCH_MIN_ACTIVE;
    if (e >= EPOCH_MAX_ACTIVE) return EPOCH_MIN_ACTIVE;
    return (uint8_t)(e + 1);
}

uint8_t epoch_prev(uint8_t e)
{
    if (e == EPOCH_MIN_ACTIVE) return EPOCH_BOOTSTRAP;
    if (e == EPOCH_BOOTSTRAP) return EPOCH_BOOTSTRAP;
    if (e > EPOCH_MAX_ACTIVE) return EPOCH_MAX_ACTIVE;
    return (uint8_t)(e - 1);
}

static int consttime_compare(const uint8_t *a, const uint8_t *b, int len)
{
    const volatile uint8_t *va = a;
    const volatile uint8_t *vb = b;

    uint8_t diff = 0;
    for (int i = 0; i < len; i++)
        diff |= va[i] ^ vb[i];
    return diff == 0;
}

/**
 * Encrypt plaintext src of length src_len with key and ad (associated data) into
 *  dest. The output format is: [TAG (8 bytes)] [CIPHERTEXT (src_len bytes)]. Returns total length.
 * The tag is computed over the key, ad, and ciphertext to authenticate all of it.
 * 
 * The key must be uniformly random and unique for each encryption. The ad can be public
 * data that is not encrypted but should be authenticated (e.g. packet header fields).
 * 
 * The src can be empty (src_len=0) in which case only the tag is output, authenticating the key and ad.
 * 
 * This is not a streaming API, the whole plaintext must be available at once. The output buffer must have
 * enough space for TAG_SIZE + src_len bytes.
 * 
 * This is not a general-purpose API, it is designed for encrypting packets; if you want to encrypt something else
 * you want to change the domain strings.
 * 
 * The beauty of this is that we reuse the same sponge for both encryption and authentication.
 */
static int ascon_encrypt(const uint8_t* key, uint8_t* dest, const uint8_t* src,
                         int src_len, const uint8_t* ad, int ad_len)
{
    ascon_state_t ctx;
    ascon_inithash(&ctx);

    ascon_absorb(&ctx, (const uint8_t*)"MC-Ascon-v1", 11);
    ascon_absorb(&ctx, key, 32);
    ascon_absorb(&ctx, ad, ad_len);
    if (src_len > 0) {
        uint8_t keystream[src_len];
        ascon_squeeze(&ctx, keystream, src_len);

        uint8_t *ct = dest + TAG_SIZE;
        for (int i = 0; i < src_len; i++)
            ct[i] = src[i] ^ keystream[i];
        ascon_absorb(&ctx, (const uint8_t*)"MC-Ascon-v1-tag", 15);
        ascon_absorb(&ctx, ct, src_len);
    } else {
        ascon_absorb(&ctx, (const uint8_t*)"MC-Ascon-v1-tag", 15);
    }

    ascon_squeeze(&ctx, dest, TAG_SIZE);
    return TAG_SIZE + src_len;
}

static int ascon_decrypt(const uint8_t* key, uint8_t* dest, const uint8_t* src,
                         int src_len, const uint8_t* ad, int ad_len)
{
    if (src_len < TAG_SIZE) return 0;

    const uint8_t* tag = src;
    const uint8_t* ct = src + TAG_SIZE;
    int ct_len = src_len - TAG_SIZE;

    ascon_state_t ctx;
    ascon_inithash(&ctx);

    ascon_absorb(&ctx, (const uint8_t*)"MC-Ascon-v1", 11);
    ascon_absorb(&ctx, key, 32);
    ascon_absorb(&ctx, ad, ad_len);
    if (src_len > TAG_SIZE) {
        uint8_t keystream[ct_len];
        ascon_squeeze(&ctx, keystream, ct_len);

        for (int i = 0; i < ct_len; i++)
            dest[i] = ct[i] ^ keystream[i];

        ascon_absorb(&ctx, (const uint8_t*)"MC-Ascon-v1-tag", 15);
        ascon_absorb(&ctx, ct, ct_len);
    } else {
        ascon_absorb(&ctx, (const uint8_t*)"MC-Ascon-v1-tag", 15);
    }
    uint8_t tag2[TAG_SIZE];
    ascon_squeeze(&ctx, tag2, TAG_SIZE);

    if (!consttime_compare(tag, tag2, TAG_SIZE))
        return 0;

    return ct_len;
}

void kdf(uint8_t out[32], const uint8_t *in1, size_t in1len,
         const uint8_t *in2, size_t in2len, const char *domain)
{
    ascon_state_t ctx;
    ascon_inithash(&ctx);
    ascon_absorb(&ctx, (const uint8_t*)"MC-KDF-v1", 9);
    ascon_absorb(&ctx, (const uint8_t*)domain, strlen(domain));
    ascon_absorb(&ctx, (const uint8_t*)"MC-KDF-v1-d1", 12);
    ascon_absorb(&ctx, in1, in1len);
    ascon_absorb(&ctx, (const uint8_t*)"MC-KDF-v1-d2", 12);
    if (in2 && in2len) ascon_absorb(&ctx, in2, in2len);
    ascon_squeeze(&ctx, out, 32);
}

/**
 * why mix in ephemeral_priv? because it's unknown to the other side.
 * why rk? because it's not controlled by either party (does not just come from this prng itself)
 */
static void prng_mix_from_ratchet(const uint8_t rk[32], const uint8_t ephemeral_priv[32])
{
    uint8_t mix_key[32];
    kdf(mix_key, rk, 32, ephemeral_priv, 32, "PRNG-RATCHET-v1");
    prng_absorb(mix_key, sizeof(mix_key), "RATCHET");
}

uint8_t compute_hint(const uint8_t *pub)
{
    return pub[0];
}

static inline bool peer_has_flag(const PeerState *s, uint8_t flag)
{
    return (s->ratchet_flags & flag) != 0;
}

static inline void peer_set_flag(PeerState *s, uint8_t flag, bool value)
{
    if (value) {
        s->ratchet_flags |= flag;
    } else {
        s->ratchet_flags &= (uint8_t)~flag;
    }
}

static bool peer_static_keys(const PeerState *s,
                             const uint8_t **own_static_priv,
                             const uint8_t **peer_static_pub)
{
    if (!g_static_keys_ready) return false;
    if (s->peer_id == 0) {
        *own_static_priv = g_static_priv_A;
        *peer_static_pub = g_static_pub_B;
    } else {
        *own_static_priv = g_static_priv_B;
        *peer_static_pub = g_static_pub_A;
    }
    return true;
}

/**
 * Build the input key material for a ratchet step. This is the DH output plus
 * optionally the static-static and static-ephemeral DHs if 3XDH is enabled.
 * 
 * When 3XDH is enabled we get strong authentication for almost free.
 * 
 * TODO: we could save some cycles by doing the KDF in parts
 * TODO: rethink on whether we want 3XDH: we need authentication... it depends on
 *  the tag length we end up with
 */
static size_t ratchet_build_ikm(const PeerState *s, uint8_t dh_primary[32], uint8_t ikm[96])
{
    ed25519_key_exchange(dh_primary, s->remote_candidate_pending, s->ephemeral_candidate_priv);
    if (!g_use_3xdh) {
        memcpy(ikm, dh_primary, 32);
        return 32;
    }

    const uint8_t *own_static_priv = NULL;
    const uint8_t *peer_static_pub = NULL;
    if (!peer_static_keys(s, &own_static_priv, &peer_static_pub)) {
        memcpy(ikm, dh_primary, 32);
        return 32;
    }

    uint8_t dh2[32];
    uint8_t dh3[32];
    ed25519_key_exchange(dh2, peer_static_pub, s->ephemeral_candidate_priv);
    ed25519_key_exchange(dh3, s->remote_candidate_pending, own_static_priv);

    memcpy(ikm, dh_primary, 32);
    if (memcmp(dh2, dh3, 32) <= 0) {
        memcpy(ikm + 32, dh2, 32);
        memcpy(ikm + 64, dh3, 32);
    } else {
        memcpy(ikm + 32, dh3, 32);
        memcpy(ikm + 64, dh2, 32);
    }
    return 96;
}

static bool clone_peer_state(PeerState *dst, const PeerState *src)
{
    memcpy(dst, src, sizeof(PeerState));
    return true;
}

/** 
 * Just ensure we don't reuse the same hint to avoid edge cases in FEC reconstruction;
 * The other side needs to know that this is a new ephemeral
 */
static void generate_ephemeral_candidate(PeerState *s, const char *side)
{
    uint8_t old_hint = compute_hint(s->ephemeral_candidate);
    for (;;) {
        uint8_t seed[32];
        random_bytes(seed, 32);
        ed25519_create_keypair(s->ephemeral_candidate, s->ephemeral_candidate_priv, seed);
        if (compute_hint(s->ephemeral_candidate) != old_hint) {
            break;
        }
    }

    printf("%s NEW_EPHEMERAL: %02x%02x%02x%02x\n", side,
           s->ephemeral_candidate[0], s->ephemeral_candidate[1],
           s->ephemeral_candidate[2], s->ephemeral_candidate[3]);
}

static void ratchet_on_epoch_advance(PeerState *s, uint8_t their_hint, const char *side)
{
    if (!peer_has_flag(s, PEER_FLAG_REMOTE_CANDIDATE_READY)) {
        printf("%s [RX] Can't advance: missing decoded remote candidate\n", side);
        return;
    }

    uint8_t dh_result[32];
    uint8_t ikm[96];
    size_t ikm_len = ratchet_build_ikm(s, dh_result, ikm);
    /* save old CKr as CKr_prev before ratcheting so that we can decrypt out of order packets post-ratchet */
    uint8_t old_CKr[32];
    compute_CKr(old_CKr, s);
    memcpy(s->CKr_prev, old_CKr, 32);

    kdf(s->RK, s->RK, 32, ikm, ikm_len, (ikm_len == 96) ? "3XDH-RK" : "DH-RK");
    prng_mix_from_ratchet(s->RK, s->ephemeral_current_priv);

    printf("%s RATCHET-ADVANCE[epoch->%d] DH=%02x%02x RK=%02x%02x%02x%02x\n",
           side, epoch_next(s->epoch), dh_result[0], dh_result[1], s->RK[0], s->RK[1], s->RK[2], s->RK[3]);

    // promote our ephemeral candidate to current, update the hint, reset anti-replay counters
    memcpy(s->ephemeral_current_priv, s->ephemeral_candidate_priv, 32);
    memcpy(s->ephemeral_current, s->ephemeral_candidate, 32);
    s->remote_hint = compute_hint(s->remote_candidate_pending);

    generate_ephemeral_candidate(s, side);

    s->epoch = epoch_next(s->epoch);
    s->recv_counter_prev = s->recv_counter_curr;
    s->recv_counter_curr = 0;
    memset(s->remote_candidate_pending, 0, sizeof(s->remote_candidate_pending));

    peer_set_flag(s, PEER_FLAG_REMOTE_CANDIDATE_READY, false);
    peer_set_flag(s, PEER_FLAG_ACK_REMOTE_CANDIDATE, false);
    peer_set_flag(s, PEER_FLAG_SAW_PEER_ACK, false);

    (void)their_hint;
}

static void ratchet_on_fec_decode(PeerState *s, const char *side)
{
    if (!peer_has_flag(s, PEER_FLAG_REMOTE_CANDIDATE_READY)) return;

    uint8_t dh_result[32];
    uint8_t ikm[96];
    size_t ikm_len = ratchet_build_ikm(s, dh_result, ikm);

    /* save old CKr as CKr_prev before ratcheting */
    uint8_t old_CKr[32];
    compute_CKr(old_CKr, s);
    memcpy(s->CKr_prev, old_CKr, 32);

    kdf(s->RK, s->RK, 32, ikm, ikm_len, (ikm_len == 96) ? "3XDH-RK" : "DH-RK");
    prng_mix_from_ratchet(s->RK, s->ephemeral_current_priv);

    printf("%s RATCHET-FEC[epoch->%d] DH=%02x%02x RK=%02x%02x%02x%02x\n",
           side, epoch_next(s->epoch), dh_result[0], dh_result[1], s->RK[0], s->RK[1], s->RK[2], s->RK[3]);

    memcpy(s->ephemeral_current_priv, s->ephemeral_candidate_priv, 32);
    memcpy(s->ephemeral_current, s->ephemeral_candidate, 32);
    s->remote_hint = compute_hint(s->remote_candidate_pending);

    s->epoch = epoch_next(s->epoch);

    generate_ephemeral_candidate(s, side);

    memset(s->remote_candidate_pending, 0, sizeof(s->remote_candidate_pending));
    peer_set_flag(s, PEER_FLAG_REMOTE_CANDIDATE_READY, false);
    peer_set_flag(s, PEER_FLAG_ACK_REMOTE_CANDIDATE, false);
    peer_set_flag(s, PEER_FLAG_SAW_PEER_ACK, false);

    s->recv_counter_prev = s->recv_counter_curr;
    s->recv_counter_curr = 0;

    s->send_counter = 0;
}

int encrypt_packet(PeerState *s, FecRxState *fec_rx, uint8_t *out, const uint8_t *msg, int mlen)
{
    if (mlen < 1) return -1;

    if (peer_has_flag(s, PEER_FLAG_REMOTE_CANDIDATE_READY) &&
        peer_has_flag(s, PEER_FLAG_SAW_PEER_ACK)) {
        ratchet_on_fec_decode(s, "[TX]");
        fec_rx_clear(fec_rx);
    }

    uint8_t ad[6];
    uint8_t hint = compute_hint(s->ephemeral_candidate);
    uint16_t counter16 = (uint16_t)s->send_counter;
    uint8_t type = 0;
    if (peer_has_flag(s, PEER_FLAG_ACK_REMOTE_CANDIDATE)) {
        type |= TYPE_FLAG_ACK_REMOTE_CANDIDATE;
    }

    ad[0] = ((type & 0xf) << 4) | (s->epoch & 0xf);
    ad[1] = (counter16 >> 8) & 0xff;
    ad[2] = counter16 & 0xff;
    ad[3] = hint;

    uint8_t coeffs[FEC_SOURCE_SYMBOLS];
    fec_equation_coeffs(hint, (uint8_t)(s->epoch & 0x0f), counter16, coeffs);
    uint16_t fec_symbol = fec_encode_symbol(s->ephemeral_candidate, coeffs);
    ad[4] = (uint8_t)(fec_symbol >> 8);
    ad[5] = (uint8_t)(fec_symbol & 0xff);

    uint8_t key[32];
    uint8_t CKs[32];
    compute_CKs(CKs, s);
    /**
     * don't just use CKs as the key, mix in the packet-specific data to get a unique key per packet and ensure
      that even if the same plaintext is sent twice we get different ciphertexts (and thus different tags) to
      avoid leaking information and to make sure that replayed packets will fail authentication
    */
    kdf(key, CKs, 32, ad, 6, "MC-Packet-v1");
    int l = ascon_encrypt(key, out + 6, msg, mlen, ad, 6);

    memcpy(out, ad, 6);

    s->send_counter++;

    return 6 + l;
}

int decrypt_packet(PeerState *s, FecRxState *fec_rx, uint8_t *pkt, int len, uint8_t *out, const char *side)
{
    if (len < 6 + TAG_SIZE) return -1;

    uint8_t epoch = pkt[0] & 0xf;
    uint8_t type = (pkt[0] >> 4) & 0xf;
    uint16_t send_counter = (uint16_t)(((uint16_t)pkt[1] << 8) | (uint16_t)pkt[2]);
    uint8_t hint = pkt[3];
    uint16_t fec_symbol = ((uint16_t)pkt[4] << 8) | (uint16_t)pkt[5];

    uint8_t key[32];
    PeerState trial_state;
    PeerState *work_state = s;
    bool used_epoch_advance = false;

    if (epoch == EPOCH_RESERVED_MAX) {
        printf("  [RX] Reserved epoch value %d rejected\n", epoch);
        return -3;
    }

    if (epoch == epoch_next(s->epoch)) {
        if (!peer_has_flag(s, PEER_FLAG_REMOTE_CANDIDATE_READY)) {
            printf("  [RX] Epoch+1 seen but candidate not decoded yet\n");
            return -3;
        }
        if (!clone_peer_state(&trial_state, s)) {
            printf("  [RX] Cannot allocate trial ratchet state\n");
            return -3;
        }
        ratchet_on_epoch_advance(&trial_state, hint, side);
        work_state = &trial_state;
        used_epoch_advance = true;
        compute_CKr(key, work_state);
    }
    else if (epoch == s->epoch) {
        compute_CKr(key, s);
    }
    else if (epoch == epoch_prev(s->epoch)) {
        compute_CKr_prev(key, s);
    }
    else {
        printf("  [RX] Packet epoch %d doesn't match (we're in %d)\n", epoch, s->epoch);
        return -3;
    }

    uint16_t *recv_counter = (epoch == work_state->epoch) ? &work_state->recv_counter_curr : &work_state->recv_counter_prev;
    int32_t counter_diff = (int32_t)(send_counter - *recv_counter);
    if (counter_diff < -(int32_t)REPLAY_TOLERANCE) {
        printf("  [RX] Packet counter %u is too old (last seen %u in epoch %d)\n",
               send_counter, *recv_counter, epoch);
        return -3;
    }
    if (counter_diff > 0) {
        *recv_counter = send_counter;
    }

    kdf(key, key, 32, pkt, 6, "MC-Packet-v1");
    int r = ascon_decrypt(key, out, pkt + 6, len - 6, pkt, 6);

    if (r <= 0) return -3;

    if (used_epoch_advance) {
        memcpy(s, &trial_state, sizeof(PeerState));
        s->send_counter = 0;
        fec_rx_clear(fec_rx);
    }

    if (!used_epoch_advance && epoch == s->epoch && (type & TYPE_FLAG_ACK_REMOTE_CANDIDATE)) {
        peer_set_flag(s, PEER_FLAG_SAW_PEER_ACK, true);
    }

    if (epoch == s->epoch && !peer_has_flag(s, PEER_FLAG_REMOTE_CANDIDATE_READY)) {
        fec_rx_ensure_round(fec_rx, hint, epoch, true);
        fec_rx_add_symbol(fec_rx, send_counter, fec_symbol);

        if (fec_rx_eq_count(fec_rx) >= FEC_SOURCE_SYMBOLS) {
            uint8_t decoded_candidate[32];
            if (fec_rx_try_decode_candidate(fec_rx, decoded_candidate)) {
                printf("%s FEC_COMPLETE hint=%02x (decoded with %d equations)\n",
                       side, hint, fec_rx_eq_count(fec_rx));
                if (compute_hint(decoded_candidate) == s->remote_hint) {
                    printf("%s FEC_DUPLICATE hint=%02x (already current, no ratchet)\n", side, hint);
                } else {
                    memcpy(s->remote_candidate_pending, decoded_candidate, sizeof(s->remote_candidate_pending));
                    peer_set_flag(s, PEER_FLAG_REMOTE_CANDIDATE_READY, true);
                    peer_set_flag(s, PEER_FLAG_ACK_REMOTE_CANDIDATE, true);
                }
                fec_rx_clear(fec_rx);
            }
        }
    }

    return r;
}
