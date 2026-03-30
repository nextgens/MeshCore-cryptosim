#ifndef MESH_CRYPTO_H
#define MESH_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fec.h"

/** these can be changed */
#define MAX_PACKET_SIZE 187
#define TAG_SIZE 8
#define REPLAY_TOLERANCE 16

/** that shouldn't be touched */
#define EPOCH_BOOTSTRAP 0x00
#define EPOCH_RESERVED_MAX 0x0f
#define EPOCH_MIN_ACTIVE 0x01
#define EPOCH_MAX_ACTIVE 0x0e
#define TYPE_FLAG_ACK_REMOTE_CANDIDATE 0x01
#define EPHEMERAL_SIZE 32
#define PEER_FLAG_REMOTE_CANDIDATE_READY 0x01
#define PEER_FLAG_ACK_REMOTE_CANDIDATE   0x02
#define PEER_FLAG_SAW_PEER_ACK           0x04

typedef struct {
    uint8_t RK[32]; /* Ratchet key - CKs/CKr derived on-demand from it to save RAM */
    uint8_t CKr_prev[32]; /* Previous receiver chain key */

    uint8_t ephemeral_current_priv[32];
    uint8_t ephemeral_current[32];
    uint8_t ephemeral_candidate_priv[32];
    uint8_t ephemeral_candidate[32];

    uint8_t epoch; /* 0x00=bootstrap, 0x01-0x0e=active, 0x0f=reserved */
    uint8_t remote_hint; /* Hint of current remote ephemeral (for dup detection) */
    uint8_t remote_candidate_pending[32];

    /* used for anti-replay */
    uint16_t send_counter;
    uint16_t recv_counter_curr;
    uint16_t recv_counter_prev;

    /* used by the state machine */
    uint8_t ratchet_flags;

    uint8_t peer_id; /* 0=A, 1=B just for the sim, the real impl does not need it */
} PeerState;

/* since we reserve some we need wrappers */
uint8_t epoch_next(uint8_t e);
uint8_t epoch_prev(uint8_t e);

/* globals in the real implementation these are available elsewhere in the real impl */
extern bool g_use_3xdh;
extern uint8_t g_static_pub_A[32];
extern uint8_t g_static_priv_A[32];
extern uint8_t g_static_pub_B[32];
extern uint8_t g_static_priv_B[32];
extern bool g_static_keys_ready;

/* Key derivation function : if you need a new key you derive it using this*/
void kdf(uint8_t out[32], const uint8_t *in1, size_t in1len,
         const uint8_t *in2, size_t in2len, const char *domain);

/* not something that should be called directly */
uint8_t compute_hint(const uint8_t *pub);

/* helpers to derive chain keys on-demand from RK */
static inline void compute_CKs(uint8_t out[32], const PeerState *s) {
    kdf(out, s->RK, 32, NULL, 0, "CKs-first");
}

static inline void compute_CKr(uint8_t out[32], const PeerState *s) {
    kdf(out, s->RK, 32, NULL, 0, "CKs-first");
}

/* return previous receiver chain key directly */
static inline void compute_CKr_prev(uint8_t out[32], const PeerState *s) {
    memcpy(out, s->CKr_prev, 32);
}

/* main API */
int encrypt_packet(PeerState *s, FecRxState *fec_rx, uint8_t *out,
                   const uint8_t *msg, int mlen);
int decrypt_packet(PeerState *s, FecRxState *fec_rx, uint8_t *pkt, int len,
                   uint8_t *out, const char *side);

#endif
