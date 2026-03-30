#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mesh-crypto.h"
#include "prng.h"

#include "lib/ed25519/ed_25519.h"

/* colors */
#define C_RESET "\x1b[0m"
#define C_MSG "\x1b[1;36m"
#define C_DIR "\x1b[1;32m"
#define C_STAT "\x1b[1;35m"
#define C_CKS "\x1b[1;33m"
#define C_CNT "\x1b[1;34m"
#define C_LEN "\x1b[1;37m"
#define C_PAYLOAD "\x1b[0;37m"

#define C_TE "\x1b[1;95m"
#define C_PCTR "\x1b[1;94m"
#define C_HINT "\x1b[1;93m"
#define C_FEC "\x1b[1;96m"
#define C_TAG "\x1b[1;91m"
#define C_CT "\x1b[1;92m"

static void bytes_to_hex(const uint8_t *in, size_t in_len, char *out, size_t out_len)
{
    static const char *hex = "0123456789abcdef";
    if (out_len == 0) return;
    if (out_len < (in_len * 2 + 1)) {
        out[0] = '\0';
        return;
    }
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2] = hex[(in[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[in_len * 2] = '\0';
}

static void generate_bootstrap_candidate(PeerState *s, const char *side)
{
    uint8_t old_hint = compute_hint(s->ephemeral_candidate);
    for (;;) {
        uint8_t seed[32];
        random_bytes(seed, sizeof(seed));
        ed25519_create_keypair(s->ephemeral_candidate, s->ephemeral_candidate_priv, seed);
        if (compute_hint(s->ephemeral_candidate) != old_hint) {
            break;
        }
    }

    printf("%s NEW_EPHEMERAL: %02x%02x%02x%02x\n", side,
           s->ephemeral_candidate[0], s->ephemeral_candidate[1],
           s->ephemeral_candidate[2], s->ephemeral_candidate[3]);
}

static void bootstrap(PeerState *A, PeerState *B)
{
    if (A->ephemeral_current[0] != 0 || B->ephemeral_current[0] != 0) {
        printf("Error: bootstrap should only be called on fresh states\n");
        return;
    }

    uint8_t seedA[32], seedB[32];
    random_bytes(seedA, sizeof(seedA));
    random_bytes(seedB, sizeof(seedB));
    ed25519_create_keypair(A->ephemeral_current, A->ephemeral_current_priv, seedA);
    ed25519_create_keypair(B->ephemeral_current, B->ephemeral_current_priv, seedB);
    A->peer_id = 0;
    B->peer_id = 1;

    memcpy(g_static_pub_A, A->ephemeral_current, 32);
    memcpy(g_static_priv_A, A->ephemeral_current_priv, 32);
    memcpy(g_static_pub_B, B->ephemeral_current, 32);
    memcpy(g_static_priv_B, B->ephemeral_current_priv, 32);
    g_static_keys_ready = true;

    printf("A static public key: %02x%02x%02x%02x\n", A->ephemeral_current[0], A->ephemeral_current[1], A->ephemeral_current[2], A->ephemeral_current[3]);
    printf("A static private key: %02x%02x%02x%02x\n", A->ephemeral_current_priv[0], A->ephemeral_current_priv[1], A->ephemeral_current_priv[2], A->ephemeral_current_priv[3]);
    printf("B static public key: %02x%02x%02x%02x\n", B->ephemeral_current[0], B->ephemeral_current[1], B->ephemeral_current[2], B->ephemeral_current[3]);
    printf("B static private key: %02x%02x%02x%02x\n", B->ephemeral_current_priv[0], B->ephemeral_current_priv[1], B->ephemeral_current_priv[2], B->ephemeral_current_priv[3]);

    uint8_t dh[32];
    ed25519_key_exchange(dh, A->ephemeral_current, B->ephemeral_current_priv);

    kdf(A->RK, dh, 32, NULL, 0, "BOOTSTRAP");
    memcpy(B->RK, A->RK, 32);

    generate_bootstrap_candidate(A, "[A]");
    generate_bootstrap_candidate(B, "[B]");
    printf("A candidate ephemeral private key: %02x%02x%02x%02x\n", A->ephemeral_candidate_priv[0], A->ephemeral_candidate_priv[1], A->ephemeral_candidate_priv[2], A->ephemeral_candidate_priv[3]);
    printf("B candidate ephemeral private key: %02x%02x%02x%02x\n", B->ephemeral_candidate_priv[0], B->ephemeral_candidate_priv[1], B->ephemeral_candidate_priv[2], B->ephemeral_candidate_priv[3]);

    printf("    [BOOTSTRAP] A hint=%02x (we send), remote_hint=NULL (B sends)\n", compute_hint(A->ephemeral_candidate));
    printf("    [BOOTSTRAP] B hint=%02x (we send), remote_hint=NULL (A sends)\n", compute_hint(B->ephemeral_candidate));
}

static void print_help(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -n NUM        Number of messages to send (default: 100)\n");
    printf("  -l PERCENT    Packet loss percentage (default: 0)\n");
    printf("  -s SEED       Random seed (default: 42)\n");
    printf("  -p PROBABILITY  Probability of order swap (0.0-1.0, default: 0.0)\n");
    printf("  -m MSG, --msg MSG  Message payload to encrypt (default: EHLO)\n");
    printf("  --3xdh 0|1     Enable/disable 3XDH ratchet input (default: 1)\n");
    printf("  --no-3xdh      Disable 3XDH ratchet input (legacy DH mode)\n");
    printf("  --fec-head NUM        Systematic symbols before interleaved recovery (default: %d)\n", FEC_DEFAULT_SYSTEMATIC_HEAD);
    printf("  --fec-mid-recovery NUM Recovery symbols inserted between systematic blocks (default: %d)\n", FEC_DEFAULT_INTERLEAVE_RECOVERY);
    printf("  -h            Show this help message\n");
}

static void print_packet_parts_colored(const uint8_t *pkt, int pkt_len)
{
    if (pkt_len < 6 + TAG_SIZE) {
        printf("%s<invalid>%s", C_PAYLOAD, C_RESET);
        return;
    }

    char te_hex[3];
    char ctr_hex[5];
    char hint_hex[3];
    char fec_hex[5];
    char tag_hex[TAG_SIZE * 2 + 1];
    char ct_hex[(MAX_PACKET_SIZE - 6 - TAG_SIZE) * 2 + 1];

    bytes_to_hex(pkt + 0, 1, te_hex, sizeof(te_hex));
    bytes_to_hex(pkt + 1, 2, ctr_hex, sizeof(ctr_hex));
    bytes_to_hex(pkt + 3, 1, hint_hex, sizeof(hint_hex));
    bytes_to_hex(pkt + 4, 2, fec_hex, sizeof(fec_hex));
    bytes_to_hex(pkt + 6, TAG_SIZE, tag_hex, sizeof(tag_hex));

    int ct_len = pkt_len - 6 - TAG_SIZE;
    bytes_to_hex(pkt + 6 + TAG_SIZE, (size_t)((ct_len > 0) ? ct_len : 0), ct_hex, sizeof(ct_hex));

    printf("%sTE=%s%s%s %sCTR=%s%s%s %sH=%s%s%s %sFEC=%s%s%s %sTAG=%s%s%s %sCT=%s%s%s",
           C_PAYLOAD, C_TE, te_hex, C_RESET,
           C_PAYLOAD, C_PCTR, ctr_hex, C_RESET,
           C_PAYLOAD, C_HINT, hint_hex, C_RESET,
           C_PAYLOAD, C_FEC, fec_hex, C_RESET,
           C_PAYLOAD, C_TAG, tag_hex, C_RESET,
           C_PAYLOAD, C_CT, ct_hex, C_RESET);
}

int main(int argc, char **argv)
{
    printf("=== MeshCore Ratchet Simulator ===\n\n");

    int num_messages = 100;
    int loss_percent = 0;
    uint32_t seed = 42;
    double order_swap_prob = 0;
    const char *message_payload = "EHLO";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            num_messages = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            loss_percent = atoi(argv[++i]);
            if (loss_percent < 0) loss_percent = 0;
            if (loss_percent > 100) loss_percent = 100;
        }
        else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            seed = (uint32_t)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            order_swap_prob = atof(argv[++i]);
            if (order_swap_prob < 0.0) order_swap_prob = 0.0;
            if (order_swap_prob > 1.0) order_swap_prob = 1.0;
        }
        else if ((strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--msg") == 0) && i + 1 < argc) {
            message_payload = argv[++i];
        }
        else if (strcmp(argv[i], "--3xdh") == 0 && i + 1 < argc) {
            g_use_3xdh = (atoi(argv[++i]) != 0);
        }
        else if (strcmp(argv[i], "--no-3xdh") == 0) {
            g_use_3xdh = false;
        }
        else if (strcmp(argv[i], "--fec-head") == 0 && i + 1 < argc) {
            int head = atoi(argv[++i]);
            if (head < 0) head = 0;
            if (head > FEC_SOURCE_SYMBOLS) head = FEC_SOURCE_SYMBOLS;
            g_fec_systematic_head = (uint8_t)head;
        }
        else if (strcmp(argv[i], "--fec-mid-recovery") == 0 && i + 1 < argc) {
            int rec = atoi(argv[++i]);
            if (rec < 0) rec = 0;
            if (rec > 255) rec = 255;
            g_fec_interleave_recovery = (uint8_t)rec;
        }
        else {
            printf("Unknown option: %s\n", argv[i]);
            print_help(argv[0]);
            return 1;
        }
    }

    if (message_payload[0] == '\0') {
        printf("Error: message payload must be non-empty\n");
        return 1;
    }
    size_t message_len = strlen(message_payload);
    if (message_len > (MAX_PACKET_SIZE - 6 - TAG_SIZE)) {
        printf("Error: message payload too long (%zu > %d)\n",
               message_len, MAX_PACKET_SIZE - 6 - TAG_SIZE);
        return 1;
    }

    printf("Parameters: %d messages, %d%% loss, seed=%u, order_swap_prob=%.2f, fec_head=%u, fec_mid_recovery=%u, 3xdh=%s, msg=\"%s\"\n\n",
           num_messages, loss_percent, seed, order_swap_prob,
           g_fec_systematic_head, g_fec_interleave_recovery,
           g_use_3xdh ? "on" : "off", message_payload);
    prng_seed(seed);

    PeerState A, B;
    memset(&A, 0, sizeof(A));
    memset(&B, 0, sizeof(B));
    FecRxState A_fec_rx, B_fec_rx;
    fec_rx_clear(&A_fec_rx);
    fec_rx_clear(&B_fec_rx);

    bootstrap(&A, &B);

    uint8_t pkt[MAX_PACKET_SIZE];
    uint8_t out[MAX_PACKET_SIZE];
    int msg_count = 0;
    int a_to_b_count = 0;
    int b_to_a_count = 0;
    int dropped_count = 0;
    int a_rx_fail = 0;
    int b_rx_fail = 0;

    bool a_sends = true;

    printf("%s%-5s%s %s%-5s%s %s%-5s%s %s%-8s%s %s%-8s%s %s%-7s%s %s%s%s\n",
           C_MSG, "Msg#", C_RESET,
           C_DIR, "Dir", C_RESET,
           C_STAT, "Stat", C_RESET,
           C_CKS, "CKs", C_RESET,
           C_CNT, "Counter", C_RESET,
           C_LEN, "CT-Len", C_RESET,
           C_PAYLOAD, "PayloadParts", C_RESET);

    for (int msg = 0; msg < num_messages; msg++) {
        if ((prng_next() % 100) < (unsigned)(order_swap_prob * 100)) {
            a_sends = !a_sends;
        }

        PeerState *sender = a_sends ? &A : &B;
        PeerState *receiver = a_sends ? &B : &A;
        FecRxState *sender_fec = a_sends ? &A_fec_rx : &B_fec_rx;
        FecRxState *receiver_fec = a_sends ? &B_fec_rx : &A_fec_rx;
        const char *receiver_side = a_sends ? "[B]" : "[A]";

        bool dropped = (prng_next() % 100) < (unsigned)loss_percent;
        if (dropped) {
            printf("%s%-5d%s %s%-5s%s %s%-5s%s\n",
                   C_MSG, msg, C_RESET,
                   C_DIR, a_sends ? "A->B" : "B->A", C_RESET,
                   C_STAT, "DROP", C_RESET);
            dropped_count++;
            continue;
        }

        const uint8_t *msg_data = (const uint8_t *)message_payload;
        int l = encrypt_packet(sender, sender_fec, pkt, msg_data, (int)message_len);
        if (l <= 0) {
            printf("%s%-5d%s %s%-5s%s %s%-5s%s\n",
                   C_MSG, msg, C_RESET,
                   C_DIR, a_sends ? "A->B" : "B->A", C_RESET,
                   C_STAT, "EENC", C_RESET);
            if (a_sends) {
                b_rx_fail++;
            } else {
                a_rx_fail++;
            }
            continue;
        }
        int r = decrypt_packet(receiver, receiver_fec, pkt, l, out, receiver_side);

        uint8_t CKs[32];
        compute_CKs(CKs, sender);
        int ct_len = l - 6;
        printf("%s%-5d%s %s%-5s%s %s%-5s%s %s%02x%02x%02x%02x%s %s%08u%s %s%-7d%s ",
               C_MSG, msg, C_RESET,
               C_DIR, a_sends ? "A->B" : "B->A", C_RESET,
               C_STAT, (r > 0) ? "OK" : "FAIL", C_RESET,
               C_CKS, CKs[0], CKs[1], CKs[2], CKs[3], C_RESET,
               C_CNT, sender->send_counter, C_RESET,
               C_LEN, ct_len, C_RESET);
        print_packet_parts_colored(pkt, l);
        printf("\n");

        if (r <= 0) {
            if (a_sends) {
                b_rx_fail++;
            } else {
                a_rx_fail++;
            }
        }

        if (a_sends) {
            a_to_b_count++;
        } else {
            b_to_a_count++;
        }
        msg_count++;

        a_sends = !a_sends;
    }

    printf("\n=== Summary ===\n");
    printf("Total messages sent: %d\n", msg_count);
    printf("A->B: %d\n", a_to_b_count);
    printf("B->A: %d\n", b_to_a_count);
    printf("Dropped: %d\n", dropped_count);
    printf("RX Failures - A: %d, B: %d\n", a_rx_fail, b_rx_fail);
    printf("Final epoch - A: %d, B: %d\n", A.epoch, B.epoch);
    printf("FEC progress - A has %d equations from B, B has %d equations from A\n",
           fec_rx_eq_count(&A_fec_rx), fec_rx_eq_count(&B_fec_rx));

    return 0;
}
