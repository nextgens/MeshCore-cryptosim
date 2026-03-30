#include <stdio.h>
#include <string.h>

#include "fec.h"

uint8_t g_fec_systematic_head = FEC_DEFAULT_SYSTEMATIC_HEAD;
uint8_t g_fec_interleave_recovery = FEC_DEFAULT_INTERLEAVE_RECOVERY;

/* Simple pseudo-random number generator : no need for ascon here. */
static uint32_t fec_rng_next(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/* AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11b). */
static uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1u) p ^= a;
        uint8_t hi = (uint8_t)(a & 0x80u);
        a <<= 1;
        if (hi) a ^= 0x1bu;
        b >>= 1;
    }
    return p;
}

static uint8_t gf256_pow(uint8_t a, uint8_t e)
{
    uint8_t out = 1;
    while (e) {
        if (e & 1u) out = gf256_mul(out, a);
        a = gf256_mul(a, a);
        e >>= 1;
    }
    return out;
}

static uint8_t gf256_inv(uint8_t a)
{
    if (a == 0) return 0;
    return gf256_pow(a, 254);
}

void fec_equation_coeffs(uint8_t hint, uint8_t epoch, uint16_t send_counter,
                         uint8_t coeffs[FEC_SOURCE_SYMBOLS])
{
    memset(coeffs, 0, FEC_SOURCE_SYMBOLS);

    uint8_t head = g_fec_systematic_head;
    if (head > FEC_SOURCE_SYMBOLS) head = FEC_SOURCE_SYMBOLS;
    uint8_t tail_count = (uint8_t)(FEC_SOURCE_SYMBOLS - head);
    uint16_t tail_start = (uint16_t)(head + g_fec_interleave_recovery);
    uint16_t tail_end = (uint16_t)(tail_start + tail_count);

    if (send_counter < head) {
        coeffs[send_counter] = 1;
        return;
    }
    if (send_counter >= tail_start && send_counter < tail_end) {
        uint8_t idx = (uint8_t)(send_counter - g_fec_interleave_recovery);
        coeffs[idx] = 1;
        return;
    }

    uint32_t state = 0x9e3779b9u ^
                     ((uint32_t)hint << 24) ^
                     ((uint32_t)(epoch & 0x0f) << 16) ^
                     (uint32_t)send_counter;

    bool any_nonzero = false;
    for (int i = 0; i < FEC_SOURCE_SYMBOLS; i++) {
        coeffs[i] = (uint8_t)(fec_rng_next(&state) & 0xff);
        any_nonzero |= (coeffs[i] != 0);
    }
    if (!any_nonzero) {
        coeffs[(uint8_t)(fec_rng_next(&state) % FEC_SOURCE_SYMBOLS)] = 1;
    }
}

uint16_t fec_encode_symbol(const uint8_t *source32,
                           const uint8_t coeffs[FEC_SOURCE_SYMBOLS])
{
    uint8_t out_hi = 0;
    uint8_t out_lo = 0;
    for (int i = 0; i < FEC_SOURCE_SYMBOLS; i++) {
        uint8_t c = coeffs[i];
        if (!c) continue;
        out_hi ^= gf256_mul(c, source32[i * 2]);
        out_lo ^= gf256_mul(c, source32[i * 2 + 1]);
    }
    return (uint16_t)(((uint16_t)out_hi << 8) | out_lo);
}

static bool fec_try_decode(const uint8_t coeff[FEC_MAX_EQUATIONS][FEC_SOURCE_SYMBOLS],
                           const uint16_t *rhs,
                           uint8_t eq_count,
                           uint8_t *out32)
{
    if (eq_count < FEC_SOURCE_SYMBOLS) return false;

    uint8_t a[FEC_MAX_EQUATIONS][FEC_SOURCE_SYMBOLS];
    uint8_t b0[FEC_MAX_EQUATIONS];
    uint8_t b1[FEC_MAX_EQUATIONS];
    for (int r = 0; r < eq_count; r++) {
        memcpy(a[r], coeff[r], FEC_SOURCE_SYMBOLS);
        b0[r] = (uint8_t)(rhs[r] >> 8);
        b1[r] = (uint8_t)(rhs[r] & 0xff);
    }

    int pivot_row[FEC_SOURCE_SYMBOLS];
    for (int i = 0; i < FEC_SOURCE_SYMBOLS; i++) pivot_row[i] = -1;

    int row = 0;
    for (int col = 0; col < FEC_SOURCE_SYMBOLS; col++) {
        int sel = -1;
        for (int r = row; r < eq_count; r++) {
            if (a[r][col] != 0) {
                sel = r;
                break;
            }
        }
        if (sel < 0) continue;

        if (sel != row) {
            uint8_t tmp_row[FEC_SOURCE_SYMBOLS];
            memcpy(tmp_row, a[row], FEC_SOURCE_SYMBOLS);
            memcpy(a[row], a[sel], FEC_SOURCE_SYMBOLS);
            memcpy(a[sel], tmp_row, FEC_SOURCE_SYMBOLS);
            uint8_t tb0 = b0[row]; b0[row] = b0[sel]; b0[sel] = tb0;
            uint8_t tb1 = b1[row]; b1[row] = b1[sel]; b1[sel] = tb1;
        }

        uint8_t inv = gf256_inv(a[row][col]);
        if (!inv) continue;
        for (int c = col; c < FEC_SOURCE_SYMBOLS; c++) {
            a[row][c] = gf256_mul(a[row][c], inv);
        }
        b0[row] = gf256_mul(b0[row], inv);
        b1[row] = gf256_mul(b1[row], inv);

        for (int r = 0; r < eq_count; r++) {
            if (r == row || a[r][col] == 0) continue;
            uint8_t factor = a[r][col];
            for (int c = col; c < FEC_SOURCE_SYMBOLS; c++) {
                a[r][c] ^= gf256_mul(factor, a[row][c]);
            }
            b0[r] ^= gf256_mul(factor, b0[row]);
            b1[r] ^= gf256_mul(factor, b1[row]);
        }

        pivot_row[col] = row;
        row++;
        if (row == FEC_SOURCE_SYMBOLS) break;
    }

    if (row < FEC_SOURCE_SYMBOLS) return false;

    for (int col = 0; col < FEC_SOURCE_SYMBOLS; col++) {
        int pr = pivot_row[col];
        if (pr < 0) return false;
        out32[col * 2] = b0[pr];
        out32[col * 2 + 1] = b1[pr];
    }
    return true;
}

uint8_t fec_rx_eq_count(const FecRxState *rx)
{
    return rx->active ? rx->eq_count : 0;
}

void fec_rx_clear(FecRxState *rx)
{
    memset(rx, 0, sizeof(*rx));
}

void fec_rx_ensure_round(FecRxState *rx, uint8_t hint, uint8_t epoch, bool log_change)
{
    if (!rx->active || rx->hint != hint || rx->epoch != epoch) {
        if (log_change) {
            printf("  [FEC new round] remote hint/epoch = %02x/%u\n", hint, epoch);
        }
        fec_rx_clear(rx);
        rx->active = 1;
        rx->hint = hint;
        rx->epoch = epoch;
    }
}

void fec_rx_add_symbol(FecRxState *rx, uint16_t counter, uint16_t symbol)
{
    if (!rx->active || rx->eq_count >= FEC_MAX_EQUATIONS) return;

    for (uint8_t i = 0; i < rx->eq_count; i++) {
        if (rx->counters[i] == counter) {
            return;
        }
    }

    rx->counters[rx->eq_count] = counter;
    rx->symbols[rx->eq_count] = symbol;
    rx->eq_count++;
}

bool fec_rx_try_decode_candidate(const FecRxState *rx, uint8_t out_candidate[32])
{
    if (!rx->active || rx->eq_count < FEC_SOURCE_SYMBOLS) return false;

    uint8_t coeff[FEC_MAX_EQUATIONS][FEC_SOURCE_SYMBOLS];
    for (uint8_t i = 0; i < rx->eq_count; i++) {
        fec_equation_coeffs(rx->hint, rx->epoch, rx->counters[i], coeff[i]);
    }
    return fec_try_decode(coeff, rx->symbols, rx->eq_count, out_candidate);
}
