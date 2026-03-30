#ifndef FEC_H
#define FEC_H

#include <stdbool.h>
#include <stdint.h>

#define FEC_SOURCE_SYMBOLS 16
#define FEC_MAX_EQUATIONS 64
#define FEC_DEFAULT_SYSTEMATIC_HEAD 10
#define FEC_DEFAULT_INTERLEAVE_RECOVERY 4

extern uint8_t g_fec_systematic_head;
extern uint8_t g_fec_interleave_recovery;

typedef struct {
    uint8_t active;
    uint8_t hint;
    uint8_t epoch;
    uint8_t eq_count;
    uint16_t counters[FEC_MAX_EQUATIONS];
    uint16_t symbols[FEC_MAX_EQUATIONS];
} FecRxState;

void fec_equation_coeffs(uint8_t hint, uint8_t epoch, uint16_t send_counter,
                         uint8_t coeffs[FEC_SOURCE_SYMBOLS]);
uint16_t fec_encode_symbol(const uint8_t *source32,
                           const uint8_t coeffs[FEC_SOURCE_SYMBOLS]);

uint8_t fec_rx_eq_count(const FecRxState *rx);
void fec_rx_clear(FecRxState *rx);
void fec_rx_ensure_round(FecRxState *rx, uint8_t hint, uint8_t epoch, bool log_change);
void fec_rx_add_symbol(FecRxState *rx, uint16_t counter, uint16_t symbol);
bool fec_rx_try_decode_candidate(const FecRxState *rx, uint8_t out_candidate[32]);

#endif
