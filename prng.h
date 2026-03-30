#ifndef PRNG_H
#define PRNG_H

#include <stddef.h>
#include <stdint.h>

/**
 * The real implementation will persist the seed accross reboots
 */

void prng_seed(uint32_t seed);
uint8_t prng_next_byte(void);
uint32_t prng_next(void);

void random_bytes(uint8_t *b, size_t n);
/** 
 * use this to mix in entropy from remote peers so that even if our local PRNG is bust we eventually "heal"
 */
void prng_absorb(const uint8_t *data, size_t len, const char *label);

#endif
