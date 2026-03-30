#include <string.h>

#include "prng.h"

#include "lib/ascon/ascon.h"

typedef struct {
    ascon_state_t sponge;
    uint64_t mix_counter;
} AsconPrng;

static AsconPrng g_prng;

uint8_t prng_next_byte(void)
{
    uint8_t out = 0;
    ascon_squeeze(&g_prng.sponge, &out, 1);
    return out;
}

uint32_t prng_next(void)
{
    uint32_t v = 0;
    v |= ((uint32_t)prng_next_byte() << 24);
    v |= ((uint32_t)prng_next_byte() << 16);
    v |= ((uint32_t)prng_next_byte() << 8);
    v |= (uint32_t)prng_next_byte();
    return v;
}

void random_bytes(uint8_t *b, size_t n)
{
    if (!b || n == 0) return;
    ascon_squeeze(&g_prng.sponge, b, n);
}

void prng_absorb(const uint8_t *data, size_t len, const char *label)
{
    uint8_t ctr[8];
    uint64_t c = g_prng.mix_counter++;
    for (int i = 7; i >= 0; --i) {
        ctr[i] = (uint8_t)(c & 0xff);
        c >>= 8;
    }

    ascon_absorb(&g_prng.sponge, (const uint8_t*)"MC-PRNG-MIX-v1", 14);
    ascon_absorb(&g_prng.sponge, (const uint8_t*)label, strlen(label));
    ascon_absorb(&g_prng.sponge, ctr, sizeof(ctr));
    ascon_absorb(&g_prng.sponge, data, len);
}

void prng_seed(uint32_t seed)
{
    memset(&g_prng, 0, sizeof(g_prng));
    ascon_inithash(&g_prng.sponge);
    ascon_absorb(&g_prng.sponge, (const uint8_t*)"MC-PRNG-v1", 10);

    uint8_t s[4];
    s[0] = (uint8_t)((seed >> 24) & 0xff);
    s[1] = (uint8_t)((seed >> 16) & 0xff);
    s[2] = (uint8_t)((seed >> 8) & 0xff);
    s[3] = (uint8_t)(seed & 0xff);
    ascon_absorb(&g_prng.sponge, s, sizeof(s));
}
