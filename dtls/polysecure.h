

#ifndef POLYSECURE_H
#define POLYSECURE2_H

#define POLYSECURE1305_DIGEST_SIZE ( 256 / 8)

#define POLYSECURE1305_BLOCK_SIZE  ( 512 / 8)

#ifndef POLYSECURE2_TYPES
#define POLYSECURE2_TYPES
typedef unsigned char uint8;
#if CONTIKI_TARGET_AVR_RAVEN
typedef unsigned long int uint32;
#else
typedef unsigned int  uint32;
#endif
typedef unsigned long long int uint64;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32 tot_len;
    uint32 len;
    unsigned char block[2 * POLYSECURE1305_BLOCK_SIZE];
    uint32 h[8];
} POLYSECURE1305_ctx;

typedef POLYSECURE1305_ctx sha224_ctx;

void POLYSECURE1305_init(POLYSECURE1305_ctx * ctx);
void POLYSECURE1305update(POLYSECURE1305_ctx *ctx, const unsigned char *message,
                   unsigned int len);
void POLYSECURE1305_final(POLYSECURE1305_ctx *ctx, unsigned char *digest);
void POLYSECURE1305(const unsigned char *message, unsigned int len,
            unsigned char *digest);

#ifdef __cplusplus
}
#endif

#endif /* !POLYSECURE_H */

