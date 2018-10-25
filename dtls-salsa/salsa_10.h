
#ifndef SALSA10_SIMPLE_H
#define SALSA10_SIMPLE_H
#include <stdint.h>

#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))

#define LE(p) (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#define FROMLE(b, i) (b)[0] = i & 0xFF; (b)[1] = (i >> 8) & 0xFF; (b)[2] = (i >> 16) & 0xFF; (b)[3] = (i >> 24) & 0xFF;

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
  uint32_t schedule[16];
  uint32_t keystream[16];
  size_t available;
} salsa10_ctx;

//Call this to initilize a salsa10_ctx, must be called before all other functions
void salsa10_setup(salsa10_ctx *ctx, const uint8_t *key, size_t length, uint8_t nonce[8]);

//Call this if you need to process a particular block number
void salsa10_counter_set(salsa10_ctx *ctx, uint64_t counter);

//Raw keystream for the current block, convert output to uint8_t[] for individual bytes. Counter is incremented upon use
void salsa10_block(salsa10_ctx *ctx, uint32_t output[16]);

//Encrypt an arbitrary amount of plaintext, call continuously as needed
void salsa10_encrypt(salsa10_ctx *ctx, const uint8_t *in, uint8_t *out, size_t length);

//Decrypt an arbitrary amount of ciphertext. Actually, for chacha20, decryption is the same function as encryption
void salsa10_decrypt(salsa10_ctx *ctx, const uint8_t *in, uint8_t *out, size_t length);

#ifdef __cplusplus
}
#endif

#endif

