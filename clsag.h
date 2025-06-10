#ifndef CLSAG_H
#define CLSAG_H

#include <stdint.h>
#include <stddef.h>
#include "ed25519-donna/ed25519.h"
#include "ed25519-donna/modm-donna-32bit.h"
#include "monero/xmr.h"

#ifdef __cplusplus
extern "C" {
#endif

// CLSAG domain separation constants (matching Monero's config::HASH_KEY_CLSAG_*)
#define CLSAG_HASH_KEY_AGG_0 "CLSAG_agg_0"
#define CLSAG_HASH_KEY_AGG_1 "CLSAG_agg_1" 
#define CLSAG_HASH_KEY_ROUND "CLSAG_round"

// CLSAG signature structure
typedef struct {
    uint8_t c1[32];          // Initial challenge scalar
    uint8_t D[32];           // Auxiliary key image (scaled by 1/8)
    uint8_t I[32];           // Key image
    uint8_t *s;              // Response scalars (ring_size elements, each 32 bytes)
    size_t ring_size;        // Number of ring members
} clsag_signature_t;

// Ring member structure (public key + commitment)
typedef struct {
    uint8_t dest[32];        // Destination public key
    uint8_t mask[32];        // Commitment (C_i)
} ring_member_t;

// CLSAG generation parameters
typedef struct {
    uint8_t message[32];     // Message to sign
    ring_member_t *ring;     // Ring of public keys and commitments
    size_t ring_size;        // Number of ring members
    uint8_t p[32];           // Secret key corresponding to P[l]
    uint8_t z[32];           // Secret mask corresponding to C[l] 
    uint8_t C_offset[32];    // Commitment offset (pseudo output)
    unsigned int l;          // Signing index (which ring member we control)
} clsag_params_t;

/**
 * Generate a CLSAG signature
 * 
 * @param params Signing parameters
 * @param sig Output signature (caller must allocate sig->s as ring_size * 32 bytes)
 * @return 1 on success, 0 on failure
 */
int clsag_sign(const clsag_params_t *params, clsag_signature_t *sig);


/**
 * Free resources allocated for CLSAG signature
 * Note: Only clears sensitive data, caller still owns sig->s memory
 * 
 * @param sig Signature to clear
 */
void clsag_clear(clsag_signature_t *sig);

#ifdef __cplusplus
}
#endif

#endif // CLSAG_H