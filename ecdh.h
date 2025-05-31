#ifndef ECDH_H
#define ECDH_H

#include <stdint.h>
#include <stddef.h>

// ECDH tuple structure - matches rct::ecdhTuple exactly
typedef struct {
    uint8_t mask[32];    // Commitment mask 'a' where C = aG + bH
    uint8_t amount[32];  // Encoded amount 'b' (64-bit amount in 32-byte key format)
} ecdh_tuple_t;

/**
 * Encode ECDH tuple for output
 * Encodes the amount and mask using ECDH with shared secret
 * 
 * @param unmasked - Input: plaintext amount and mask to encode
 * @param shared_secret - 32-byte shared secret (typically r*A or a*R)
 * @param v2 - true for v2+ format (amount only), false for v1 format (amount + mask)
 */
void monero_ecdh_encode(ecdh_tuple_t *unmasked, const uint8_t shared_secret[32], int v2);

/**
 * Decode ECDH tuple from output
 * Decodes the amount and mask using ECDH with shared secret
 * 
 * @param masked - Input: encoded amount and mask to decode
 * @param shared_secret - 32-byte shared secret (typically r*A or a*R)  
 * @param v2 - true for v2+ format (amount only), false for v1 format (amount + mask)
 */
void monero_ecdh_decode(ecdh_tuple_t *masked, const uint8_t shared_secret[32], int v2);

/**
 * Convert 64-bit amount to 32-byte key format
 * Used internally for amount encoding
 * 
 * @param amount_key - Output: 32-byte key representation
 * @param amount - Input: 64-bit amount value
 */
void monero_d2h(uint8_t amount_key[32], uint64_t amount);

/**
 * Convert 32-byte key to 64-bit amount
 * Used internally for amount decoding
 * 
 * @param amount_key - Input: 32-byte key representation
 * @return 64-bit amount value (first 8 bytes interpreted as little-endian)
 */
uint64_t monero_h2d(const uint8_t amount_key[32]);

/**
 * Generate amount encoding factor from shared secret
 * Internal function for ECDH encoding/decoding
 * 
 * @param shared_secret - Input: 32-byte shared secret
 * @param encoding_factor - Output: 32-byte encoding factor
 */
void monero_gen_amount_encoding_factor(const uint8_t shared_secret[32], uint8_t encoding_factor[32]);

/**
 * Generate commitment mask from shared secret  
 * Internal function for ECDH encoding/decoding
 * 
 * @param shared_secret - Input: 32-byte shared secret
 * @param commitment_mask - Output: 32-byte commitment mask
 */
void monero_gen_commitment_mask(const uint8_t shared_secret[32], uint8_t commitment_mask[32]);

#endif // ECDH_H