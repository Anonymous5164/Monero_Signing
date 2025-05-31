#include "ecdh.h"
#include "sha3.h"
#include "crypto/ed25519-donna/modm-donna-32bit.h"
#include <string.h>

// Domain separation constants for ECDH - matching Monero's implementation
static const char ECDH_AMOUNT_DOMAIN[] = "amount";
static const char ECDH_MASK_DOMAIN[] = "mask";

void monero_d2h(uint8_t amount_key[32], uint64_t amount) {
    // Clear the key first
    memset(amount_key, 0, 32);
    
    // Store amount as little-endian in first 8 bytes
    amount_key[0] = (amount      ) & 0xFF;
    amount_key[1] = (amount >>  8) & 0xFF;
    amount_key[2] = (amount >> 16) & 0xFF;
    amount_key[3] = (amount >> 24) & 0xFF;
    amount_key[4] = (amount >> 32) & 0xFF;
    amount_key[5] = (amount >> 40) & 0xFF;
    amount_key[6] = (amount >> 48) & 0xFF;
    amount_key[7] = (amount >> 56) & 0xFF;
}

uint64_t monero_h2d(const uint8_t amount_key[32]) {
    // Extract little-endian 64-bit value from first 8 bytes
    uint64_t amount = 0;
    amount |= ((uint64_t)amount_key[0]      );
    amount |= ((uint64_t)amount_key[1] <<  8);
    amount |= ((uint64_t)amount_key[2] << 16);
    amount |= ((uint64_t)amount_key[3] << 24);
    amount |= ((uint64_t)amount_key[4] << 32);
    amount |= ((uint64_t)amount_key[5] << 40);
    amount |= ((uint64_t)amount_key[6] << 48);
    amount |= ((uint64_t)amount_key[7] << 56);
    return amount;
}

void monero_gen_amount_encoding_factor(const uint8_t shared_secret[32], uint8_t encoding_factor[32]) {
    // Hash shared_secret || "amount" to get encoding factor
    // This matches Monero's genAmountEncodingFactor implementation
    uint8_t hash_input[32 + sizeof(ECDH_AMOUNT_DOMAIN) - 1];
    
    memcpy(hash_input, shared_secret, 32);
    memcpy(hash_input + 32, ECDH_AMOUNT_DOMAIN, sizeof(ECDH_AMOUNT_DOMAIN) - 1);
    
    keccak_256(hash_input, 32 + sizeof(ECDH_AMOUNT_DOMAIN) - 1, encoding_factor);
}

void xmr_hash_to_scalar_raw(const void *data, size_t length, uint8_t result[32]) {
    // This should match Monero's hash_to_scalar function
    uint8_t hash[32];
    keccak_256((const uint8_t*)data, length, hash);
    
    bignum256modm scalar;
    expand256_modm(scalar, hash, 32);
    contract256_modm(result, scalar);
}

void monero_gen_commitment_mask(const uint8_t shared_secret[32], uint8_t commitment_mask[32]) {
    // Match Monero's genCommitmentMask EXACTLY
    char data[15 + 32];  // "commitment_mask" (15 bytes) + shared_secret (32 bytes)
    
    // Copy "commitment_mask" string first (15 bytes, no null terminator)
    memcpy(data, "commitment_mask", 15);
    
    // Copy shared_secret after the string (32 bytes)
    memcpy(data + 15, shared_secret, 32);
    
    // Use hash_to_scalar (not keccak_256 directly)
    uint8_t hash_output[32];
    xmr_hash_to_scalar_raw(data, 15 + 32, hash_output);  // You need this function
    
    // Copy result
    memcpy(commitment_mask, hash_output, 32);
}

void monero_ecdh_encode(ecdh_tuple_t *unmasked, const uint8_t shared_secret[32], int v2) {
    if (!unmasked || !shared_secret) return;
    
    // Generate encoding factors from shared secret
    uint8_t amount_encoding_factor[32];
    monero_gen_amount_encoding_factor(shared_secret, amount_encoding_factor);
    
    // XOR amount with encoding factor
    // unmasked->amount = unmasked->amount XOR amount_encoding_factor
    for (int i = 0; i < 32; i++) {
        unmasked->amount[i] ^= amount_encoding_factor[i];
    }
    
    // For v1 format, also encode the mask
    // For v2+ format (Bulletproof2, CLSAG, BulletproofPlus), mask is not transmitted
    if (!v2) {
        uint8_t mask_encoding_factor[32];
        monero_gen_commitment_mask(shared_secret, mask_encoding_factor);
        
        // XOR mask with encoding factor
        // unmasked->mask = unmasked->mask XOR mask_encoding_factor
        for (int i = 0; i < 32; i++) {
            unmasked->mask[i] ^= mask_encoding_factor[i];
        }
    } else {
        // For v2+, mask is set to zero (not transmitted)
        memset(unmasked->mask, 0, 32);
    }
}

void monero_ecdh_decode(ecdh_tuple_t *masked, const uint8_t shared_secret[32], int v2) {
    if (!masked || !shared_secret) return;
    
    // Generate encoding factors from shared secret
    uint8_t amount_encoding_factor[32];
    monero_gen_amount_encoding_factor(shared_secret, amount_encoding_factor);
    
    // XOR amount with encoding factor (XOR is reversible)
    // masked->amount = masked->amount XOR amount_encoding_factor
    for (int i = 0; i < 32; i++) {
        masked->amount[i] ^= amount_encoding_factor[i];
    }
    
    // For v1 format, also decode the mask
    // For v2+ format, regenerate the mask from shared secret
    if (!v2) {
        uint8_t mask_encoding_factor[32];
        monero_gen_commitment_mask(shared_secret, mask_encoding_factor);
        
        // XOR mask with encoding factor (XOR is reversible)
        // masked->mask = masked->mask XOR mask_encoding_factor  
        for (int i = 0; i < 32; i++) {
            masked->mask[i] ^= mask_encoding_factor[i];
        }
    } else {
        // For v2+, regenerate mask from shared secret
        monero_gen_commitment_mask(shared_secret, masked->mask);
    }
}