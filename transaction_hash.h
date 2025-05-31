#ifndef TRANSACTION_HASH_H
#define TRANSACTION_HASH_H

#include <stdint.h>
#include <stddef.h>
#include "tx_prefix_hash.h"
#include "rct_types.h"

/**
 * Compute full Monero transaction hash
 * This is the hash that gets signed by MLSAG/CLSAG signatures
 * Surgically ported from rct::get_pre_mlsag_hash()
 * 
 * @param tx_prefix - Transaction prefix structure
 * @param rct_sig - Complete RCT signature structure
 * @param transaction_hash - Output: 32-byte transaction hash for signing
 * @return 1 on success, 0 on failure
 */
int monero_get_transaction_hash(
    const transaction_prefix_t *tx_prefix,
    const rct_sig_t *rct_sig,
    uint8_t transaction_hash[32]
);

/**
 * Compute RCT signature base hash
 * Internal function that hashes the RCT base portion
 * 
 * @param rct_base - RCT signature base structure
 * @param inputs - Number of transaction inputs
 * @param outputs - Number of transaction outputs
 * @param base_hash - Output: 32-byte hash of RCT base
 * @return 1 on success, 0 on failure
 */
int monero_get_rct_base_hash(
    const rct_sig_base_t *rct_base,
    size_t inputs,
    size_t outputs,
    uint8_t base_hash[32]
);

/**
 * Compute range proofs hash
 * Hashes bulletproofs, bulletproof plus, or borromean range proofs
 * 
 * @param rct_sig - Complete RCT signature structure
 * @param range_proof_hash - Output: 32-byte hash of range proofs
 * @return 1 on success, 0 on failure
 */
int monero_get_range_proof_hash(
    const rct_sig_t *rct_sig,
    uint8_t range_proof_hash[32]
);

/**
 * Hash key vector using Keccak
 * Internal utility function for hashing arrays of keys
 * 
 * @param keys - Array of 32-byte keys
 * @param count - Number of keys in array
 * @param hash_out - Output: 32-byte hash
 */
void monero_hash_key_vector(
    const rct_key_t *keys,
    size_t count,
    uint8_t hash_out[32]
);

/**
 * Create dummy range proof hash for PoC
 * Used when range proofs are not implemented
 * 
 * @param outputs - Number of outputs (for context)
 * @param dummy_hash - Output: 32-byte dummy hash
 */
void monero_create_dummy_range_proof_hash(
    size_t outputs,
    uint8_t dummy_hash[32]
);

/**
 * Combine three hashes into final transaction hash
 * Final step of transaction hash computation
 * 
 * @param prefix_hash - Transaction prefix hash
 * @param base_hash - RCT base hash
 * @param range_proof_hash - Range proof hash
 * @param final_hash - Output: Combined transaction hash
 */
void monero_combine_transaction_hashes(
    const uint8_t prefix_hash[32],
    const uint8_t base_hash[32], 
    const uint8_t range_proof_hash[32],
    uint8_t final_hash[32]
);

#endif // TRANSACTION_HASH_H