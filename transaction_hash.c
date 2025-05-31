#include "transaction_hash.h"
#include "sha3.h"
#include <string.h>
#include <stdlib.h>

static int monero_hash_bulletproofs(const bulletproof_t *bulletproofs, size_t count, uint8_t hash_out[32]);
static int monero_hash_bulletproofs_plus(const bulletproof_plus_t *bulletproofs_plus, size_t count, uint8_t hash_out[32]);
static int monero_hash_borromean_range_sigs(const range_sig_t *range_sigs, size_t count, uint8_t hash_out[32]);

// Internal helper to determine if RCT type is simple
static inline int is_simple_rct_type(rct_type_t type) {
    return type == RCT_TYPE_SIMPLE || type == RCT_TYPE_BULLETPROOF || 
           type == RCT_TYPE_BULLETPROOF2 || type == RCT_TYPE_CLSAG || 
           type == RCT_TYPE_BULLETPROOF_PLUS;
}

int monero_get_transaction_hash(
    const transaction_prefix_t *tx_prefix,
    const rct_sig_t *rct_sig,
    uint8_t transaction_hash[32]) {
    
    if (!tx_prefix || !rct_sig || !transaction_hash) {
        return 0;
    }
    
    // Step 1: Get transaction prefix hash (you already have this working)
    uint8_t prefix_hash[32];
    if (!monero_get_transaction_prefix_hash(tx_prefix, prefix_hash)) {
        return 0;
    }
    
    // Step 2: Get RCT signature base hash
    uint8_t rct_base_hash[32];
    size_t inputs = is_simple_rct_type(rct_sig->base.type) ? 
                   rct_sig->base.mix_ring.row_count : 
                   (rct_sig->base.mix_ring.row_count > 0 ? rct_sig->base.mix_ring.rows[0].count : 0);
    size_t outputs = rct_sig->base.ecdh_info.count;
    
    if (!monero_get_rct_base_hash(&rct_sig->base, inputs, outputs, rct_base_hash)) {
        return 0;
    }
    
    // Step 3: Get range proof hash
    uint8_t range_proof_hash[32];
    if (!monero_get_range_proof_hash(rct_sig, range_proof_hash)) {
        return 0;
    }
    
    // Step 4: Combine all hashes - exactly matching get_pre_mlsag_hash logic
    monero_combine_transaction_hashes(prefix_hash, rct_base_hash, range_proof_hash, transaction_hash);
    
    return 1;
}

int monero_get_rct_base_hash(
    const rct_sig_base_t *rct_base,
    size_t inputs,
    size_t outputs,
    uint8_t base_hash[32]) {
    
    if (!rct_base || !base_hash) {
        return 0;
    }
    
    // Serialize RCT base using the exact same logic as Monero's serialize_rctsig_base
    uint8_t *serialization_buffer = malloc(MAX_TX_BUFFER_SIZE);
    if (!serialization_buffer) {
        return 0;
    }
    
    size_t serialized_size;
    int result = rct_serialize_sig_base(rct_base, inputs, outputs, 
                                       serialization_buffer, MAX_TX_BUFFER_SIZE, 
                                       &serialized_size);
    
    if (!result) {
        free(serialization_buffer);
        return 0;
    }
    
    // Hash the serialized RCT base - matches cryptonote::get_blob_hash
    keccak_256(serialization_buffer, serialized_size, base_hash);
    
    free(serialization_buffer);
    return 1;
}

int monero_get_range_proof_hash(
    const rct_sig_t *rct_sig,
    uint8_t range_proof_hash[32]) {
    
    if (!rct_sig || !range_proof_hash) {
        return 0;
    }
    
    // Handle different RCT types - exact logic from get_pre_mlsag_hash lines 588-626
    if (rct_sig->base.type == RCT_TYPE_BULLETPROOF || 
        rct_sig->base.type == RCT_TYPE_BULLETPROOF2 || 
        rct_sig->base.type == RCT_TYPE_CLSAG) {
        
        // Hash bulletproof data
        if (rct_sig->prunable.bulletproofs_count > 0) {
            return monero_hash_bulletproofs(rct_sig->prunable.bulletproofs, 
                                          rct_sig->prunable.bulletproofs_count, 
                                          range_proof_hash);
        } else {
            // No bulletproofs - create zero hash
            memset(range_proof_hash, 0, 32);
            return 1;
        }
    }
    else if (rct_sig->base.type == RCT_TYPE_BULLETPROOF_PLUS) {
        
        // Hash bulletproof plus data  
        if (rct_sig->prunable.bulletproofs_plus_count > 0) {
            return monero_hash_bulletproofs_plus(rct_sig->prunable.bulletproofs_plus,
                                                rct_sig->prunable.bulletproofs_plus_count,
                                                range_proof_hash);
        } else {
            // No bulletproofs plus - create zero hash
            memset(range_proof_hash, 0, 32);
            return 1;
        }
    }
    else {
        // Borromean range proofs (RCTTypeFull, RCTTypeSimple)
        if (rct_sig->prunable.range_sigs_count > 0) {
            return monero_hash_borromean_range_sigs(rct_sig->prunable.range_sigs,
                                                  rct_sig->prunable.range_sigs_count,
                                                  range_proof_hash);
        } else {
            // No range sigs - create zero hash
            memset(range_proof_hash, 0, 32);
            return 1;
        }
    }
}

// Hash bulletproofs - matches the key extraction logic from get_pre_mlsag_hash
static int monero_hash_bulletproofs(
    const bulletproof_t *bulletproofs,
    size_t count,
    uint8_t hash_out[32]) {
    
    if (count == 0) {
        memset(hash_out, 0, 32);
        return 1;
    }
    
    // Calculate total keys needed: (6*2+9) per bulletproof (from line 589 comment)
    size_t total_keys = 0;
    for (size_t i = 0; i < count; i++) {
        total_keys += 6 + bulletproofs[i].L.count + bulletproofs[i].R.count + 3; // A,S,T1,T2,taux,mu + L + R + a,b,t
    }
    
    rct_key_t *all_keys = malloc(total_keys * sizeof(rct_key_t));
    if (!all_keys) {
        return 0;
    }
    
    size_t key_index = 0;
    for (size_t i = 0; i < count; i++) {
        const bulletproof_t *bp = &bulletproofs[i];
        
        // V are not hashed (comment from line 591)
        // Add A, S, T1, T2, taux, mu
        all_keys[key_index++] = bp->A;
        all_keys[key_index++] = bp->S;
        all_keys[key_index++] = bp->T1;
        all_keys[key_index++] = bp->T2;
        all_keys[key_index++] = bp->taux;
        all_keys[key_index++] = bp->mu;
        
        // Add L vector
        for (size_t j = 0; j < bp->L.count; j++) {
            all_keys[key_index++] = bp->L.keys[j];
        }
        
        // Add R vector
        for (size_t j = 0; j < bp->R.count; j++) {
            all_keys[key_index++] = bp->R.keys[j];
        }
        
        // Add a, b, t
        all_keys[key_index++] = bp->a;
        all_keys[key_index++] = bp->b;
        all_keys[key_index++] = bp->t;
    }
    
    // Hash all keys together
    monero_hash_key_vector(all_keys, key_index, hash_out);
    
    free(all_keys);
    return 1;
}

// Hash bulletproof plus - matches the key extraction logic
static int monero_hash_bulletproofs_plus(
    const bulletproof_plus_t *bulletproofs_plus,
    size_t count,
    uint8_t hash_out[32]) {
    
    if (count == 0) {
        memset(hash_out, 0, 32);
        return 1;
    }
    
    // Calculate total keys needed: (6*2+6) per bulletproof plus (from line 606 comment)
    size_t total_keys = 0;
    for (size_t i = 0; i < count; i++) {
        total_keys += 6 + bulletproofs_plus[i].L.count + bulletproofs_plus[i].R.count; // A,A1,B,r1,s1,d1 + L + R
    }
    
    rct_key_t *all_keys = malloc(total_keys * sizeof(rct_key_t));
    if (!all_keys) {
        return 0;
    }
    
    size_t key_index = 0;
    for (size_t i = 0; i < count; i++) {
        const bulletproof_plus_t *bpp = &bulletproofs_plus[i];
        
        // V are not hashed (comment from line 610)
        // Add A, A1, B, r1, s1, d1
        all_keys[key_index++] = bpp->A;
        all_keys[key_index++] = bpp->A1;
        all_keys[key_index++] = bpp->B;
        all_keys[key_index++] = bpp->r1;
        all_keys[key_index++] = bpp->s1;
        all_keys[key_index++] = bpp->d1;
        
        // Add L vector
        for (size_t j = 0; j < bpp->L.count; j++) {
            all_keys[key_index++] = bpp->L.keys[j];
        }
        
        // Add R vector  
        for (size_t j = 0; j < bpp->R.count; j++) {
            all_keys[key_index++] = bpp->R.keys[j];
        }
    }
    
    // Hash all keys together
    monero_hash_key_vector(all_keys, key_index, hash_out);
    
    free(all_keys);
    return 1;
}

// Hash borromean range signatures - matches the key extraction logic  
static int monero_hash_borromean_range_sigs(
    const range_sig_t *range_sigs,
    size_t count,
    uint8_t hash_out[32]) {
    
    if (count == 0) {
        memset(hash_out, 0, 32);
        return 1;
    }
    
    // Calculate total keys: (64*3+1) per range sig (from line 619 comment)
    size_t total_keys = count * (64 * 3 + 1 + 64); // s0[64] + s1[64] + ee + Ci[64]
    
    rct_key_t *all_keys = malloc(total_keys * sizeof(rct_key_t));
    if (!all_keys) {
        return 0;
    }
    
    size_t key_index = 0;
    for (size_t i = 0; i < count; i++) {
        const range_sig_t *rs = &range_sigs[i];
        
        // Add s0 array
        for (size_t j = 0; j < 64; j++) {
            all_keys[key_index++] = rs->asig.s0[j];
        }
        
        // Add s1 array
        for (size_t j = 0; j < 64; j++) {
            all_keys[key_index++] = rs->asig.s1[j];
        }
        
        // Add ee
        all_keys[key_index++] = rs->asig.ee;
        
        // Add Ci array
        for (size_t j = 0; j < 64; j++) {
            all_keys[key_index++] = rs->Ci[j];
        }
    }
    
    // Hash all keys together
    monero_hash_key_vector(all_keys, key_index, hash_out);
    
    free(all_keys);
    return 1;
}

void monero_hash_key_vector(
    const rct_key_t *keys,
    size_t count,
    uint8_t hash_out[32]) {
    
    if (!keys || count == 0) {
        memset(hash_out, 0, 32);
        return;
    }
    
    // Hash the concatenated key data - matches cn_fast_hash(kv) from line 626
    keccak_256((const uint8_t*)keys, count * 32, hash_out);
}

void monero_combine_transaction_hashes(
    const uint8_t prefix_hash[32],
    const uint8_t base_hash[32],
    const uint8_t range_proof_hash[32],
    uint8_t final_hash[32]) {
    
    // Create hash vector matching get_pre_mlsag_hash logic
    // hashes.push_back(rv.message);         // prefix hash
    // hashes.push_back(hash2rct(h));        // base hash  
    // hashes.push_back(cn_fast_hash(kv));   // range proof hash
    uint8_t combined_hashes[96]; // 3 * 32 bytes
    
    memcpy(combined_hashes, prefix_hash, 32);
    memcpy(combined_hashes + 32, base_hash, 32);
    memcpy(combined_hashes + 64, range_proof_hash, 32);
    
    // Final hash of the combined hashes - matches hash_to_scalar(hashes) logic
    keccak_256(combined_hashes, 96, final_hash);
}

void monero_create_dummy_range_proof_hash(
    size_t outputs,
    uint8_t dummy_hash[32]) {
    
    // Create a deterministic dummy hash based on output count
    // This ensures consistent dummy hashes for testing
    uint8_t dummy_data[8];
    memset(dummy_data, 0, 8);
    
    // Encode output count as little-endian
    dummy_data[0] = (outputs      ) & 0xFF;
    dummy_data[1] = (outputs >>  8) & 0xFF;
    dummy_data[2] = (outputs >> 16) & 0xFF;
    dummy_data[3] = (outputs >> 24) & 0xFF;
    dummy_data[4] = (outputs >> 32) & 0xFF;
    dummy_data[5] = (outputs >> 40) & 0xFF;
    dummy_data[6] = (outputs >> 48) & 0xFF;
    dummy_data[7] = (outputs >> 56) & 0xFF;
    
    keccak_256(dummy_data, 8, dummy_hash);
}