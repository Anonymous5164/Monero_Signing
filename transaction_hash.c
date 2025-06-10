#include "transaction_hash.h"
#include "sha3.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int monero_hash_bulletproofs_plus(const bulletproof_plus_t *bulletproofs_plus, size_t count, uint8_t hash_out[32]);

// Internal helper to determine if RCT type is simple
static inline int is_simple_rct_type(rct_type_t type) {
    return type == RCT_TYPE_SIMPLE || type == RCT_TYPE_BULLETPROOF || 
           type == RCT_TYPE_BULLETPROOF2 || type == RCT_TYPE_CLSAG || 
           type == RCT_TYPE_BULLETPROOF_PLUS;
}

int monero_get_transaction_hash(const transaction_prefix_t *tx_prefix, const rct_sig_t *rct_sig, uint8_t transaction_hash[32]) {
    
    if (!tx_prefix || !rct_sig || !transaction_hash) {
        return 0;
    }
    
    // Step 1: Get transaction prefix hash (you already have this working)
    uint8_t prefix_hash[32];
    if (!monero_get_transaction_prefix_hash(tx_prefix, prefix_hash)) {
        return 0;
    }

        // DEBUG: Component 1
    printf("[DEVICE] Component1: ");
    for (int i = 0; i < 32; i++) printf("%02x", prefix_hash[i]);
    printf("\n");

    
    // Step 2: Get RCT signature base hash
    uint8_t rct_base_hash[32];
    size_t inputs = is_simple_rct_type(rct_sig->base.type) ? rct_sig->base.mix_ring.row_count : (rct_sig->base.mix_ring.row_count > 0 ? rct_sig->base.mix_ring.rows[0].count : 0);
    size_t outputs = rct_sig->base.ecdh_info.count;
    
    
    if (!monero_get_rct_base_hash(&rct_sig->base, inputs, outputs, rct_base_hash)) {
        return 0;
    }

    // DEBUG: Component 2
    printf("[DEVICE] Component2: ");
    for (int i = 0; i < 32; i++) printf("%02x", rct_base_hash[i]);
    printf("\n");
    
    // Step 3: Get range proof hash
    uint8_t range_proof_hash[32];
    if (!monero_get_range_proof_hash(rct_sig, range_proof_hash)) {
        return 0;
    }

    printf("[DEVICE] Component3: ");
    for (int i = 0; i < 32; i++) printf("%02x", range_proof_hash[i]);
    printf("\n");
    
    // Step 4: Combine all hashes - exactly matching get_pre_mlsag_hash logic
    monero_combine_transaction_hashes(prefix_hash, rct_base_hash, range_proof_hash, transaction_hash);
    printf("[DEVICE] Final: ");
    for (int i = 0; i < 32; i++) printf("%02x", transaction_hash[i]);
    printf("\n");
    
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
    int result = rct_serialize_sig_base(rct_base, inputs, outputs, serialization_buffer, MAX_TX_BUFFER_SIZE, &serialized_size);
    
    if (!result) {
        free(serialization_buffer);
        return 0;
    }

    printf("[DEVICE] === Byte-by-Byte Debug ===\n");
    printf("[DEVICE] Serialized %zu bytes total\n", serialized_size);
    printf("[DEVICE] First 64 bytes of serialized RCT base:\n");
    for (size_t i = 0; i < (serialized_size < 64 ? serialized_size : 64); i++) {
        printf("%02x", serialization_buffer[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("\n");
    printf("[DEVICE] === End Byte Debug ===\n");
    
    // Hash the serialized RCT base - matches cryptonote::get_blob_hash
    keccak_256(serialization_buffer, serialized_size, base_hash);
    
    free(serialization_buffer);
    return 1;
}

int monero_get_range_proof_hash(const rct_sig_t *rct_sig, uint8_t range_proof_hash[32]) {
    
    if (!rct_sig || !range_proof_hash) {
        return 0;
    }
    
    if (rct_sig->base.type == RCT_TYPE_BULLETPROOF_PLUS) {
        
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
        printf("[DEVICE] monero_get_range_proof_hash: Unsupported RCT type %d\n", rct_sig->base.type);
        return 0;
    }
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

    printf("[DEVICE] BP+ Structure Debug:\n");
    printf("[DEVICE]   bulletproofs_plus_count: %zu\n", count);
    for (size_t i = 0; i < count; i++) {
        const bulletproof_plus_t *bpp = &bulletproofs_plus[i];
        printf("[DEVICE]   BP[%zu]: L.count=%zu, R.count=%zu\n", i, bpp->L.count, bpp->R.count);
        printf("[DEVICE]   BP[%zu]: A=", i);
        for (int j = 0; j < 8; j++) printf("%02x", bpp->A.bytes[j]);
        printf("...\n");
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

    printf("[DEVICE] BP+ Debug: total_keys=%zu, count=%zu\n", total_keys, count);
    if (total_keys > 0) {
        printf("[DEVICE] First key: ");
        for (int i = 0; i < 32; i++) printf("%02x", all_keys[0].bytes[i]);
        printf("\n");
    }
    if (total_keys > 1) {
        printf("[DEVICE] Second key: ");
        for (int i = 0; i < 32; i++) printf("%02x", all_keys[1].bytes[i]);
        printf("\n");
    }
    
    // Hash all keys together
    monero_hash_key_vector(all_keys, key_index, hash_out);
    
    free(all_keys);
    return 1;
}

void monero_hash_key_vector(const rct_key_t *keys, size_t count, uint8_t hash_out[32]) {
    
    if (!keys || count == 0) {
        memset(hash_out, 0, 32);
        return;
    }
    
    // Hash the concatenated key data - matches cn_fast_hash(kv) from line 626
    keccak_256((const uint8_t*)keys, count * 32, hash_out);
}

void monero_combine_transaction_hashes(const uint8_t prefix_hash[32], const uint8_t base_hash[32], const uint8_t range_proof_hash[32], uint8_t final_hash[32]) {
    
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
