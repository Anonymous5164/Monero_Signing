#include "device_pipeline.h"
#include "utils.h"
#include "clsag.h"
#include "pseudo_outputs.h"
#include "transaction_hash.h"
#include "ecdh.h"
#include "sha3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

// Device wallet keys (securely stored in real implementation)
static uint8_t device_spend_key[32];
static uint8_t device_view_key[32];

// Add this function to your device code
static size_t encode_varint(uint8_t* output, uint64_t value) {
    size_t len = 0;
    while (value >= 0x80) {
        output[len] = (uint8_t)(value | 0x80);
        value >>= 7;
        len++;
    }
    output[len] = (uint8_t)value;
    return len + 1;
}

// Initialize device with wallet keys
int device_init_wallet(const char* seed_hex) {
    if (!seed_hex || strlen(seed_hex) != 64) {
        printf("[Device] ERROR: Invalid seed format\n");
        return 0;
    }
    
    uint8_t seed[32];
    hex_to_bytes(seed_hex, seed);
    seed_to_keys(seed, device_spend_key, device_view_key);
    
    printf("[Device] Wallet initialized successfully\n");
    return 1;
}

// Parse hex string to bytes with validation
static int parse_hex_to_bytes(const char* hex_str, uint8_t* output, size_t expected_len) {
    if (!hex_str || !output) return 0;
    
    size_t hex_len = strlen(hex_str);
    if (hex_len != expected_len * 2) return 0;
    
    hex_to_bytes(hex_str, output);
    return 1;
}

// Extract single transaction R from extra field
static int extract_tx_public_key_from_extra(const uint8_t* extra, size_t extra_len, uint8_t tx_public_key[32]) {
    if (extra_len < 33 || extra[0] != 0x01) {
        printf("[Device] ERROR: Invalid extra format\n");
        return 0;
    }
    
    memcpy(tx_public_key, extra + 1, 32);
    return 1;
}

// Parse ring members from JSON
static int parse_ring_members(cJSON* ring_json, ring_member_t** ring, size_t* ring_size) {
    if (!cJSON_IsArray(ring_json)) return 0;
    
    *ring_size = cJSON_GetArraySize(ring_json);
    if (*ring_size == 0) return 0;
    
    *ring = malloc(*ring_size * sizeof(ring_member_t));
    if (!*ring) return 0;
    
    for (size_t i = 0; i < *ring_size; i++) {
        cJSON* member = cJSON_GetArrayItem(ring_json, i);
        cJSON* dest = cJSON_GetObjectItem(member, "dest");
        cJSON* mask = cJSON_GetObjectItem(member, "mask");
        
        if (!dest || !mask || !cJSON_IsString(dest) || !cJSON_IsString(mask)) {
            free(*ring);
            return 0;
        }
        
        if (!parse_hex_to_bytes(dest->valuestring, (*ring)[i].dest, 32) ||
            !parse_hex_to_bytes(mask->valuestring, (*ring)[i].mask, 32)) {
            free(*ring);
            return 0;
        }
    }
    
    return 1;
}

static int generate_output_keys(uint32_t output_index, const uint8_t single_tx_public_key[32],
                               const uint8_t recipient_view_public_key[32], const uint8_t recipient_spend_public_key[32],
                               uint8_t output_public_key[32], uint8_t* view_tag) {
    
    // Generate key derivation using single R and DEVICE view key
    uint8_t derivation[32];
    if (!monero_generate_key_derivation(single_tx_public_key, device_view_key, derivation)) {
        return 0;
    }
    
    // Derive output public key using recipient's spend key
    if (!monero_derive_public_key(derivation, output_index, recipient_spend_public_key, output_public_key)) {
        return 0;
    }
    
    // Generate view tag using Monero's correct method: "view_tag" + derivation + varint(index)
    uint8_t view_tag_data[8 + 32 + 16]; // salt + derivation + max varint size
    memcpy(view_tag_data, "view_tag", 8);
    memcpy(view_tag_data + 8, derivation, 32);
    
    // Add varint-encoded index
    size_t varint_len = encode_varint(view_tag_data + 40, output_index);
    
    uint8_t view_tag_hash[32];
    keccak_256(view_tag_data, 40 + varint_len, view_tag_hash);
    *view_tag = view_tag_hash[0];
    
    return 1;
}

// Generate device-side ECDH info for outputs
static int generate_device_ecdh_info(size_t num_outputs, const tx_output_info_t* output_info,
                                    const uint8_t single_tx_public_key[32],
                                    ecdh_tuple_t* ecdh_info) {
    
    for (size_t i = 0; i < num_outputs; i++) {
        // Generate shared secret using single R and device view key
        uint8_t shared_secret[32];
        if (!monero_generate_key_derivation(single_tx_public_key, device_view_key, shared_secret)) {
            printf("[Device] ERROR: Failed to generate key derivation for output %zu\n", i);
            return 0;
        }
        
        // Create ECDH tuple with real values
        ecdh_tuple_t tuple;
        monero_d2h(tuple.amount, output_info[i].amount);  // Convert amount to 32-byte key format
        memcpy(tuple.mask, output_info[i].mask, 32);      // Use the commitment mask
        
        // Encode using device's ECDH implementation
        // For CLSAG (v2+ format), use proper ECDH encoding
        monero_ecdh_encode(&tuple, shared_secret, 1);  // 1 = v2+ format (CLSAG compatible)
        
        // Store encoded tuple
        ecdh_info[i] = tuple;
        

        // DEBUG: Verify decoding
        ecdh_tuple_t verify_tuple = ecdh_info[i];
        monero_ecdh_decode(&verify_tuple, shared_secret, 1);
        uint64_t decoded_amount = monero_h2d(verify_tuple.amount);
        
        if (decoded_amount != output_info[i].amount) {
            printf("[Device] WARNING: ECDH encode/decode mismatch for output %zu: expected %lu, got %lu\n",
                   i, output_info[i].amount, decoded_amount);
        } else {
            printf("[Device] ECDH verification passed for output %zu\n", i);
        }
    }
    
    return 1;
}

// Main transaction processing pipeline
int device_process_transaction(const char* input_json_path, const char* output_json_path) {
    
    // 1. Read and parse JSON
    FILE* input_file = fopen(input_json_path, "r");
    if (!input_file) {
        printf("[Device] ERROR: Cannot open input file: %s\n", input_json_path);
        return 0;
    }
    
    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);
    
    char* json_content = malloc(file_size + 1);
    if (!json_content) {
        fclose(input_file);
        return 0;
    }
    
    fread(json_content, 1, file_size, input_file);
    if (ferror(input_file)) {
        printf("[Device] ERROR: Failed to read file\n");
        free(json_content);
        fclose(input_file);
        return 0;
    }
    json_content[file_size] = '\0';
    fclose(input_file);
    
    cJSON* root = cJSON_Parse(json_content);
    free(json_content);
    
    if (!root) {
        printf("[Device] ERROR: Failed to parse JSON\n");
        return 0;
    }
    
    cJSON* tx_data = cJSON_GetObjectItem(root, "transaction_data");
    if (!tx_data) {
        printf("[Device] ERROR: No transaction_data found\n");
        cJSON_Delete(root);
        return 0;
    }
    
    // 2. Extract single transaction R from extra
    cJSON* tx_prefix_json = cJSON_GetObjectItem(tx_data, "tx_prefix");
    cJSON* extra_json = cJSON_GetObjectItem(tx_prefix_json, "extra");
    
    if (!extra_json || !cJSON_IsString(extra_json)) {
        printf("[Device] ERROR: No extra data found\n");
        cJSON_Delete(root);
        return 0;
    }
    
    const char* extra_hex = extra_json->valuestring;
    size_t extra_len = strlen(extra_hex) / 2;
    uint8_t* extra_bytes = malloc(extra_len);
    hex_to_bytes(extra_hex, extra_bytes);
    
    uint8_t single_tx_public_key[32];
    if (!extract_tx_public_key_from_extra(extra_bytes, extra_len, single_tx_public_key)) {
        free(extra_bytes);
        cJSON_Delete(root);
        return 0;
    }
    free(extra_bytes);
    
    // 3. Parse transaction structure 
    device_transaction_t tx = {0};
    
    // Parse fee
    cJSON* rct_sig = cJSON_GetObjectItem(tx_data, "rct_signature");
    cJSON* rct_base = cJSON_GetObjectItem(rct_sig, "base");
    cJSON* fee_json = cJSON_GetObjectItem(rct_base, "txn_fee");
    
    if (!fee_json || !cJSON_IsNumber(fee_json)) {
        printf("[Device] ERROR: Invalid fee\n");
        cJSON_Delete(root);
        return 0;
    }
    tx.fee = (uint64_t)fee_json->valuedouble;
    
    // Parse inputs 
    cJSON* clsag_inputs = cJSON_GetObjectItem(tx_data, "clsag_inputs");
    if (!clsag_inputs || !cJSON_IsArray(clsag_inputs)) {
        printf("[Device] ERROR: Invalid clsag_inputs\n");
        cJSON_Delete(root);
        return 0;
    }
    
    tx.num_inputs = cJSON_GetArraySize(clsag_inputs);
    tx.inputs = malloc(tx.num_inputs * sizeof(device_input_t));
    
    for (size_t i = 0; i < tx.num_inputs; i++) {
        cJSON* input_json = cJSON_GetArrayItem(clsag_inputs, i);
        device_input_t* input = &tx.inputs[i];
        
        // Parse ring
        cJSON* ring_json = cJSON_GetObjectItem(input_json, "ring");
        if (!parse_ring_members(ring_json, &input->ring, &input->ring_size)) {
            printf("[Device] ERROR: Failed to parse ring for input %zu\n", i);
            goto cleanup;
        }
        
        // Parse input fields
        cJSON* real_index = cJSON_GetObjectItem(input_json, "real_index");
        cJSON* amount = cJSON_GetObjectItem(input_json, "amount");
        cJSON* tx_public_key = cJSON_GetObjectItem(input_json, "tx_public_key");
        cJSON* output_index = cJSON_GetObjectItem(input_json, "output_index");
        
        if (!real_index || !amount || !tx_public_key || !output_index) {
            printf("[Device] ERROR: Missing input fields for input %zu\n", i);
            goto cleanup;
        }
        
        input->real_index = (uint32_t)real_index->valuedouble;
        input->amount = (uint64_t)amount->valuedouble;
        input->output_index = (uint32_t)output_index->valuedouble;
        
        // Parse source transaction R (NOT single R)
        if (!parse_hex_to_bytes(tx_public_key->valuestring, input->tx_public_key, 32)) {
            printf("[Device] ERROR: Invalid tx_public_key for input %zu\n", i);
            goto cleanup;
        }
        
        // Validate ring bounds
        if (input->real_index >= input->ring_size) {
            printf("[Device] ERROR: Invalid real_index for input %zu\n", i);
            goto cleanup;
        }
    }
    
    // Parse outputs
    cJSON* outputs_json = cJSON_GetObjectItem(tx_data, "outputs");
    if (!outputs_json || !cJSON_IsArray(outputs_json)) {
        printf("[Device] ERROR: Invalid outputs\n");
        goto cleanup;
    }
    
    tx.num_outputs = cJSON_GetArraySize(outputs_json);
    tx.outputs = malloc(tx.num_outputs * sizeof(device_output_t));
    
    for (size_t i = 0; i < tx.num_outputs; i++) {
        cJSON* output_json = cJSON_GetArrayItem(outputs_json, i);
        
        cJSON* amount = cJSON_GetObjectItem(output_json, "amount");
        cJSON* is_subaddress = cJSON_GetObjectItem(output_json, "is_subaddress");
        cJSON* view_pub = cJSON_GetObjectItem(output_json, "view_public_key");
        cJSON* spend_pub = cJSON_GetObjectItem(output_json, "spend_public_key");
        
        if (!amount || !view_pub || !spend_pub) {
            printf("[Device] ERROR: Missing output fields for output %zu\n", i);
            goto cleanup;
        }
        
        tx.outputs[i].amount = (uint64_t)amount->valuedouble;
        tx.outputs[i].is_subaddress = cJSON_IsTrue(is_subaddress);
        
        if (!parse_hex_to_bytes(view_pub->valuestring, tx.outputs[i].view_public_key, 32) ||
            !parse_hex_to_bytes(spend_pub->valuestring, tx.outputs[i].spend_public_key, 32)) {
            printf("[Device] ERROR: Invalid public keys for output %zu\n", i);
            goto cleanup;
        }
    }
    
    printf("[Device] Parsed transaction: %zu inputs, %zu outputs, fee=%lu\n", 
           tx.num_inputs, tx.num_outputs, tx.fee);

    // Parse bulletproofs from prunable section
    cJSON* rct_prunable = cJSON_GetObjectItem(rct_sig, "prunable");
    if (!rct_prunable) {
        printf("[Device] ERROR: No prunable section found\n");
        cJSON_Delete(root);
        return 0;
    }

    // Structure to store parsed bulletproof data
    typedef struct {
        size_t bp_count;
        bulletproof_plus_t* bulletproofs_plus;
    } parsed_bulletproofs_t;

    parsed_bulletproofs_t parsed_bp = {0};

    cJSON* bulletproofs_json = cJSON_GetObjectItem(rct_prunable, "bulletproofs");
    if(bulletproofs_json && cJSON_IsArray(bulletproofs_json)) {
        parsed_bp.bp_count = cJSON_GetArraySize(bulletproofs_json);
        parsed_bp.bulletproofs_plus = malloc(parsed_bp.bp_count * sizeof(bulletproof_plus_t));
    
        printf("[Device] Parsing %zu bulletproofs from JSON\n", parsed_bp.bp_count);
    
        for (size_t i = 0; i < parsed_bp.bp_count; i++) {
            cJSON* bp_json = cJSON_GetArrayItem(bulletproofs_json, i);
            bulletproof_plus_t* bp = &parsed_bp.bulletproofs_plus[i];
        
            // Initialize all vectors
            memset(bp, 0, sizeof(bulletproof_plus_t));
        
            // Parse V array
            cJSON* V_json = cJSON_GetObjectItem(bp_json, "V");
            if (V_json && cJSON_IsArray(V_json)) {
                size_t v_count = cJSON_GetArraySize(V_json);
                if (!key_vector_init(&bp->V, v_count)) {
                    printf("[Device] ERROR: Failed to init V vector\n");
                    goto cleanup_bulletproofs;
                }
            
                for (size_t j = 0; j < v_count; j++) {
                    cJSON* v_item = cJSON_GetArrayItem(V_json, j);
                    if (cJSON_IsString(v_item) && strlen(v_item->valuestring) == 64) {
                        hex_to_bytes(v_item->valuestring, bp->V.keys[j].bytes);
                    }
                }
                printf("[Device] Parsed V array with %zu elements\n", v_count);
            }
        
            // Parse A
            cJSON* A_json = cJSON_GetObjectItem(bp_json, "A");
            if (A_json && cJSON_IsString(A_json) && strlen(A_json->valuestring) == 64) {
                hex_to_bytes(A_json->valuestring, bp->A.bytes);
            }
        
            // Parse A1
            cJSON* A1_json = cJSON_GetObjectItem(bp_json, "A1");
            if (A1_json && cJSON_IsString(A1_json) && strlen(A1_json->valuestring) == 64) {
                hex_to_bytes(A1_json->valuestring, bp->A1.bytes);
            }
        
            // Parse B
            cJSON* B_json = cJSON_GetObjectItem(bp_json, "B");
            if (B_json && cJSON_IsString(B_json) && strlen(B_json->valuestring) == 64) {
                hex_to_bytes(B_json->valuestring, bp->B.bytes);
            }
        
            // Parse r1
            cJSON* r1_json = cJSON_GetObjectItem(bp_json, "r1");
            if (r1_json && cJSON_IsString(r1_json) && strlen(r1_json->valuestring) == 64) {
                hex_to_bytes(r1_json->valuestring, bp->r1.bytes);
            }
        
            // Parse s1
            cJSON* s1_json = cJSON_GetObjectItem(bp_json, "s1");
            if (s1_json && cJSON_IsString(s1_json) && strlen(s1_json->valuestring) == 64) {
                hex_to_bytes(s1_json->valuestring, bp->s1.bytes);
            }
        
            // Parse d1
            cJSON* d1_json = cJSON_GetObjectItem(bp_json, "d1");
            if (d1_json && cJSON_IsString(d1_json) && strlen(d1_json->valuestring) == 64) {
                hex_to_bytes(d1_json->valuestring, bp->d1.bytes);
            }
        
            // Parse L array
            cJSON* L_json = cJSON_GetObjectItem(bp_json, "L");
            if (L_json && cJSON_IsArray(L_json)) {
                size_t l_count = cJSON_GetArraySize(L_json);
                if (!key_vector_init(&bp->L, l_count)) {
                    printf("[Device] ERROR: Failed to init L vector\n");
                    goto cleanup_bulletproofs;
                }
            
                for (size_t j = 0; j < l_count; j++) {
                    cJSON* l_item = cJSON_GetArrayItem(L_json, j);
                    if (cJSON_IsString(l_item) && strlen(l_item->valuestring) == 64) {
                        hex_to_bytes(l_item->valuestring, bp->L.keys[j].bytes);
                    }
                }
                printf("[Device] Parsed L array with %zu elements\n", l_count);
            }
        
            // Parse R array
            cJSON* R_json = cJSON_GetObjectItem(bp_json, "R");
            if (R_json && cJSON_IsArray(R_json)) {
                size_t r_count = cJSON_GetArraySize(R_json);
                if (!key_vector_init(&bp->R, r_count)) {
                    printf("[Device] ERROR: Failed to init R vector\n");
                    goto cleanup_bulletproofs;
                }
            
                for (size_t j = 0; j < r_count; j++) {
                    cJSON* r_item = cJSON_GetArrayItem(R_json, j);
                    if (cJSON_IsString(r_item) && strlen(r_item->valuestring) == 64) {
                        hex_to_bytes(r_item->valuestring, bp->R.keys[j].bytes);
                    }
                }
                printf("[Device] Parsed R array with %zu elements\n", r_count);
            }
        }
    
    } else {
        printf("[Device] No bulletproofs found in prunable section\n");
    }
    
    // Allocate arrays dynamically to avoid VLA issues with goto
    uint8_t* key_images = malloc(tx.num_inputs * 32);
    uint8_t* pseudo_outputs = malloc(tx.num_inputs * 32);
    uint8_t* pseudo_masks = malloc(tx.num_inputs * 32);
    uint8_t* output_public_keys = malloc(tx.num_outputs * 32);
    uint8_t* view_tags_array = malloc(tx.num_outputs);
    
    if (!key_images || !pseudo_outputs || !pseudo_masks || !output_public_keys || !view_tags_array) {
        printf("[Device] ERROR: Memory allocation failed\n");
        free(key_images);
        free(pseudo_outputs);
        free(pseudo_masks);
        free(output_public_keys);
        free(view_tags_array);
        goto cleanup_bulletproofs;
    }
    
    // Generate key images using SOURCE transaction Rs
    for (size_t i = 0; i < tx.num_inputs; i++) {
        uint8_t ephemeral_secret[32];
        
        if (!monero_generate_key_image_for_output(
                tx.inputs[i].tx_public_key,
                device_view_key,
                device_spend_key,
                tx.inputs[i].output_index,
                key_images + i * 32,
                ephemeral_secret)) {
            printf("[Device] ERROR: Failed to generate key image for input %zu\n", i);
            free(key_images);
            free(pseudo_outputs);
            free(pseudo_masks);
            free(output_public_keys);
            free(view_tags_array);
            goto cleanup_bulletproofs;
        }
        
        memset(ephemeral_secret, 0, 32);
    }
    
    // Generate output keys using single R
    for (size_t i = 0; i < tx.num_outputs; i++) {
        uint8_t output_public_key[32];
        uint8_t view_tag;
        
        if (!generate_output_keys(i, single_tx_public_key,
                                 tx.outputs[i].view_public_key,
                                 tx.outputs[i].spend_public_key,
                                 output_public_key, &view_tag)) {
            printf("[Device] ERROR: Failed to generate keys for output %zu\n", i);
            free(key_images);
            free(pseudo_outputs);
            free(pseudo_masks);
            free(output_public_keys);
            free(view_tags_array);
            goto cleanup_bulletproofs;
        }
        
        memcpy(output_public_keys + i * 32, output_public_key, 32);
        view_tags_array[i] = view_tag;
        
    }
    
    // Prepare output info for pseudo output generation AND ECDH
    tx_output_info_t* output_info = malloc(tx.num_outputs * sizeof(tx_output_info_t));
    
    for (size_t i = 0; i < tx.num_outputs; i++) {
        output_info[i].amount = tx.outputs[i].amount;
        
        // Generate mask using EXACT same method as host's generate_single_r_mask
        uint8_t derivation[32];
        monero_generate_key_derivation(single_tx_public_key, device_view_key, derivation);

        uint8_t derivation_with_index[36];
        memcpy(derivation_with_index, derivation, 32);
        derivation_with_index[32] = (i >> 24) & 0xFF;
        derivation_with_index[33] = (i >> 16) & 0xFF; 
        derivation_with_index[34] = (i >> 8) & 0xFF;
        derivation_with_index[35] = i & 0xFF;
        
        uint8_t mask_hash[32];
        xmr_fast_hash(mask_hash, derivation_with_index, 36);

        bignum256modm mask_scalar;
        expand256_modm(mask_scalar, mask_hash, 32);
        contract256_modm(output_info[i].mask, mask_scalar);
    }
    
    // Generate pseudo outputs
    uint64_t* input_amounts = malloc(tx.num_inputs * sizeof(uint64_t));
    for (size_t i = 0; i < tx.num_inputs; i++) {
        input_amounts[i] = tx.inputs[i].amount;
    }
    
    uint8_t (*pseudo_outputs_2d)[32] = (uint8_t (*)[32])pseudo_outputs;
    uint8_t (*pseudo_masks_2d)[32] = (uint8_t (*)[32])pseudo_masks;
    
    if (!generate_pseudo_outputs(input_amounts, tx.num_inputs, 
                                output_info, tx.num_outputs, 
                                tx.fee, pseudo_outputs_2d, pseudo_masks_2d)) {
        printf("[Device] ERROR: Failed to generate pseudo outputs\n");
        free(output_info);
        free(input_amounts);
        free(key_images);
        free(pseudo_outputs);
        free(pseudo_masks);
        free(output_public_keys);
        free(view_tags_array);
        goto cleanup_bulletproofs;
    }
    
    free(input_amounts);
    
    // Generate device-side ECDH info
    ecdh_tuple_t* ecdh_info = malloc(tx.num_outputs * sizeof(ecdh_tuple_t));
    if (!ecdh_info) {
        printf("[Device] ERROR: Failed to allocate ECDH info\n");
        free(output_info);
        free(key_images);
        free(pseudo_outputs);
        free(pseudo_masks);
        free(output_public_keys);
        free(view_tags_array);
        goto cleanup_bulletproofs;
    }
    
    if (!generate_device_ecdh_info(tx.num_outputs, output_info, single_tx_public_key, ecdh_info)) {
        printf("[Device] ERROR: Failed to generate ECDH info\n");
        free(ecdh_info);
        free(output_info);
        free(key_images);
        free(pseudo_outputs);
        free(pseudo_masks);
        free(output_public_keys);
        free(view_tags_array);
        goto cleanup_bulletproofs;
    }
    
    // Build transaction prefix
    transaction_prefix_t tx_prefix;
    tx_prefix_init(&tx_prefix);
    
    cJSON* version = cJSON_GetObjectItem(tx_prefix_json, "version");
    cJSON* unlock_time = cJSON_GetObjectItem(tx_prefix_json, "unlock_time");
    
    tx_prefix.version = version ? (uint64_t)version->valuedouble : 2;
    tx_prefix.unlock_time = unlock_time ? (uint64_t)unlock_time->valuedouble : 0;
    tx_prefix.vin_count = tx.num_inputs;
    tx_prefix.vout_count = tx.num_outputs;
    
    // Build inputs
    cJSON* inputs_json = cJSON_GetObjectItem(tx_prefix_json, "inputs");
    tx_prefix.vin = malloc(tx.num_inputs * sizeof(txin_v_t));
    
    for (size_t i = 0; i < tx.num_inputs; i++) {
        cJSON* input_json = cJSON_GetArrayItem(inputs_json, i);
        cJSON* key_offsets_json = cJSON_GetObjectItem(input_json, "key_offsets");
        size_t key_offsets_count = cJSON_GetArraySize(key_offsets_json);
        uint64_t* key_offsets = malloc(key_offsets_count * sizeof(uint64_t));
        
        for (size_t j = 0; j < key_offsets_count; j++) {
            cJSON* offset = cJSON_GetArrayItem(key_offsets_json, j);
            uint64_t absolute_offset = (uint64_t)offset->valuedouble;
            
            if (j == 0) {
                key_offsets[j] = absolute_offset;
            } else {
                cJSON* prev_offset = cJSON_GetArrayItem(key_offsets_json, j-1);
                uint64_t prev_absolute = (uint64_t)prev_offset->valuedouble;
                key_offsets[j] = absolute_offset - prev_absolute;
            }
        }
        
        cJSON* amount = cJSON_GetObjectItem(input_json, "amount");
        uint64_t input_amount = amount ? (uint64_t)amount->valuedouble : 0;
        
        tx_create_txin_to_key(&tx_prefix.vin[i], input_amount, key_offsets, 
                             key_offsets_count, key_images + i * 32);
    }
    
    // Build outputs
    tx_prefix.vout = malloc(tx.num_outputs * sizeof(tx_out_t));
    for (size_t i = 0; i < tx.num_outputs; i++) {
        tx_create_txout_to_tagged_key(&tx_prefix.vout[i], 0, 
                                     output_public_keys + i * 32, view_tags_array[i]);
    }
    
    // Build extra field with single R
    tx_prefix.extra_len = 33;
    tx_prefix.extra = malloc(33);
    tx_prefix.extra[0] = 0x01;
    memcpy(tx_prefix.extra + 1, single_tx_public_key, 32);
    
    // Build complete RCT signature structure for full transaction hash
    rct_sig_t rct_sig_full;
    rct_sig_init(&rct_sig_full);

    // Set RCT type and fee
    rct_sig_full.base.type = RCT_TYPE_BULLETPROOF_PLUS;
    rct_sig_full.base.txn_fee = tx.fee;

    // Initialize output commitments
    if (!ctkey_vector_init(&rct_sig_full.base.out_pk, tx.num_outputs)) {
        printf("[Device] ERROR: Failed to initialize output commitments\n");
        goto cleanup_rct;
    }

    // Generate output commitments using existing output_info masks
    for (size_t j = 0; j < tx.num_outputs; j++) {  // Use j, not i
        bignum256modm mask_scalar;
        expand256_modm(mask_scalar, output_info[j].mask, 32);
    
        ge25519 commitment;
        xmr_gen_c(&commitment, mask_scalar, output_info[j].amount);
        ge25519_pack(rct_sig_full.base.out_pk.keys[j].mask.bytes, &commitment);
    
        memset(rct_sig_full.base.out_pk.keys[j].dest.bytes, 0, 32);
    }

    // Initialize ECDH info
    if (!ecdh_info_vector_init(&rct_sig_full.base.ecdh_info, tx.num_outputs)) {
        printf("[Device] ERROR: Failed to initialize ECDH info\n");
        goto cleanup_rct;
    }

    for (size_t j = 0; j < tx.num_outputs; j++) {  // Use j, not i
        memcpy(rct_sig_full.base.ecdh_info.tuples[j].amount, ecdh_info[j].amount, 32);
        memcpy(rct_sig_full.base.ecdh_info.tuples[j].mask, ecdh_info[j].mask, 32);
    }

    // Initialize pseudo outputs
    if (!key_vector_init(&rct_sig_full.prunable.pseudo_outs, tx.num_inputs)) {
        printf("[Device] ERROR: Failed to initialize pseudo outputs\n");
        goto cleanup_rct;
    }

    for (size_t j = 0; j < tx.num_inputs; j++) {  // Use j, not i
        memcpy(rct_sig_full.prunable.pseudo_outs.keys[j].bytes, pseudo_outputs + j * 32, 32);
    }

    // Use parsed bulletproof data
    if (parsed_bp.bp_count > 0) {
        rct_sig_full.prunable.bulletproofs_plus_count = parsed_bp.bp_count;
        rct_sig_full.prunable.bulletproofs_plus = parsed_bp.bulletproofs_plus;
        printf("[Device] Using %zu parsed bulletproofs in RCT structure\n", parsed_bp.bp_count);
    } else {
        rct_sig_full.prunable.bulletproofs_plus_count = 0;
        rct_sig_full.prunable.bulletproofs_plus = NULL;
    }

    // Zero out other bulletproof types
    rct_sig_full.prunable.bulletproofs_count = 0;
    rct_sig_full.prunable.bulletproofs = NULL;
    rct_sig_full.prunable.range_sigs_count = 0;
    rct_sig_full.prunable.range_sigs = NULL;
    rct_sig_full.prunable.MGs_count = 0;
    rct_sig_full.prunable.MGs = NULL;
    rct_sig_full.prunable.CLSAGs_count = 0;
    rct_sig_full.prunable.CLSAGs = NULL;

    // Compute transaction prefix hash for export
    uint8_t transaction_prefix_hash[32];
    if (!monero_get_transaction_prefix_hash(&tx_prefix, transaction_prefix_hash)) {
        printf("[Device] ERROR: Failed to compute transaction prefix hash\n");
        goto cleanup_rct;
    }
   
    // Compute FULL transaction hash for signing
    uint8_t full_transaction_hash[32];
    if (!monero_get_transaction_hash(&tx_prefix, &rct_sig_full, full_transaction_hash)) {
        printf("[Device] ERROR: Failed to compute full transaction hash\n");
        goto cleanup_rct;
    }
    
    // Generate CLSAG signatures
    clsag_signature_t* signatures = malloc(tx.num_inputs * sizeof(clsag_signature_t));

    for (size_t i = 0; i < tx.num_inputs; i++) {
        signatures[i].s = malloc(tx.inputs[i].ring_size * 32);
        signatures[i].ring_size = tx.inputs[i].ring_size;
    
        uint8_t ephemeral_secret[32];
        uint8_t temp_key_image[32];
    
        if (!monero_generate_key_image_for_output(
                tx.inputs[i].tx_public_key, 
                device_view_key, 
                device_spend_key, 
                tx.inputs[i].output_index, 
                temp_key_image, 
                ephemeral_secret)) {
            printf("[Device] ERROR: Failed to generate ephemeral secret for input %zu\n", i);
            goto cleanup_signatures;
        }

        clsag_params_t params;
        memcpy(params.message, full_transaction_hash, 32);  // Use FULL hash!
        params.ring = tx.inputs[i].ring;
        params.ring_size = tx.inputs[i].ring_size;
        memcpy(params.p, ephemeral_secret, 32);
        memcpy(params.z, pseudo_masks + i * 32, 32);
        memcpy(params.C_offset, pseudo_outputs + i * 32, 32);
        params.l = tx.inputs[i].real_index;
    
        if (!clsag_sign(&params, &signatures[i])) {
            printf("[Device] ERROR: CLSAG signing failed for input %zu\n", i);
            memset(ephemeral_secret, 0, 32);
            goto cleanup_signatures;
        }
    
        memset(ephemeral_secret, 0, 32);
        memset(&params, 0, sizeof(params));
    
    }
    
    // Create output JSON
    cJSON* output_root = cJSON_CreateObject();
    cJSON* signed_data = cJSON_CreateObject();
    cJSON_AddItemToObject(output_root, "signed_transaction_data", signed_data);
    
    // Export transaction prefix hash (for host compatibility)
    char hash_hex[65];
    for (int j = 0; j < 32; j++) {
        sprintf(hash_hex + j*2, "%02x", transaction_prefix_hash[j]);
    }
    cJSON_AddItemToObject(signed_data, "transaction_prefix_hash", cJSON_CreateString(hash_hex));
    printf("[Device] Exported transaction prefix hash: %s\n", hash_hex);
    
    // Add key images
    cJSON* key_images_array = cJSON_CreateArray();
    for (size_t i = 0; i < tx.num_inputs; i++) {
        char hex_str[65];
        for (int j = 0; j < 32; j++) {
            sprintf(hex_str + j*2, "%02x", key_images[i * 32 + j]);
        }
        cJSON_AddItemToArray(key_images_array, cJSON_CreateString(hex_str));
    }
    cJSON_AddItemToObject(signed_data, "key_images", key_images_array);
    
    // Add CLSAG signatures
    cJSON* clsag_signatures_array = cJSON_CreateArray();
    for (size_t i = 0; i < tx.num_inputs; i++) {
        cJSON* sig_obj = cJSON_CreateObject();
        
        char hex_str[65];
        for (int j = 0; j < 32; j++) {
            sprintf(hex_str + j*2, "%02x", signatures[i].c1[j]);
        }
        cJSON_AddItemToObject(sig_obj, "c1", cJSON_CreateString(hex_str));
        
        for (int j = 0; j < 32; j++) {
            sprintf(hex_str + j*2, "%02x", signatures[i].D[j]);
        }
        cJSON_AddItemToObject(sig_obj, "D", cJSON_CreateString(hex_str));
        
        cJSON* s_array = cJSON_CreateArray();
        for (size_t k = 0; k < signatures[i].ring_size; k++) {
            for (int j = 0; j < 32; j++) {
                sprintf(hex_str + j*2, "%02x", signatures[i].s[k*32 + j]);
            }
            cJSON_AddItemToArray(s_array, cJSON_CreateString(hex_str));
        }
        cJSON_AddItemToObject(sig_obj, "s", s_array);
        
        cJSON_AddItemToArray(clsag_signatures_array, sig_obj);
    }
    cJSON_AddItemToObject(signed_data, "clsag_signatures", clsag_signatures_array);
    
    // Add pseudo outputs
    cJSON* pseudo_outs_array = cJSON_CreateArray();
    for (size_t i = 0; i < tx.num_inputs; i++) {
        char hex_str[65];
        for (int j = 0; j < 32; j++) {
            sprintf(hex_str + j*2, "%02x", pseudo_outputs[i * 32 + j]);
        }
        cJSON_AddItemToArray(pseudo_outs_array, cJSON_CreateString(hex_str));
    }
    cJSON_AddItemToObject(signed_data, "pseudo_outputs", pseudo_outs_array);
    
    // Add one-time keys
    cJSON* one_time_keys_array = cJSON_CreateArray();
    for (size_t i = 0; i < tx.num_outputs; i++) {
        char hex_str[65];
        for (int j = 0; j < 32; j++) {
            sprintf(hex_str + j*2, "%02x", output_public_keys[i * 32 + j]);
        }
        cJSON_AddItemToArray(one_time_keys_array, cJSON_CreateString(hex_str));
    }
    cJSON_AddItemToObject(signed_data, "one_time_keys", one_time_keys_array);
    
    // Add view tags
    cJSON* view_tags_json_array = cJSON_CreateArray();
    for (size_t i = 0; i < tx.num_outputs; i++) {
        char hex_str[3];
        sprintf(hex_str, "%02x", view_tags_array[i]);
        cJSON_AddItemToArray(view_tags_json_array, cJSON_CreateString(hex_str));
    }
    cJSON_AddItemToObject(signed_data, "view_tags", view_tags_json_array);
    
    // Export output masks for verification
    cJSON* output_masks_array = cJSON_CreateArray();
    for (size_t i = 0; i < tx.num_outputs; i++) {
        char hex_str[65];
        for (int j = 0; j < 32; j++) {
            sprintf(hex_str + j*2, "%02x", output_info[i].mask[j]);
        }
        cJSON_AddItemToArray(output_masks_array, cJSON_CreateString(hex_str));
    }
    cJSON_AddItemToObject(signed_data, "output_masks", output_masks_array);
    
    // Export device-computed ECDH info
    cJSON* ecdh_info_array = cJSON_CreateArray();
    for (size_t i = 0; i < tx.num_outputs; i++) {
        cJSON* ecdh_obj = cJSON_CreateObject();
        
        // Export encoded amount (32 bytes)
        char amount_hex[65];
        for (int j = 0; j < 32; j++) {
            sprintf(amount_hex + j*2, "%02x", ecdh_info[i].amount[j]);
        }
        cJSON_AddItemToObject(ecdh_obj, "amount", cJSON_CreateString(amount_hex));
        
        // Export encoded mask (32 bytes)
        char mask_hex[65];
        for (int j = 0; j < 32; j++) {
            sprintf(mask_hex + j*2, "%02x", ecdh_info[i].mask[j]);
        }
        cJSON_AddItemToObject(ecdh_obj, "mask", cJSON_CreateString(mask_hex));
        
        cJSON_AddItemToArray(ecdh_info_array, ecdh_obj);
    }
    cJSON_AddItemToObject(signed_data, "ecdh_info", ecdh_info_array);
    
    printf("[Device] Exported device-computed ECDH info for %zu outputs\n", tx.num_outputs);
    
    // Write output file
    char* json_string = cJSON_Print(output_root);
    FILE* output_file = fopen(output_json_path, "w");
    if (output_file) {
        fprintf(output_file, "%s", json_string);
        fclose(output_file);
        printf("[Device] Signed transaction data written to: %s\n", output_json_path);
    } else {
        printf("[Device] ERROR: Failed to write output file\n");
    }
    
    free(json_string);
    cJSON_Delete(output_root);
    
    // Free allocated memory in success path
    free(ecdh_info);
    free(output_info);
    free(key_images);
    free(pseudo_outputs);
    free(pseudo_masks);
    free(output_public_keys);
    free(view_tags_array);
    tx_prefix_free(&tx_prefix);

    // Free signatures
    for (size_t i = 0; i < tx.num_inputs; i++) {
        if (signatures[i].s) free(signatures[i].s);
    }
    free(signatures);

    // CRITICAL: Prevent double-free by nullifying shared pointer
    rct_sig_full.prunable.bulletproofs_plus = NULL;
    rct_sig_full.prunable.bulletproofs_plus_count = 0;
    rct_sig_free(&rct_sig_full);

    // Free parsed bulletproofs
    if (parsed_bp.bulletproofs_plus) {
        for (size_t i = 0; i < parsed_bp.bp_count; i++) {
            key_vector_free(&parsed_bp.bulletproofs_plus[i].V);
            key_vector_free(&parsed_bp.bulletproofs_plus[i].L);
            key_vector_free(&parsed_bp.bulletproofs_plus[i].R);
        }
        free(parsed_bp.bulletproofs_plus);
    }

    // Free transaction data
    if (tx.inputs) {
        for (size_t i = 0; i < tx.num_inputs; i++) {
            if (tx.inputs[i].ring) free(tx.inputs[i].ring);
        }
        free(tx.inputs);
    }
    if (tx.outputs) free(tx.outputs);
    
    cJSON_Delete(root);
    
    printf("[Device] Transaction processing complete\n");
    return 1;

    // Error cleanup paths
cleanup_signatures:
    if (signatures) {
        for (size_t i = 0; i < tx.num_inputs; i++) {
            if (signatures[i].s) free(signatures[i].s);
        }
        free(signatures);
    }

cleanup_rct:
    // CRITICAL: Prevent double-free
    rct_sig_full.prunable.bulletproofs_plus = NULL;
    rct_sig_full.prunable.bulletproofs_plus_count = 0;
    rct_sig_free(&rct_sig_full);

cleanup_bulletproofs:
    if (parsed_bp.bulletproofs_plus) {
        for (size_t i = 0; i < parsed_bp.bp_count; i++) {
            key_vector_free(&parsed_bp.bulletproofs_plus[i].V);
            key_vector_free(&parsed_bp.bulletproofs_plus[i].L);
            key_vector_free(&parsed_bp.bulletproofs_plus[i].R);
        }
        free(parsed_bp.bulletproofs_plus);
    }

cleanup:
    // Free transaction data
    if (tx.inputs) {
        for (size_t i = 0; i < tx.num_inputs; i++) {
            if (tx.inputs[i].ring) free(tx.inputs[i].ring);
        }
        free(tx.inputs);
    }
    if (tx.outputs) free(tx.outputs);
    
    cJSON_Delete(root);
    
    printf("[Device] Transaction processing complete\n");
    return 1;
}

// Example usage
int device_pipeline(void) {
    const char* seed_hex = "887957b85b1e3529473437ff466c37ef59427a42ec20b296dc00db53f2857602";
    
    if (!device_init_wallet(seed_hex)) {
        printf("[Device] Failed to initialize wallet\n");
        return 0;
    }
    
    const char* input_path = "../transaction_data.json";
    const char* output_path = "../../Monero_PoC/monero/build/bin/signed_transaction_data.json";
    
    return device_process_transaction(input_path, output_path);
}