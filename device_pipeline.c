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

// Generate output keys using single transaction R
static int generate_output_keys(uint32_t output_index, const uint8_t single_tx_public_key[32],
                               const uint8_t view_public_key[32], const uint8_t spend_public_key[32],
                               uint8_t output_public_key[32], uint8_t* view_tag) {
    
    // Generate key derivation using single R
    uint8_t derivation[32];
    if (!monero_generate_key_derivation(single_tx_public_key, view_public_key, derivation)) {
        return 0;
    }
    
    // Derive output public key
    if (!monero_derive_public_key(derivation, output_index, spend_public_key, output_public_key)) {
        return 0;
    }
    
    // Generate view tag using CORRECT 36-byte input (derivation + 4-byte index)
    uint8_t view_tag_data[36];
    memcpy(view_tag_data, derivation, 32);
    // Add 4-byte little-endian index (matching Monero standard)
    view_tag_data[32] = (output_index) & 0xFF;
    view_tag_data[33] = (output_index >> 8) & 0xFF;
    view_tag_data[34] = (output_index >> 16) & 0xFF;
    view_tag_data[35] = (output_index >> 24) & 0xFF;
    
    uint8_t view_tag_hash[32];
    keccak_256(view_tag_data, 36, view_tag_hash);  // 36 bytes, not 33
    *view_tag = view_tag_hash[0];
    
    return 1;
}

// Main transaction processing pipeline
int device_process_transaction(const char* input_json_path, const char* output_json_path) {
    printf("[Device] Starting transaction processing pipeline\n");
    
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
    
    // 4. Allocate arrays dynamically to avoid VLA issues with goto
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
        goto cleanup;
    }
    
    // 5. Generate key images using SOURCE transaction Rs
    for (size_t i = 0; i < tx.num_inputs; i++) {
        uint8_t ephemeral_secret[32];
        
        // Use SOURCE transaction R for key image generation
        if (!monero_generate_key_image_for_output(
                tx.inputs[i].tx_public_key,  // Source R, not single R
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
            goto cleanup;
        }
        
        // Clear sensitive data
        memset(ephemeral_secret, 0, 32);
        
        printf("[Device] Generated key image for input %zu\n", i);
    }
    
    // 6. Generate output keys using single R
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
            goto cleanup;
        }
        
        // Store for transaction prefix building
        memcpy(output_public_keys + i * 32, output_public_key, 32);
        view_tags_array[i] = view_tag;
        
        printf("[Device] Generated output key for output %zu\n", i);
    }
    
    // 7. Prepare output info for pseudo output generation
    tx_output_info_t* output_info = malloc(tx.num_outputs * sizeof(tx_output_info_t));
    
    for (size_t i = 0; i < tx.num_outputs; i++) {
        output_info[i].amount = tx.outputs[i].amount;
        
        // Generate mask using EXACT same method as host's generate_single_r_mask
        uint8_t derivation[32];
        monero_generate_key_derivation(single_tx_public_key, device_view_key, derivation);
        
        // Match host exactly: derivation + 4-byte index, then hash and reduce
        uint8_t derivation_with_index[36];
        memcpy(derivation_with_index, derivation, 32);
        derivation_with_index[32] = (i >> 24) & 0xFF;
        derivation_with_index[33] = (i >> 16) & 0xFF; 
        derivation_with_index[34] = (i >> 8) & 0xFF;
        derivation_with_index[35] = i & 0xFF;
        
        // Hash to get final mask (matching host's crypto::cn_fast_hash)
        uint8_t mask_hash[32];
        keccak_256(derivation_with_index, 36, mask_hash);
        
        // Reduce to scalar (matching host's sc_reduce32)
        bignum256modm mask_scalar;
        expand256_modm(mask_scalar, mask_hash, 32);
        contract256_modm(output_info[i].mask, mask_scalar);
    }
    
    // Extract input amounts
    uint64_t* input_amounts = malloc(tx.num_inputs * sizeof(uint64_t));
    for (size_t i = 0; i < tx.num_inputs; i++) {
        input_amounts[i] = tx.inputs[i].amount;
    }
    
    // Generate pseudo outputs using helper arrays
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
        goto cleanup;
    }
    
    free(input_amounts);
    
    printf("[Device] Generated pseudo outputs\n");
    
    // 8. *** CRITICAL: Build transaction prefix with REAL values ***
    transaction_prefix_t tx_prefix;
    tx_prefix_init(&tx_prefix);
    
    // Parse version and unlock_time from JSON
    cJSON* version = cJSON_GetObjectItem(tx_prefix_json, "version");
    cJSON* unlock_time = cJSON_GetObjectItem(tx_prefix_json, "unlock_time");
    
    tx_prefix.version = version ? (uint64_t)version->valuedouble : 2;
    tx_prefix.unlock_time = unlock_time ? (uint64_t)unlock_time->valuedouble : 0;
    tx_prefix.vin_count = tx.num_inputs;
    tx_prefix.vout_count = tx.num_outputs;
    
    // Build inputs with REAL key images
    cJSON* inputs_json = cJSON_GetObjectItem(tx_prefix_json, "inputs");
    tx_prefix.vin = malloc(tx.num_inputs * sizeof(txin_v_t));
    
    for (size_t i = 0; i < tx.num_inputs; i++) {
        cJSON* input_json = cJSON_GetArrayItem(inputs_json, i);
        
        // Parse key_offsets
        cJSON* key_offsets_json = cJSON_GetObjectItem(input_json, "key_offsets");
        size_t key_offsets_count = cJSON_GetArraySize(key_offsets_json);
        uint64_t* key_offsets = malloc(key_offsets_count * sizeof(uint64_t));
        
        for (size_t j = 0; j < key_offsets_count; j++) {
             cJSON* offset = cJSON_GetArrayItem(key_offsets_json, j);
              uint64_t absolute_offset = (uint64_t)offset->valuedouble;
    
              if (j == 0) {
                     key_offsets[j] = absolute_offset;  // First remains absolute
                } else {
            // Convert to relative: current - previous absolute
           cJSON* prev_offset = cJSON_GetArrayItem(key_offsets_json, j-1);
          uint64_t prev_absolute = (uint64_t)prev_offset->valuedouble;
         key_offsets[j] = absolute_offset - prev_absolute;
        }
    }
        
        cJSON* amount = cJSON_GetObjectItem(input_json, "amount");
        uint64_t input_amount = amount ? (uint64_t)amount->valuedouble : 0;
        
        // Use REAL key image generated above
        tx_create_txin_to_key(&tx_prefix.vin[i], input_amount, key_offsets, 
                             key_offsets_count, key_images + i * 32);
    }
    
    // Build outputs with REAL output keys and view tags
    tx_prefix.vout = malloc(tx.num_outputs * sizeof(tx_out_t));
    
    for (size_t i = 0; i < tx.num_outputs; i++) {
        // Use REAL output keys and view tags generated above
        tx_create_txout_to_tagged_key(&tx_prefix.vout[i], 0, 
                                     output_public_keys + i * 32, view_tags_array[i]);
    }
    
    // Set extra data (use ONLY single R - 33 bytes total)
    tx_prefix.extra_len = 33;  // 1 byte tag + 32 bytes single R
    tx_prefix.extra = malloc(33);
    tx_prefix.extra[0] = 0x01;  // TX_EXTRA_TAG_PUBKEY
    memcpy(tx_prefix.extra + 1, single_tx_public_key, 32);
    
    // 9. *** CRITICAL: Compute transaction prefix hash from REAL transaction structure ***
    uint8_t transaction_prefix_hash[32];
    if (!monero_get_transaction_prefix_hash(&tx_prefix, transaction_prefix_hash)) {
        printf("[Device] ERROR: Failed to compute transaction prefix hash\n");
        free(output_info);
        free(key_images);
        free(pseudo_outputs);
        free(pseudo_masks);
        free(output_public_keys);
        free(view_tags_array);
        tx_prefix_free(&tx_prefix);
        goto cleanup;
    }
    
    printf("[Device] Transaction prefix hash computed from REAL transaction structure\n");
    // === DEBUG: Show device transaction structure ===
printf("[Device] === DEVICE TRANSACTION STRUCTURE DEBUG ===\n");
printf("[Device] Version: %lu\n", tx_prefix.version);
printf("[Device] Unlock time: %lu\n", tx_prefix.unlock_time);
printf("[Device] Inputs count: %zu\n", tx_prefix.vin_count);

for (size_t i = 0; i < tx_prefix.vin_count; i++) {
    if (tx_prefix.vin[i].type == TXIN_TO_KEY) {
        printf("[Device] Input %zu:\n", i);
        printf("[Device]   Amount: %lu\n", tx_prefix.vin[i].variant.to_key.amount);
        printf("[Device]   Key offsets count: %zu\n", tx_prefix.vin[i].variant.to_key.key_offsets_count);
        printf("[Device]   Key offsets: ");
        for (size_t j = 0; j < 5 && j < tx_prefix.vin[i].variant.to_key.key_offsets_count; j++) {
            printf("%lu", tx_prefix.vin[i].variant.to_key.key_offsets[j]);
            if (j < tx_prefix.vin[i].variant.to_key.key_offsets_count - 1) printf(", ");
        }
        printf("...\n");
        printf("[Device]   Key image: ");
        for (int k = 0; k < 32; k++) {
            printf("%02x", tx_prefix.vin[i].variant.to_key.k_image[k]);
        }
        printf("\n");
    }
}

printf("[Device] Outputs count: %zu\n", tx_prefix.vout_count);
for (size_t i = 0; i < tx_prefix.vout_count; i++) {
    printf("[Device] Output %zu:\n", i);
    printf("[Device]   Amount: %lu\n", tx_prefix.vout[i].amount);
    if (tx_prefix.vout[i].target.type == TXOUT_TO_TAGGED_KEY) {
        printf("[Device]   Key: ");
        for (int k = 0; k < 32; k++) {
            printf("%02x", tx_prefix.vout[i].target.variant.to_tagged_key.key[k]);
        }
        printf("\n");
        printf("[Device]   View tag: %02x\n", tx_prefix.vout[i].target.variant.to_tagged_key.view_tag[0]);
    }
}

printf("[Device] Extra field length: %zu\n", tx_prefix.extra_len);
printf("[Device] Extra field (first 10 bytes): ");
for (size_t i = 0; i < 10 && i < tx_prefix.extra_len; i++) {
    printf("%02x ", tx_prefix.extra[i]);
}
printf("\n");
printf("[Device] === END DEVICE TRANSACTION DEBUG ===\n");
    
    // 10. Sign each input with CLSAG using the REAL transaction hash
    clsag_signature_t* signatures = malloc(tx.num_inputs * sizeof(clsag_signature_t));
    
    for (size_t i = 0; i < tx.num_inputs; i++) {
        // Allocate signature scalars
        signatures[i].s = malloc(tx.inputs[i].ring_size * 32);
        signatures[i].ring_size = tx.inputs[i].ring_size;
        
        // Generate ephemeral secret key using SOURCE transaction R
        uint8_t ephemeral_secret[32];
        uint8_t temp_key_image[32];
        
        if (!monero_generate_key_image_for_output(
                tx.inputs[i].tx_public_key,  // Source R
                device_view_key,
                device_spend_key,
                tx.inputs[i].output_index,
                temp_key_image,
                ephemeral_secret)) {
            printf("[Device] ERROR: Failed to generate ephemeral secret for input %zu\n", i);
            goto cleanup_signatures;
        }
        
        // Set up CLSAG parameters
        clsag_params_t params;
        memcpy(params.message, transaction_prefix_hash, 32);  // Use REAL hash
        params.ring = tx.inputs[i].ring;
        params.ring_size = tx.inputs[i].ring_size;
        memcpy(params.p, ephemeral_secret, 32);
        memcpy(params.z, pseudo_masks + i * 32, 32);
        memcpy(params.C_offset, pseudo_outputs + i * 32, 32);
        params.l = tx.inputs[i].real_index;
        
        // Sign with CLSAG
        if (!clsag_sign(&params, &signatures[i])) {
            printf("[Device] ERROR: CLSAG signing failed for input %zu\n", i);
            memset(ephemeral_secret, 0, 32);
            goto cleanup_signatures;
        }
        
        // Clear sensitive data
        memset(ephemeral_secret, 0, 32);
        memset(&params, 0, sizeof(params));
        
        printf("[Device] CLSAG signature generated for input %zu\n", i);
    }
    
    // 11. Create output JSON with REAL transaction prefix hash
    cJSON* output_root = cJSON_CreateObject();
    cJSON* signed_data = cJSON_CreateObject();
    cJSON_AddItemToObject(output_root, "signed_transaction_data", signed_data);
    
    // *** CRITICAL: Export transaction prefix hash ***
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
        
        // c1
        char hex_str[65];
        for (int j = 0; j < 32; j++) {
            sprintf(hex_str + j*2, "%02x", signatures[i].c1[j]);
        }
        cJSON_AddItemToObject(sig_obj, "c1", cJSON_CreateString(hex_str));
        
        // D
        for (int j = 0; j < 32; j++) {
            sprintf(hex_str + j*2, "%02x", signatures[i].D[j]);
        }
        cJSON_AddItemToObject(sig_obj, "D", cJSON_CreateString(hex_str));
        
        // s vector
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
    
    // Add one-time keys (CRITICAL for host reconstruction)
    cJSON* one_time_keys_array = cJSON_CreateArray();
    for (size_t i = 0; i < tx.num_outputs; i++) {
        char hex_str[65];
        for (int j = 0; j < 32; j++) {
            sprintf(hex_str + j*2, "%02x", output_public_keys[i * 32 + j]);
        }
        cJSON_AddItemToArray(one_time_keys_array, cJSON_CreateString(hex_str));
    }
    cJSON_AddItemToObject(signed_data, "one_time_keys", one_time_keys_array);
    
    // Add view tags (CRITICAL for host reconstruction)
    cJSON* view_tags_json_array = cJSON_CreateArray();
    for (size_t i = 0; i < tx.num_outputs; i++) {
        char hex_str[3];
        sprintf(hex_str, "%02x", view_tags_array[i]);
        cJSON_AddItemToArray(view_tags_json_array, cJSON_CreateString(hex_str));
    }
    cJSON_AddItemToObject(signed_data, "view_tags", view_tags_json_array);
    
    // Export output masks for verification (optional)
    cJSON* output_masks_array = cJSON_CreateArray();
    for (size_t i = 0; i < tx.num_outputs; i++) {
        char hex_str[65];
        for (int j = 0; j < 32; j++) {
            sprintf(hex_str + j*2, "%02x", output_info[i].mask[j]);
        }
        cJSON_AddItemToArray(output_masks_array, cJSON_CreateString(hex_str));
    }
    cJSON_AddItemToObject(signed_data, "output_masks", output_masks_array);
    
    // Write output file
    char* json_string = cJSON_Print(output_root);
    FILE* output_file = fopen(output_json_path, "w");
    if (output_file) {
        fprintf(output_file, "%s", json_string);
        fclose(output_file);
        printf("[Device] Signed transaction data written to: %s\n", output_json_path);
        printf("[Device] Transaction signatures ready for broadcast\n");
    } else {
        printf("[Device] ERROR: Failed to write output file\n");
    }
    
    free(json_string);
    cJSON_Delete(output_root);
    
    // Free dynamic arrays
    free(output_info);
    free(key_images);
    free(pseudo_outputs);
    free(pseudo_masks);
    free(output_public_keys);
    free(view_tags_array);
    tx_prefix_free(&tx_prefix);
    
    // Cleanup signatures
cleanup_signatures:
    for (size_t i = 0; i < tx.num_inputs; i++) {
        if (signatures[i].s) free(signatures[i].s);
    }
    free(signatures);
    
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
int device_pipeline_example(void) {
    const char* seed_hex = "887957b85b1e3529473437ff466c37ef59427a42ec20b296dc00db53f2857602";
    
    if (!device_init_wallet(seed_hex)) {
        printf("[Device] Failed to initialize wallet\n");
        return 0;
    }
    
    const char* input_path = "../transaction_data.json";
    const char* output_path = "../../Monero_PoC/monero/build/bin/signed_transaction_data.json";
    
    return device_process_transaction(input_path, output_path);
}