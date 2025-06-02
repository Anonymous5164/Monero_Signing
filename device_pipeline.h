#ifndef DEVICE_PIPELINE_H
#define DEVICE_PIPELINE_H

#include <stdint.h>
#include <stddef.h>
#include "clsag.h"

#ifdef __cplusplus
extern "C" {
#endif

// Device-side input structure
typedef struct {
    ring_member_t* ring;        // Ring members (dest + mask pairs)
    size_t ring_size;           // Number of ring members
    uint32_t real_index;        // Index of real output in ring
    uint64_t amount;            // Input amount
    uint8_t tx_public_key[32];  // SOURCE transaction public key (not single R)
    uint32_t output_index;      // Output index in source transaction
} device_input_t;

// Device-side output structure  
typedef struct {
    uint64_t amount;            // Output amount
    int is_subaddress;          // Whether output is to subaddress
    uint8_t view_public_key[32]; // Recipient view public key
    uint8_t spend_public_key[32]; // Recipient spend public key
} device_output_t;

// Complete transaction structure for device processing
typedef struct {
    device_input_t* inputs;     // Array of inputs
    size_t num_inputs;          // Number of inputs
    device_output_t* outputs;   // Array of outputs
    size_t num_outputs;         // Number of outputs
    uint64_t fee;               // Transaction fee
} device_transaction_t;

/**
 * Initialize device wallet with seed
 * Sets up internal spend and view keys for signing
 * 
 * @param seed_hex - Hex string of wallet seed (64 characters)
 * @return 1 on success, 0 on failure
 */
int device_init_wallet(const char* seed_hex);

/**
 * Main device transaction processing pipeline
 * 
 * This function performs the complete signing process:
 * 1. Parses JSON transaction data from host
 * 2. Extracts single transaction R from extra field
 * 3. Generates key images using SOURCE transaction Rs for each input
 * 4. Generates pseudo outputs for transaction balance
 * 5. Builds complete transaction prefix and RCT structures
 * 6. Computes transaction hash from built structures
 * 7. Signs each input with CLSAG using computed transaction hash
 * 8. Outputs production-ready signatures in JSON format
 * 
 * Key behaviors:
 * - Uses SOURCE transaction R for input key image generation
 * - Uses SINGLE transaction R for output derivation
 * - Generates real cryptographic signatures (no stubs/dummies)
 * - Validates ring signatures and transaction structure
 * - Produces broadcastable transaction signatures
 * 
 * @param input_json_path - Path to transaction data JSON from host
 * @param output_json_path - Path to write signed transaction JSON
 * @return 1 on success, 0 on failure
 */
int device_process_transaction(const char* input_json_path, const char* output_json_path);

/**
 * Example usage function
 * Demonstrates complete pipeline with hardcoded seed and paths
 * 
 * @return 1 on success, 0 on failure
 */
int device_pipeline_example(void);

#ifdef __cplusplus
}
#endif

#endif // DEVICE_PIPELINE_H