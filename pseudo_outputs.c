#include "pseudo_outputs.h"

int generate_pseudo_outputs(const uint64_t *input_amounts,
                           size_t num_inputs,
                           const tx_output_info_t *outputs,
                           size_t num_outputs,
                           uint64_t fee,
                           uint8_t pseudo_outputs[][32],
                           uint8_t pseudo_masks[][32]) {
    
    if (!input_amounts || !outputs || !pseudo_outputs || !pseudo_masks || 
        num_inputs == 0 || num_outputs == 0) {
        return 0;
    }

    // Step 1: Compute sum of output masks + fee mask
    bignum256modm sumout, temp_mask;
    set256_modm(sumout, 0);  // Initialize to zero
    
    // Add all output masks
    for (size_t i = 0; i < num_outputs; i++) {
        expand256_modm(temp_mask, outputs[i].mask, 32);
        add256_modm(sumout, sumout, temp_mask);
    }
    
    // Add fee mask (fee has implicit mask of zero, so fee_mask = 0)
    // In Monero: fee_mask is always zero since fee is public
    // So we don't add anything for fee
    
    // Step 2: Generate N-1 random pseudo output masks and sum them
    bignum256modm sumpouts, pseudo_mask_modm;
    set256_modm(sumpouts, 0);  // Initialize to zero
    
    for (size_t i = 0; i < num_inputs - 1; i++) {
        // Generate random mask: skGen(a[i])
        xmr_random_scalar(pseudo_mask_modm);
        contract256_modm(pseudo_masks[i], pseudo_mask_modm);
        
        // Sum the masks: sc_add(sumpouts.bytes, a[i].bytes, sumpouts.bytes)
        add256_modm(sumpouts, sumpouts, pseudo_mask_modm);
        
        // Generate Pedersen commitment: genC(pseudoOuts[i], a[i], inamounts[i])
        ge25519 commitment;
        xmr_gen_c(&commitment, pseudo_mask_modm, input_amounts[i]);
        ge25519_pack(pseudo_outputs[i], &commitment);
    }
    
    // Step 3: Compute last mask to balance equation
    // sc_sub(a[i].bytes, sumout.bytes, sumpouts.bytes)
    size_t last_idx = num_inputs - 1;
    sub256_modm(pseudo_mask_modm, sumout, sumpouts);
    contract256_modm(pseudo_masks[last_idx], pseudo_mask_modm);
    
    // Generate last pseudo output commitment
    ge25519 commitment;
    xmr_gen_c(&commitment, pseudo_mask_modm, input_amounts[last_idx]);
    ge25519_pack(pseudo_outputs[last_idx], &commitment);
    
    return 1;
}

int generate_output_commitments(const tx_output_info_t *outputs,
                               size_t num_outputs,
                               uint8_t output_commitments[][32]) {
    
    if (!outputs || !output_commitments || num_outputs == 0) {
        return 0;
    }
    
    for (size_t i = 0; i < num_outputs; i++) {
        // Convert mask to scalar
        bignum256modm mask_scalar;
        expand256_modm(mask_scalar, outputs[i].mask, 32);
        
        // Generate Pedersen commitment: C = mask*G + amount*H
        ge25519 commitment;
        xmr_gen_c(&commitment, mask_scalar, outputs[i].amount);
        ge25519_pack(output_commitments[i], &commitment);
    }
    
    return 1;
}

int verify_pseudo_output_balance(const uint8_t pseudo_outputs[][32], size_t num_pseudo, const uint8_t output_commitments[][32], size_t num_outputs, uint64_t fee) {
    
    if (!pseudo_outputs || !output_commitments || num_pseudo == 0 || num_outputs == 0) {
        return 0;
    }
    
    // Sum all pseudo outputs
    ge25519 sum_pseudo, temp_point;
    ge25519_set_neutral(&sum_pseudo);
    
    for (size_t i = 0; i < num_pseudo; i++) {
        if (ge25519_unpack_vartime(&temp_point, pseudo_outputs[i]) == 0) {
            return 0; // Invalid point
        }
        ge25519_add(&sum_pseudo, &sum_pseudo, &temp_point, 0);
    }
    
    // Sum all output commitments
    ge25519 sum_outputs;
    ge25519_set_neutral(&sum_outputs);
    
    for (size_t i = 0; i < num_outputs; i++) {
        if (ge25519_unpack_vartime(&temp_point, output_commitments[i]) == 0) {
            return 0; // Invalid point
        }
        ge25519_add(&sum_outputs, &sum_outputs, &temp_point, 0);
    }
    
    // Add fee commitment: fee*H (fee has mask=0, so commitment = 0*G + fee*H = fee*H)
    if (fee > 0) {
        ge25519 fee_commitment;
        bignum256modm zero_mask, fee_scalar;
        set256_modm(zero_mask, 0);
        xmr_gen_c(&fee_commitment, zero_mask, fee);
        ge25519_add(&sum_outputs, &sum_outputs, &fee_commitment, 0);
    }
    
    // Check if sum_pseudo == sum_outputs + fee
    uint8_t sum_pseudo_bytes[32], sum_outputs_bytes[32];
    ge25519_pack(sum_pseudo_bytes, &sum_pseudo);
    ge25519_pack(sum_outputs_bytes, &sum_outputs);
    
    return (memcmp(sum_pseudo_bytes, sum_outputs_bytes, 32) == 0) ? 1 : 0;
}

void generate_random_output_masks(tx_output_info_t *outputs, size_t num_outputs) {
    for (size_t i = 0; i < num_outputs; i++) {
        bignum256modm random_mask;
        xmr_random_scalar(random_mask);
        contract256_modm(outputs[i].mask, random_mask);
    }
}

// Example usage function
int example_pseudo_output_generation() {
    // Example transaction: 2 inputs, 2 outputs, fee = 76860000
    uint64_t input_amounts[] = {2790000000, 1000000000};  // From unsigned_txn_set
    size_t num_inputs = 2;
    
    tx_output_info_t outputs[] = {
        {2000000000, {0}},  // Output amount, mask will be generated
        {1713140000, {0}}   // Change amount, mask will be generated  
    };
    size_t num_outputs = 2;
    uint64_t fee = 76860000;  // Calculated as: sum(inputs) - sum(outputs)
    
    // Generate random masks for outputs
    generate_random_output_masks(outputs, num_outputs);
    
    // Generate pseudo outputs
    uint8_t pseudo_outputs[2][32];
    uint8_t pseudo_masks[2][32];
    
    if (!generate_pseudo_outputs(input_amounts, num_inputs, outputs, num_outputs, 
                                fee, pseudo_outputs, pseudo_masks)) {
        printf("Failed to generate pseudo outputs\n");
        return 0;
    }
    
    // Generate output commitments
    uint8_t output_commitments[2][32];
    if (!generate_output_commitments(outputs, num_outputs, output_commitments)) {
        printf("Failed to generate output commitments\n");
        return 0;
    }
    
    // Verify balance
    if (verify_pseudo_output_balance(pseudo_outputs, num_inputs, 
                                   output_commitments, num_outputs, fee)) {
        printf("Pseudo output balance verified!\n");
        return 1;
    } else {
        printf("Pseudo output balance verification failed!\n");
        return 0;
    }
}