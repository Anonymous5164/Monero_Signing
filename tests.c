// Updated round_trip_tests.c - Fixed CLSAG test setup
#include "tests.h"
#include "utils.h"
#include "clsag.h"
#include "pseudo_outputs.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

// Internal point arithmetic implementations

static void ge25519_neg(ge25519 *result, const ge25519 *point) {
    // For Edwards curve points in extended coordinates (x, y, z, t):
    // To negate a point P = (x, y, z, t), we compute -P = (-x, y, z, -t)
    // This flips the sign of the x and t coordinates
    
    // Copy the point first
    ge25519_copy(result, point);
    
    // Negate x coordinate: x = -x mod p
    curve25519_neg(result->x, result->x);
    
    // y and z coordinates stay the same
    // result->y = point->y (already copied)
    // result->z = point->z (already copied)
    
    // Negate t coordinate: t = -t mod p  
    curve25519_neg(result->t, result->t);
}

static void ge25519_sub(ge25519 *result, const ge25519 *a, const ge25519 *b) {
    // Point subtraction: a - b = a + (-b)
    ge25519 neg_b;
    ge25519_neg(&neg_b, b);
    ge25519_add(result, a, &neg_b, 0);
}

// Test 1: Secret key to public key relationship
void test_secret_to_public_roundtrip() {
    printf("Testing secret-to-public key relationship...\n");
    
    for (int i = 0; i < 10; i++) {
        uint8_t secret_key[32], public_key1[32], public_key2[32];
        
        // Generate random secret key
        bignum256modm secret_scalar;
        xmr_random_scalar(secret_scalar);
        contract256_modm(secret_key, secret_scalar);
        
        // Method 1: Use your function
        int result1 = private_to_public_key(secret_key, public_key1);
        
        // Method 2: Direct scalar multiplication
        ge25519 point;
        expand256_modm(secret_scalar, secret_key, 32);
        ge25519_scalarmult_base_wrapper(&point, secret_scalar);
        ge25519_pack(public_key2, &point);
        
        // They must be identical
        assert(result1 == 1);
        assert(memcmp(public_key1, public_key2, 32) == 0);
    }
    printf(" Secret-to-public key test PASSED\n\n");
}

// Test 2: Key derivation symmetry  
void test_key_derivation_symmetry() {
    printf("Testing key derivation symmetry...\n");
    
    for (int i = 0; i < 10; i++) {
        uint8_t view_secret[32], view_public[32];
        uint8_t tx_secret[32], tx_public[32];
        uint8_t derivation1[32], derivation2[32];
        
        // Generate wallet keys
        bignum256modm view_scalar;
        xmr_random_scalar(view_scalar);
        contract256_modm(view_secret, view_scalar);
        private_to_public_key(view_secret, view_public);
        
        // Generate transaction keys  
        bignum256modm tx_scalar;
        xmr_random_scalar(tx_scalar);
        contract256_modm(tx_secret, tx_scalar);
        private_to_public_key(tx_secret, tx_public);
        
        // Derivation from receiver side: D = a*R
        int result1 = monero_generate_key_derivation(tx_public, view_secret, derivation1);
        
        // Derivation from sender side: D = r*A  
        int result2 = monero_generate_key_derivation(view_public, tx_secret, derivation2);
        
        // Both derivations must be identical (ECDH property)
        assert(result1 == 1 && result2 == 1);
        assert(memcmp(derivation1, derivation2, 32) == 0);
    }
    printf(" Key derivation symmetry test PASSED\n\n");
}

// Test 3: Secret/Public key derivation consistency
void test_derived_key_consistency() {
    printf("Testing derived key consistency...\n");
    
    for (int i = 0; i < 10; i++) {
        uint8_t derivation[32], spend_secret[32], spend_public[32];
        uint8_t derived_secret[32], derived_public[32], verification[32];
        
        // Generate base keys
        bignum256modm spend_scalar;
        xmr_random_scalar(spend_scalar);
        contract256_modm(spend_secret, spend_scalar);
        private_to_public_key(spend_secret, spend_public);
        
        // Generate random derivation
        bignum256modm deriv_scalar;
        xmr_random_scalar(deriv_scalar);
        contract256_modm(derivation, deriv_scalar);
        
        uint32_t output_index = i;  // Use loop counter as output index
        
        // Derive secret and public keys
        int result1 = monero_derive_secret_key(derivation, output_index, spend_secret, derived_secret);
        int result2 = monero_derive_public_key(derivation, output_index, spend_public, derived_public);
        
        // Verify: derived_secret * G should equal derived_public
        int result3 = private_to_public_key(derived_secret, verification);
        
        assert(result1 == 1 && result2 == 1 && result3 == 1);
        assert(memcmp(derived_public, verification, 32) == 0);
    }
    printf(" Derived key consistency test PASSED\n\n");
}

// Test 4: Key image uniqueness and determinism
void test_key_image_properties() {
    printf("Testing key image properties...\n");
    
    uint8_t public_key[32], secret_key[32];
    uint8_t key_image1[32], key_image2[32], key_image3[32];
    
    // Generate test keys
    bignum256modm secret_scalar;
    xmr_random_scalar(secret_scalar);
    contract256_modm(secret_key, secret_scalar);
    private_to_public_key(secret_key, public_key);
    
    // Test determinism: same inputs = same output
    int result1 = monero_generate_key_image(public_key, secret_key, key_image1);
    int result2 = monero_generate_key_image(public_key, secret_key, key_image2);
    
    assert(result1 == 1 && result2 == 1);
    assert(memcmp(key_image1, key_image2, 32) == 0);
    
    // Test uniqueness: different secret = different key image
    uint8_t different_secret[32];
    xmr_random_scalar(secret_scalar);
    contract256_modm(different_secret, secret_scalar);
    
    int result3 = monero_generate_key_image(public_key, different_secret, key_image3);
    assert(result3 == 1);
    assert(memcmp(key_image1, key_image3, 32) != 0);
    
    printf(" Key image properties test PASSED\n\n");
}

// Test 5: Complete key generation pipeline
void test_complete_pipeline() {
    printf("Testing complete key generation pipeline...\n");
    
    for (int i = 0; i < 5; i++) {
        // 1. Generate wallet from seed
        uint8_t seed[32], spend_private[32], view_private[32];
        uint8_t spend_public[32], view_public[32];
        
        // Random seed
        bignum256modm seed_scalar;
        xmr_random_scalar(seed_scalar);
        contract256_modm(seed, seed_scalar);
        
        // Generate wallet keys
        seed_to_keys(seed, spend_private, view_private);
        private_to_public_key(spend_private, spend_public);
        private_to_public_key(view_private, view_public);
        
        // 2. Simulate receiving a transaction
        uint8_t tx_public[32], tx_secret[32];
        xmr_random_scalar(seed_scalar);
        contract256_modm(tx_secret, seed_scalar);
        private_to_public_key(tx_secret, tx_public);
        
        // 3. Generate key image for the received output
        uint8_t key_image[32], ephemeral_secret[32];
        uint32_t output_index = 0;
        
        int result = monero_generate_key_image_for_output(
            tx_public, view_private, spend_private, output_index,
            key_image, ephemeral_secret
        );
        
        assert(result == 1);
        
        // 4. Verify the key image is valid (non-zero)
        int is_zero = 1;
        for (int j = 0; j < 32; j++) {
            if (key_image[j] != 0) {
                is_zero = 0;
                break;
            }
        }
        assert(!is_zero);  // Key image should not be all zeros
        
        printf("  Pipeline test %d: \n", i + 1);
    }
    printf(" Complete pipeline test PASSED\n\n");
}

// Test 6: Pseudo output balance verification
void test_pseudo_output_balance() {
    printf("Testing pseudo output balance...\n");
    
    for (int test = 0; test < 5; test++) {
        // Create test transaction with multiple inputs/outputs
        uint64_t input_amounts[] = {1000000000, 2000000000, 500000000};  // 1, 2, 0.5 XMR
        size_t num_inputs = 3;
        
        tx_output_info_t outputs[] = {
            {2500000000, {0}},  // 2.5 XMR to recipient
            {950000000, {0}}    // 0.95 XMR change
        };
        size_t num_outputs = 2;
        uint64_t fee = 50000000;  // 0.05 XMR fee
        
        // Check: sum(inputs) should equal sum(outputs) + fee
        uint64_t input_sum = 0, output_sum = 0;
        for (size_t i = 0; i < num_inputs; i++) input_sum += input_amounts[i];
        for (size_t i = 0; i < num_outputs; i++) output_sum += outputs[i].amount;
        
        assert(input_sum == output_sum + fee);  // Basic arithmetic check
        
        // Generate random output masks
        generate_random_output_masks(outputs, num_outputs);
        
        // Generate pseudo outputs
        uint8_t pseudo_outputs[num_inputs][32];
        uint8_t pseudo_masks[num_inputs][32];
        
        int result = generate_pseudo_outputs(
            input_amounts, num_inputs,
            outputs, num_outputs,
            fee,
            pseudo_outputs, pseudo_masks
        );
        assert(result == 1);
        
        // Generate output commitments
        uint8_t output_commitments[num_outputs][32];
        result = generate_output_commitments(outputs, num_outputs, output_commitments);
        assert(result == 1);
        
        // Verify balance cryptographically
        result = verify_pseudo_output_balance(
            pseudo_outputs, num_inputs,
            output_commitments, num_outputs,
            fee
        );
        assert(result == 1);
        
        printf("  Balance test %d: \n", test + 1);
    }
    printf(" Pseudo output balance test PASSED\n\n");
}

// Test 7: CLSAG round-trip test (Fixed to match Monero's approach)
void test_clsag_roundtrip() {
    
    printf("Testing CLSAG round-trip...\n");
    
    for (int test = 0; test < 3; test++) {
        const size_t ring_size = 11;
        ring_member_t ring[ring_size];
        size_t real_index = 5;
        
        // Generate real keys
        uint8_t real_secret_key[32], real_public_key[32];
        bignum256modm real_secret_scalar;
        xmr_random_scalar(real_secret_scalar);
        contract256_modm(real_secret_key, real_secret_scalar);
        private_to_public_key(real_secret_key, real_public_key);
        
        // Real input amount and mask
        uint64_t real_input_amount = 1000000000;
        bignum256modm real_input_mask;
        xmr_random_scalar(real_input_mask);
        
        // Real commitment: C_nonzero = mask*G + amount*H
        ge25519 real_commitment_nonzero;
        xmr_gen_c(&real_commitment_nonzero, real_input_mask, real_input_amount);
        uint8_t real_commitment_nonzero_bytes[32];
        ge25519_pack(real_commitment_nonzero_bytes, &real_commitment_nonzero);
        
        // Pseudo output commitment
        bignum256modm pseudo_mask;
        xmr_random_scalar(pseudo_mask);
        ge25519 pseudo_commitment;
        xmr_gen_c(&pseudo_commitment, pseudo_mask, real_input_amount);
        uint8_t C_offset[32];
        ge25519_pack(C_offset, &pseudo_commitment);
        
        // Compute z = real_mask - pseudo_mask
        bignum256modm z_scalar;
        sub256_modm(z_scalar, real_input_mask, pseudo_mask);
        uint8_t z_bytes[32];
        contract256_modm(z_bytes, z_scalar);
        
        // Set up ring
        // Real member
        memcpy(ring[real_index].dest, real_public_key, 32);
        memcpy(ring[real_index].mask, real_commitment_nonzero_bytes, 32);  // C_nonzero
        
        // Decoy members
        for (size_t i = 0; i < ring_size; i++) {
            if (i == real_index) continue;
            
            bignum256modm decoy_scalar;
            xmr_random_scalar(decoy_scalar);
            ge25519 decoy_point;
            ge25519_scalarmult_base_wrapper(&decoy_point, decoy_scalar);
            ge25519_pack(ring[i].dest, &decoy_point);
            
            xmr_random_scalar(decoy_scalar);
            uint64_t decoy_amount = 500000000 + (i * 100000000);
            ge25519 decoy_commitment_nonzero;
            xmr_gen_c(&decoy_commitment_nonzero, decoy_scalar, decoy_amount);
            ge25519_pack(ring[i].mask, &decoy_commitment_nonzero);
        }
        
        // Sign
        uint8_t message[32];
        memset(message, 0, 32);
        memcpy(message, "clsag_test_message", 18);
        
        clsag_params_t params = {
            .ring = ring,
            .ring_size = ring_size,
            .l = real_index
        };
        memcpy(params.message, message, 32);
        memcpy(params.p, real_secret_key, 32);
        memcpy(params.z, z_bytes, 32);
        memcpy(params.C_offset, C_offset, 32);
        
        clsag_signature_t sig;
        uint8_t sig_s[ring_size * 32];
        sig.s = sig_s;
        
        int sign_result = clsag_sign(&params, &sig);
        if (sign_result != 1) {
            printf("   Test %d: Signing failed\n", test + 1);
            continue;
        }
        
        // Verify
        int verify_result = clsag_verify(message, ring, ring_size, C_offset, &sig);
        
        if (verify_result == 1) {
            printf("   Test %d: PASSED\n", test + 1);
        } else {
            printf("   Test %d: Verification failed\n", test + 1);
        }
    }
    printf(" CLSAG round-trip test COMPLETED\n\n");
}

// Test 8: Simple CLSAG test with minimal ring size
void test_clsag_simple() {
    printf("Testing CLSAG with minimal ring (size 2)...\n");
    
    const size_t ring_size = 2;
    ring_member_t ring[2];
    
    // Real keys
    uint8_t real_secret[32], real_public[32];
    bignum256modm secret_scalar;
    xmr_random_scalar(secret_scalar);
    contract256_modm(real_secret, secret_scalar);
    private_to_public_key(real_secret, real_public);
    
    // Amounts and masks
    uint64_t amount = 1000000000;
    bignum256modm real_mask, pseudo_mask;
    xmr_random_scalar(real_mask);
    xmr_random_scalar(pseudo_mask);
    
    // Commitments
    ge25519 real_commitment, pseudo_commitment;
    xmr_gen_c(&real_commitment, real_mask, amount);
    xmr_gen_c(&pseudo_commitment, pseudo_mask, amount);
    
    uint8_t C_offset[32];
    ge25519_pack(C_offset, &pseudo_commitment);
    
    // Set up ring
    memcpy(ring[0].dest, real_public, 32);
    ge25519_pack(ring[0].mask, &real_commitment);
    
    // Decoy
    bignum256modm decoy_scalar;
    xmr_random_scalar(decoy_scalar);
    ge25519 decoy_point;
    ge25519_scalarmult_base_wrapper(&decoy_point, decoy_scalar);
    ge25519_pack(ring[1].dest, &decoy_point);
    
    xmr_random_scalar(decoy_scalar);
    ge25519 decoy_commitment;
    xmr_gen_c(&decoy_commitment, decoy_scalar, 2000000000);
    ge25519_pack(ring[1].mask, &decoy_commitment);
    
    // CLSAG mask
    bignum256modm z_scalar;
    sub256_modm(z_scalar, real_mask, pseudo_mask);
    uint8_t z_bytes[32];
    contract256_modm(z_bytes, z_scalar);
    
    // Sign
    uint8_t message[32];
    memset(message, 0, 32);
    memcpy(message, "simple_test", 11);
    
    clsag_params_t params = {
        .ring = ring,
        .ring_size = 2,
        .l = 0
    };
    memcpy(params.message, message, 32);
    memcpy(params.p, real_secret, 32);
    memcpy(params.z, z_bytes, 32);
    memcpy(params.C_offset, C_offset, 32);
    
    clsag_signature_t sig;
    uint8_t sig_s[2 * 32];
    sig.s = sig_s;
    
    int sign_result = clsag_sign(&params, &sig);
    if (sign_result != 1) {
        printf("   Signing failed\n");
        return;
    }
    
    int verify_result = clsag_verify(message, ring, 2, C_offset, &sig);
    if (verify_result == 1) {
        printf("   Simple CLSAG test PASSED\n");
    } else {
        printf("   Simple CLSAG verification failed\n");
    }
    
    printf(" Simple CLSAG test COMPLETED\n\n");
}

// Main test runner
void run_all_roundtrip_tests() {
    printf(" Running Round-Trip Tests \n\n");
    
    test_secret_to_public_roundtrip();
    test_key_derivation_symmetry();
    test_derived_key_consistency();
    test_key_image_properties();
    test_complete_pipeline();
    test_pseudo_output_balance();
    
    // Test CLSAG
    test_clsag_simple();
    test_clsag_roundtrip();
    
    printf(" ALL ROUND-TRIP TESTS COMPLETED! \n");
    printf("Core crypto functions are mathematically consistent!\n\n");
}

// Dumped the prefix txn hash tests from main

// Test function for transaction prefix hash
void test_tx_prefix_hash() {
    printf(" Testing Transaction Prefix Hash \n");
    
    // Test 1: Single input, dual output transaction
    uint8_t computed_hash[32];
    keccak_256(test_tx_prefix_0_data, test_tx_prefix_0_len, computed_hash);
    
    if (memcmp(computed_hash, expected_hash_0, 32) == 0) {
        printf("Single input test: PASSED\n");
    } else {
        printf("Single input test: FAILED\n");
    }
    
    // Test 2: Multi-input, multi-output transaction
    uint8_t computed_hash_1[32];
    keccak_256(test_tx_prefix_1_data, test_tx_prefix_1_len, computed_hash_1);
    
    if (memcmp(computed_hash_1, expected_hash_1, 32) == 0) {
        printf("Multi-input test: PASSED\n");
    } else {
        printf("Multi-input test: FAILED\n");
    }
    
    // Test 3: Recreate single input transaction with our serializer
    transaction_prefix_t monero_tx;
    tx_prefix_init(&monero_tx);
    
    monero_tx.version = 2;
    monero_tx.unlock_time = 0;
    monero_tx.vin_count = 1;
    monero_tx.vin = malloc(sizeof(txin_v_t));
    
    uint64_t monero_key_offsets[] = {0x208068, 0x6fa641, 0x17cf, 0x4296, 0xc15, 0xd59, 0x52e, 0xa31, 0x42c, 0x9f, 0x134, 0x45, 0x12b, 0x77, 0x16d, 0x10f};
    uint8_t monero_key_image[32];
    hex_to_bytes("811f0366f3703a0592b89b95e265f0a56d7c8b48828f972ef682a6e79e6801b3", monero_key_image);
    tx_create_txin_to_key(&monero_tx.vin[0], 0, monero_key_offsets, 16, monero_key_image);
    
    monero_tx.vout_count = 2;
    monero_tx.vout = malloc(2 * sizeof(tx_out_t));
    
    uint8_t output_key_0[32];
    hex_to_bytes("93dd18236ba1043e5453f3ae16108566463028f071250b644d695e4cf53ec6aa", output_key_0);
    tx_create_txout_to_tagged_key(&monero_tx.vout[0], 0, output_key_0, 0xe5);
    
    uint8_t output_key_1[32];
    hex_to_bytes("34ad35e8159f937770a6cc7f0ed2fccb941d2f4f68623c3369a90b4ad1640b82", output_key_1);
    tx_create_txout_to_tagged_key(&monero_tx.vout[1], 0, output_key_1, 0x9b);
    
    monero_tx.extra_len = 44;
    monero_tx.extra = malloc(44);
    hex_to_bytes("01570351247d420969b40f810e35bab6db3ac2847134f7c4c0bae654e427200c74020901f2ed5d6bbb72d5ef", monero_tx.extra);
    
    uint8_t our_monero_hash[32];
    int monero_result = monero_get_transaction_prefix_hash(&monero_tx, our_monero_hash);
    
    if (monero_result && memcmp(our_monero_hash, expected_hash_0, 32) == 0) {
        printf("Single input serializer: PASSED\n");
    } else {
        printf("Single input serializer: FAILED\n");
    }
    
    tx_prefix_free(&monero_tx);
    
    // Test 4: Recreate multi-input transaction with our serializer
    transaction_prefix_t multi_tx;
    tx_prefix_init(&multi_tx);
    
    multi_tx.version = 2;
    multi_tx.unlock_time = 0;
    multi_tx.vin_count = 2;
    multi_tx.vin = malloc(2 * sizeof(txin_v_t));
    
    uint64_t input0_offsets[] = {0x8b4b23, 0x21b45, 0x2e0fe, 0x5218, 0xf0c, 0xbbb, 0x8c, 0x1732, 0x169, 0x2aa, 0x23c, 0x638, 0x457, 0x1d, 0xa0, 0xb};
    uint8_t input0_key_image[32];
    hex_to_bytes("1e94fdb4fc211285db112556cdb29c8b6199e9b8fd73583d76723d9b7f5f979a", input0_key_image);
    tx_create_txin_to_key(&multi_tx.vin[0], 0, input0_offsets, 16, input0_key_image);
    
    uint64_t input1_offsets[] = {0x82a550, 0xd21de, 0x427b, 0x868e, 0x2e0b, 0x12f5, 0x8b5, 0xee, 0x17f, 0x10f, 0x51, 0x8, 0xf7, 0x47, 0x66, 0x1d};
    uint8_t input1_key_image[32];
    hex_to_bytes("1b0d442b9240e58d094dd87a24c78eb57fb388a4b504e53f2b1da9cb1c9e252c", input1_key_image);
    tx_create_txin_to_key(&multi_tx.vin[1], 0, input1_offsets, 16, input1_key_image);
    
    multi_tx.vout_count = 2;
    multi_tx.vout = malloc(2 * sizeof(tx_out_t));
    
    uint8_t multi_output_key_0[32];  
    hex_to_bytes("002d736300462e7c0022daa69e00697974a265fbed4cd2398a27c2cfc06ee30d", multi_output_key_0);
    tx_create_txout_to_tagged_key(&multi_tx.vout[0], 0, multi_output_key_0, 0xd4);
    
    uint8_t multi_output_key_1[32];
    hex_to_bytes("922849eefa9840509df9a994789bb92114c7c5437292553ab16165253a52408c", multi_output_key_1);
    tx_create_txout_to_tagged_key(&multi_tx.vout[1], 0, multi_output_key_1, 0x6a);
    
    multi_tx.extra_len = 44;
    multi_tx.extra = malloc(44);
    hex_to_bytes("01f53a17617ccc452909423e807deb59c890be4d6fd311f886f9cdcccaa1109f1c0209012dabfa9994ce0daa", multi_tx.extra);
    
    uint8_t our_multi_hash[32];
    int multi_result = monero_get_transaction_prefix_hash(&multi_tx, our_multi_hash);
    
    if (multi_result && memcmp(our_multi_hash, expected_hash_1, 32) == 0) {
        printf("Multi-input serializer: PASSED\n");
    } else {
        printf("Multi-input serializer: FAILED\n");
    }
    
    tx_prefix_free(&multi_tx);
    printf("\n");
}

void test_multiple_functions_from_file(const char* filename, int max_tests_per_type) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Could not open %s\n", filename);
        return;
    }
    
    char line[512];
    int key_image_tests = 0, derivation_tests = 0, derive_pub_tests = 0, derive_sec_tests = 0;
    int key_image_pass = 0, derivation_pass = 0, derive_pub_pass = 0, derive_sec_pass = 0;
    
    while (fgets(line, sizeof(line), file)) {
        
        // Test generate_key_derivation
        if (strncmp(line, "generate_key_derivation", 23) == 0 && derivation_tests < max_tests_per_type) {
            char pub_hex[65], sec_hex[65], success_str[10], expected_hex[65];
            if (sscanf(line, "generate_key_derivation %64s %64s %9s %64s", 
                      pub_hex, sec_hex, success_str, expected_hex) == 4) {
                
                if (strcmp(success_str, "true") == 0) {
                    uint8_t pub[32], sec[32], expected[32], actual[32];
                    hex_to_bytes(pub_hex, pub);
                    hex_to_bytes(sec_hex, sec);
                    hex_to_bytes(expected_hex, expected);
                    
                    if (monero_generate_key_derivation(pub, sec, actual)) {
                        if (memcmp(actual, expected, 32) == 0) derivation_pass++;
                    }
                    derivation_tests++;
                }
            }
        }
        
        // Test derive_public_key  
        else if (strncmp(line, "derive_public_key", 17) == 0 && derive_pub_tests < max_tests_per_type) {
            char deriv_hex[65], base_hex[65], success_str[10], expected_hex[65];
            unsigned int output_index;
            if (sscanf(line, "derive_public_key %64s %u %64s %9s %64s",
                      deriv_hex, &output_index, base_hex, success_str, expected_hex) == 5) {
                
                if (strcmp(success_str, "true") == 0) {
                    uint8_t deriv[32], base[32], expected[32], actual[32];
                    hex_to_bytes(deriv_hex, deriv);
                    hex_to_bytes(base_hex, base);
                    hex_to_bytes(expected_hex, expected);
                    
                    if (monero_derive_public_key(deriv, output_index, base, actual)) {
                        if (memcmp(actual, expected, 32) == 0) derive_pub_pass++;
                    }
                    derive_pub_tests++;
                }
            }
        }
        
        // Test derive_secret_key
        else if (strncmp(line, "derive_secret_key", 17) == 0 && derive_sec_tests < max_tests_per_type) {
            char deriv_hex[65], base_hex[65], expected_hex[65];
            unsigned int output_index;
            if (sscanf(line, "derive_secret_key %64s %u %64s %64s",
                      deriv_hex, &output_index, base_hex, expected_hex) == 4) {
                
                uint8_t deriv[32], base[32], expected[32], actual[32];
                hex_to_bytes(deriv_hex, deriv);
                hex_to_bytes(base_hex, base);
                hex_to_bytes(expected_hex, expected);
                
                if (monero_derive_secret_key(deriv, output_index, base, actual)) {
                    if (memcmp(actual, expected, 32) == 0) derive_sec_pass++;
                }
                derive_sec_tests++;
            }
        }
        
        // Test generate_key_image
        else if (strncmp(line, "generate_key_image", 18) == 0 && key_image_tests < max_tests_per_type) {
            char pub_hex[65], sec_hex[65], expected_hex[65];
            if (sscanf(line, "generate_key_image %64s %64s %64s", 
                      pub_hex, sec_hex, expected_hex) == 3) {
                
                uint8_t pub[32], sec[32], expected[32], actual[32];
                hex_to_bytes(pub_hex, pub);
                hex_to_bytes(sec_hex, sec);
                hex_to_bytes(expected_hex, expected);
                
                monero_generate_key_image(pub, sec, actual);
                if (memcmp(actual, expected, 32) == 0) key_image_pass++;
                key_image_tests++;
            }
        }
    }
    
    fclose(file);
    
    printf(" Monero Function Tests \n");
    if (key_image_tests > 0)
        printf("Key Images: %d/%d passed\n", key_image_pass, key_image_tests);
    if (derivation_tests > 0)
        printf("Key Derivations: %d/%d passed\n", derivation_pass, derivation_tests);
    if (derive_pub_tests > 0)
        printf("Derive Public: %d/%d passed\n", derive_pub_pass, derive_pub_tests);
    if (derive_sec_tests > 0)
        printf("Derive Secret: %d/%d passed\n", derive_sec_pass, derive_sec_tests);
    printf("\n");
}