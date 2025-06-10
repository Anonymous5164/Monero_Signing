#include "clsag.h"
#include "sha3.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char* mock_random_values[] = {
    "2b057184b80721b4aa9253ee041445b42811e47e2aeb97c5a55da47b0aa42603",  // s[0]
    "a276421e38ebf6e11ff42e9c492c62fcef57fc28e3fa43da30fae9f82e8aad0a",  // s[1]
    "0f14936a3b5aa4cb2d43c6570a3da297fce2f0245afcd9d381b6250f6bf6db0e",  // s[2]
    "4ce856d20e8e7c92e0892d98dee29bcb30c9e7cdbedc146405f1ebc0b9c7df02",  // s[3]
    "fba3db236a35211438528552efda2b8d05959804329ef5e69ffef0eb89b3da0b",  // s[4]
    "6cd20b511a51bb792ab763a7e9b8f7c74a27ef8c56f36b9181d2c2ef887e5304",  // s[5]
    "31d8c10abe8ae8332bca68f153e8a22efbab40824ac1d6c19df9e83896220d08",  // s[6]
    "ffc0f0f6017fe251f235fa31893fcec243c991f53b750786d23fd6a687b39609",  // s[7]
    "d4802e7c0718319b19d73596508ebec1e9f5153c4a0a97ca6d85920258389202",  // s[8]
    "dbee9ec75e21a553e84a976a5f8aabb85f76f62cd204b9edf61d474dc7e7340e",  // s[9]
    "106c78255b8783204ac88a3b2d606fc990fcfbfcc0e44ffc91f4b54fc07f9c0c",  // s[10]
    "12ee74eceefc77e4d4e942350c2267125a4c406ff6c74e2563ddc9e4b7bddb02",  // s[11]
    "2230d79cc606c61a79f4e4372702517667784a0adc31c7018258ea20c882710b",  // s[12]
    "ceca35db4d6c7bd47192ad480de1852fd32f3722a4b070714f2673b6dff02906",  // s[13]
    "8d25f0af108213c19cf585d16bdcad787d256215f38cb61c1611931b4a32b80e",  // s[14]
    "1f45db8d05048dead7da814aa531d0c213871bcf1c1680ab4c6b579866d6c001",  // s[15]
    "6313c8485d57afe65ee7b15a19b6fa978aac085cffbdc1933196e1901c10cd07",  // a
};

void xmr_random_scalar_stub(bignum256modm result, int index) {
    if (index >= 0 && index < 17) {
        uint8_t bytes[32];
        hex_to_bytes(mock_random_values[index], bytes, 32);
        expand256_modm(result, bytes, 32);
    } else {
        printf("[ERROR] Invalid index for mock random scalar: %d\n", index);
    }
}

// Debug helper functions
static void print_key_debug(const char* label, const uint8_t key[32]) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
}

static void print_scalar_debug(const char* label, const bignum256modm scalar) {
    uint8_t bytes[32];
    contract256_modm(bytes, scalar);
}

// Internal helper functions
static void hash_to_scalar_clsag(const uint8_t *data, size_t len, bignum256modm result);
static void hash_to_point_clsag(const uint8_t *data, size_t len, ge25519 *result);
static void compute_aggregation_hashes(const ring_member_t *ring, size_t ring_size, const uint8_t I[32], const uint8_t D[32], const uint8_t C_offset[32], bignum256modm mu_P, bignum256modm mu_C, const uint8_t C_nonzero[][32]);
static void compute_round_hash(const uint8_t message[32], const ring_member_t *ring, size_t ring_size, const uint8_t C_offset[32], const uint8_t L[32], const uint8_t R[32], bignum256modm result, const uint8_t C_nonzero[][32]);

// Internal point arithmetic helpers
static void ge25519_neg(ge25519 *result, const ge25519 *point);
static void ge25519_sub(ge25519 *result, const ge25519 *a, const ge25519 *b);

int clsag_sign(const clsag_params_t *params, clsag_signature_t *sig) {
    if (!params || !sig || !params->ring || params->ring_size < 2 || params->l >= params->ring_size || !sig->s){
        return 0;
    }

    printf("Message (32 bytes): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", params->message[i]);
    }
    printf("\n");

    // DEBUG: Function entry (minimal)
    
    const size_t n = params->ring_size;

    uint8_t (*C_nonzero)[32] = malloc(n * sizeof(uint8_t[32]));
    if (!C_nonzero) {
        return 0;  // Memory allocation failed
    }

    ge25519 C_offset_point;
    ge25519_unpack_vartime(&C_offset_point, params->C_offset);

    for (size_t i = 0; i < n; i++) {
       ge25519 C_i, C_nonzero_point;
       ge25519_unpack_vartime(&C_i, params->ring[i].mask);           // C[i]
       ge25519_add(&C_nonzero_point, &C_i, &C_offset_point, 0);     // C[i] + C_offset
       ge25519_pack(C_nonzero[i], &C_nonzero_point);                // Store as bytes
    }
    
    // DEBUG: C_nonzero computation (skip - too verbose)
    
    // Clear output signature
    memset(sig->c1, 0, 32);
    memset(sig->D, 0, 32);
    memset(sig->I, 0, 32);
    memset(sig->s, 0, n * 32);
    sig->ring_size = n;

    // Convert secret key and mask to scalar form
    bignum256modm p_scalar, z_scalar;
    expand256_modm(p_scalar, params->p, 32);
    expand256_modm(z_scalar, params->z, 32);

    // DEBUG: Remove verbose secret scalars
    
    // Compute key image I = p * H_p(P[l])
    ge25519 H_point, I_point;
    xmr_hash_to_ec(&H_point, params->ring[params->l].dest, 32);
    ge25519_scalarmult(&I_point, &H_point, p_scalar);
    ge25519_pack(sig->I, &I_point);

    // Compute auxiliary key image D = z * H_p(P[l])
    ge25519 D_point, D_scaled;
    ge25519_scalarmult(&D_point, &H_point, z_scalar);
    
    // Scale D by 1/8 for storage (matching Monero's approach)
    // Use precomputed INV_EIGHT = 8^-1 mod L (curve order)
    // This matches Monero's rct::INV_EIGHT constant
    uint8_t inv_eight_bytes[32] = {
        0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61,
        0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06
    };
    
    bignum256modm inv_eight, z_div8;
    expand256_modm(inv_eight, inv_eight_bytes, 32);
    mul256_modm(z_div8, z_scalar, inv_eight);
    ge25519_scalarmult(&D_scaled, &H_point, z_div8);
    ge25519_pack(sig->D, &D_scaled);

    // DEBUG: Key images (essential)
    uint8_t H_bytes[32];
    ge25519_pack(H_bytes, &H_point);
   
    uint8_t D_unscaled[32];
    ge25519_pack(D_unscaled, &D_point);
    
    // Compute aggregation hashes mu_P and mu_C
    bignum256modm mu_P, mu_C;
    compute_aggregation_hashes(params->ring, n, sig->I, sig->D, params->C_offset, mu_P, mu_C, C_nonzero);

    // Generate random scalar a for commitment
    bignum256modm a;
    xmr_random_scalar(a);

    // Compute initial commitments aG and aH
    ge25519 aG_point, aH_point;
    ge25519_scalarmult_base_wrapper(&aG_point, a);
    ge25519_scalarmult(&aH_point, &H_point, a);

    uint8_t aG[32], aH[32];
    ge25519_pack(aG, &aG_point);
    ge25519_pack(aH, &aH_point);

    // Compute initial round hash
    bignum256modm c;
    compute_round_hash(params->message, params->ring, n, params->C_offset, aG, aH, c, C_nonzero);

    // Start ring traversal from next index
    size_t i = (params->l + 1) % n;
    if (i == 0) {
        contract256_modm(sig->c1, c);
    }

    // Precompute key image points for efficiency
    ge25519 I_point_precomp, D_point_precomp;
    ge25519_unpack_vartime(&I_point_precomp, sig->I);
    ge25519_unpack_vartime(&D_point_precomp, sig->D);

    
    // Ring signature loop
    while (i != params->l) {
        
        // Generate random scalar s[i]
        bignum256modm s_i;
        xmr_random_scalar(s_i);
        contract256_modm(sig->s + i * 32, s_i);

        // Compute c_P = c * mu_P and c_C = c * mu_C
        bignum256modm c_P, c_C;
        mul256_modm(c_P, mu_P, c);
        mul256_modm(c_C, mu_C, c);

        // Compute L = s[i]*G + c_P*P[i] + c_C*(C[i] - C_offset)
        ge25519 P_i, C_i, C_diff, L_point;
        ge25519_unpack_vartime(&P_i, params->ring[i].dest);
        ge25519_unpack_vartime(&C_i, params->ring[i].mask);
        
        // Compute C[i] - C_offset
        // ge25519 C_offset_point;
        // ge25519_unpack_vartime(&C_offset_point, params->C_offset);
        // // ge25519_sub(&C_diff, &C_i, &C_offset_point);

        // L = s[i]*G + c_P*P[i] + c_C*(C[i] - C_offset)
        // Correction L= s[i]*G + c_P*P[i] + c_C*C[i]
        ge25519 term1, term2, term3;
        ge25519_scalarmult_base_wrapper(&term1, s_i);  // s[i]*G
        ge25519_scalarmult(&term2, &P_i, c_P);         // c_P*P[i]
        ge25519_scalarmult(&term3, &C_i, c_C);      // c_C*(C[i] - C_offset  **Correction c_C*C[i]

        ge25519_add(&L_point, &term1, &term2, 0);
        ge25519_add(&L_point, &L_point, &term3, 0);

        // Compute R = s[i]*H_p(P[i]) + c_P*I + c_C*D
        ge25519 H_i, R_point;
        xmr_hash_to_ec(&H_i, params->ring[i].dest, 32);
        
        ge25519_scalarmult(&term1, &H_i, s_i);              // s[i]*H_p(P[i])
        ge25519_scalarmult(&term2, &I_point_precomp, c_P);  // c_P*I  
        // ge25519_scalarmult(&term3, &D_point_precomp, c_C);  // c_C*D
        ge25519_scalarmult(&term3, &D_point, c_C);  // c_C*D


        ge25519_add(&R_point, &term1, &term2, 0);
        ge25519_add(&R_point, &R_point, &term3, 0);

        // Pack L and R for hashing
        uint8_t L[32], R[32];
        ge25519_pack(L, &L_point);
        ge25519_pack(R, &R_point);

        // Compute next challenge c = H(domain, P, C, C_offset, message, L, R)
        compute_round_hash(params->message, params->ring, n, params->C_offset, L, R, c, C_nonzero);

        // Move to next ring member
        i = (i + 1) % n;
        if (i == 0) {
            contract256_modm(sig->c1, c);
        }
    }

    // Compute final response scalar s[l] = a - c*(mu_P*p + mu_C*z)
    bignum256modm temp1, temp2, temp3;
    mul256_modm(temp1, mu_P, p_scalar);    // mu_P * p
    mul256_modm(temp2, mu_C, z_scalar);    // mu_C * z  
    add256_modm(temp3, temp1, temp2);      // mu_P*p + mu_C*z
    mul256_modm(temp1, c, temp3);          // c * (mu_P*p + mu_C*z)
    sub256_modm(temp2, a, temp1);          // a - c*(mu_P*p + mu_C*z)
    contract256_modm(sig->s + params->l * 32, temp2);

    // Clear sensitive data
    memset(&a, 0, sizeof(a));
    memset(&p_scalar, 0, sizeof(p_scalar));
    memset(&z_scalar, 0, sizeof(z_scalar));
    free(C_nonzero);
    return 1;
}

void clsag_clear(clsag_signature_t *sig) {
    if (!sig) return;
    
    // Clear sensitive data
    memset(sig->c1, 0, 32);
    memset(sig->D, 0, 32);
    memset(sig->I, 0, 32);
    if (sig->s && sig->ring_size > 0) {
        memset(sig->s, 0, sig->ring_size * 32);
    }
    sig->ring_size = 0;
}

// Internal helper function implementations

static void hash_to_scalar_clsag(const uint8_t *data, size_t len, bignum256modm result) {
    uint8_t hash[32];
    keccak_256(data, len, hash);
    expand256_modm(result, hash, 32);
}

static void hash_to_point_clsag(const uint8_t *data, size_t len, ge25519 *result) {
    xmr_hash_to_ec(result, data, len);
}

static void compute_aggregation_hashes(const ring_member_t *ring, size_t ring_size, const uint8_t I[32], const uint8_t D[32], const uint8_t C_offset[32], bignum256modm mu_P, bignum256modm mu_C, const uint8_t C_nonzero[][32]) {
    const size_t n = ring_size;
    
    // Build hash input: domain || P values || C values || I || D || C_offset
    const size_t hash_size = 32 + 2*n*32 + 32 + 32 + 32;
    uint8_t *hash_input_P = malloc(hash_size);
    uint8_t *hash_input_C = malloc(hash_size);
    
    size_t offset = 0;
    
    // Domain separation for mu_P
    memset(hash_input_P, 0, 32);
    memcpy(hash_input_P, CLSAG_HASH_KEY_AGG_0, strlen(CLSAG_HASH_KEY_AGG_0));
    offset += 32;
    
    // Domain separation for mu_C  
    memset(hash_input_C, 0, 32);
    memcpy(hash_input_C, CLSAG_HASH_KEY_AGG_1, strlen(CLSAG_HASH_KEY_AGG_1));
    
    // Copy P values
    for (size_t i = 0; i < n; i++) {
        memcpy(hash_input_P + offset, ring[i].dest, 32);
        memcpy(hash_input_C + offset, ring[i].dest, 32);
        offset += 32;
    }
    
    // Copy C values  
    for (size_t i = 0; i < n; i++) {
        memcpy(hash_input_P + offset, C_nonzero[i], 32);
        memcpy(hash_input_C + offset, C_nonzero[i], 32);
        offset += 32;
    }
    
    // Copy I, D, C_offset
    memcpy(hash_input_P + offset, I, 32);
    memcpy(hash_input_C + offset, I, 32);
    offset += 32;
    
    memcpy(hash_input_P + offset, D, 32);
    memcpy(hash_input_C + offset, D, 32);
    offset += 32;
    
    memcpy(hash_input_P + offset, C_offset, 32);
    memcpy(hash_input_C + offset, C_offset, 32);
    
    // DEBUG: Remove verbose aggregation hash inputs
    
    // Compute hashes
    hash_to_scalar_clsag(hash_input_P, hash_size, mu_P);
    hash_to_scalar_clsag(hash_input_C, hash_size, mu_C);
    
    free(hash_input_P);
    free(hash_input_C);
}

static void compute_round_hash(const uint8_t message[32], const ring_member_t *ring, size_t ring_size, const uint8_t C_offset[32], const uint8_t L[32], const uint8_t R[32], bignum256modm result, const uint8_t C_nonzero[][32]) {
    const size_t n = ring_size;
    
    // Build hash input: domain || P values || C values || C_offset || message || L || R
    const size_t hash_size = 32 + 2*n*32 + 32 + 32 + 32 + 32;
    uint8_t *hash_input = malloc(hash_size);
    
    size_t offset = 0;
    
    // Domain separation
    memset(hash_input, 0, 32);
    memcpy(hash_input, CLSAG_HASH_KEY_ROUND, strlen(CLSAG_HASH_KEY_ROUND));
    offset += 32;
    
    // Copy P values
    for (size_t i = 0; i < n; i++) {
        memcpy(hash_input + offset, ring[i].dest, 32);
        offset += 32;
    }
    
    // Copy C values
    for (size_t i = 0; i < n; i++) {
        memcpy(hash_input + offset, C_nonzero[i], 32);
        offset += 32;
    }
    
    // Copy C_offset, message, L, R
    memcpy(hash_input + offset, C_offset, 32);
    offset += 32;
    memcpy(hash_input + offset, message, 32);
    offset += 32;
    memcpy(hash_input + offset, L, 32);
    offset += 32;
    memcpy(hash_input + offset, R, 32);
    
    hash_to_scalar_clsag(hash_input, hash_size, result);
    free(hash_input);
}

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