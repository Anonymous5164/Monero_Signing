#include "clsag.h"
#include "sha3.h"
#include <string.h>
#include <stdlib.h>

// Internal helper functions
static void hash_to_scalar_clsag(const uint8_t *data, size_t len, bignum256modm result);
static void hash_to_point_clsag(const uint8_t *data, size_t len, ge25519 *result);
static void compute_aggregation_hashes(const ring_member_t *ring, size_t ring_size,
                                     const uint8_t I[32], const uint8_t D[32], 
                                     const uint8_t C_offset[32],
                                     bignum256modm mu_P, bignum256modm mu_C);
static void compute_round_hash(const uint8_t message[32], const ring_member_t *ring,
                             size_t ring_size, const uint8_t C_offset[32],
                             const uint8_t L[32], const uint8_t R[32],
                             bignum256modm result);

// Internal point arithmetic helpers
static void ge25519_neg(ge25519 *result, const ge25519 *point);
static void ge25519_sub(ge25519 *result, const ge25519 *a, const ge25519 *b);

int clsag_sign(const clsag_params_t *params, clsag_signature_t *sig) {
    if (!params || !sig || !params->ring || params->ring_size < 2 || 
        params->l >= params->ring_size || !sig->s) {
        return 0;
    }

    const size_t n = params->ring_size;
    
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

    // Compute aggregation hashes mu_P and mu_C
    bignum256modm mu_P, mu_C;
    compute_aggregation_hashes(params->ring, n, sig->I, sig->D, 
                             params->C_offset, mu_P, mu_C);

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
    compute_round_hash(params->message, params->ring, n, params->C_offset,
                      aG, aH, c);

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
        ge25519 C_offset_point;
        ge25519_unpack_vartime(&C_offset_point, params->C_offset);
        ge25519_sub(&C_diff, &C_i, &C_offset_point);

        // L = s[i]*G + c_P*P[i] + c_C*(C[i] - C_offset)
        ge25519 term1, term2, term3;
        ge25519_scalarmult_base_wrapper(&term1, s_i);  // s[i]*G
        ge25519_scalarmult(&term2, &P_i, c_P);         // c_P*P[i]
        ge25519_scalarmult(&term3, &C_diff, c_C);      // c_C*(C[i] - C_offset)
        
        ge25519_add(&L_point, &term1, &term2, 0);
        ge25519_add(&L_point, &L_point, &term3, 0);

        // Compute R = s[i]*H_p(P[i]) + c_P*I + c_C*D
        ge25519 H_i, R_point;
        xmr_hash_to_ec(&H_i, params->ring[i].dest, 32);
        
        ge25519_scalarmult(&term1, &H_i, s_i);              // s[i]*H_p(P[i])
        ge25519_scalarmult(&term2, &I_point_precomp, c_P);  // c_P*I  
        ge25519_scalarmult(&term3, &D_point_precomp, c_C);  // c_C*D

        ge25519_add(&R_point, &term1, &term2, 0);
        ge25519_add(&R_point, &R_point, &term3, 0);

        // Pack L and R for hashing
        uint8_t L[32], R[32];
        ge25519_pack(L, &L_point);
        ge25519_pack(R, &R_point);

        // Compute next challenge c = H(domain, P, C, C_offset, message, L, R)
        compute_round_hash(params->message, params->ring, n, params->C_offset,
                          L, R, c);

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

    return 1;
}

int clsag_verify(const uint8_t message[32], 
                 const ring_member_t *ring,
                 size_t ring_size,
                 const uint8_t C_offset[32],
                 const clsag_signature_t *sig) {
    
    if (!message || !ring || !C_offset || !sig || !sig->s || 
        ring_size < 2 || sig->ring_size != ring_size) {
        return 0;
    }

    const size_t n = ring_size;

    // Verify scalar ranges
    bignum256modm c1_scalar;
    expand256_modm(c1_scalar, sig->c1, 32);
    if (!check256_modm(c1_scalar)) return 0;

    for (size_t i = 0; i < n; i++) {
        bignum256modm s_i;
        expand256_modm(s_i, sig->s + i * 32, 32);
        if (!check256_modm(s_i)) return 0;
    }

    // Verify key image is not identity
    ge25519 I_point;
    if (ge25519_unpack_vartime(&I_point, sig->I) == 0) return 0;
    // Check I != identity (all zeros)
    uint8_t identity[32] = {1,0}; // Identity point in compressed form
    if (memcmp(sig->I, identity, 32) == 0) return 0;

    // Scale D by 8 for computation
    ge25519 D_point;
    if (ge25519_unpack_vartime(&D_point, sig->D) == 0) return 0;
    ge25519_mul8(&D_point, &D_point);

    // Compute aggregation hashes
    bignum256modm mu_P, mu_C;
    compute_aggregation_hashes(ring, n, sig->I, sig->D, C_offset, mu_P, mu_C);

    // Initialize verification loop
    bignum256modm c;
    copy256_modm(c, c1_scalar);

    ge25519 C_offset_point;
    if (ge25519_unpack_vartime(&C_offset_point, C_offset) == 0) return 0;

    // Verify each ring member
    for (size_t i = 0; i < n; i++) {
        bignum256modm s_i;
        expand256_modm(s_i, sig->s + i * 32, 32);

        // Compute c_P = c * mu_P and c_C = c * mu_C
        bignum256modm c_P, c_C;
        mul256_modm(c_P, mu_P, c);
        mul256_modm(c_C, mu_C, c);

        // Verify L computation: L = s[i]*G + c_P*P[i] + c_C*(C[i] - C_offset)
        ge25519 P_i, C_i, C_diff, L_point;
        if (ge25519_unpack_vartime(&P_i, ring[i].dest) == 0) return 0;
        if (ge25519_unpack_vartime(&C_i, ring[i].mask) == 0) return 0;
        
        ge25519_sub(&C_diff, &C_i, &C_offset_point);

        ge25519 term1, term2, term3;
        ge25519_scalarmult_base_wrapper(&term1, s_i);
        ge25519_scalarmult(&term2, &P_i, c_P);
        ge25519_scalarmult(&term3, &C_diff, c_C);
        
        ge25519_add(&L_point, &term1, &term2, 0);
        ge25519_add(&L_point, &L_point, &term3, 0);

        // Verify R computation: R = s[i]*H_p(P[i]) + c_P*I + c_C*D
        ge25519 H_i, R_point;
        xmr_hash_to_ec(&H_i, ring[i].dest, 32);
        
        ge25519_scalarmult(&term1, &H_i, s_i);
        ge25519_scalarmult(&term2, &I_point, c_P);
        ge25519_scalarmult(&term3, &D_point, c_C);

        ge25519_add(&R_point, &term1, &term2, 0);
        ge25519_add(&R_point, &R_point, &term3, 0);

        // Compute next challenge
        uint8_t L[32], R[32];
        ge25519_pack(L, &L_point);
        ge25519_pack(R, &R_point);

        bignum256modm c_new;
        compute_round_hash(message, ring, n, C_offset, L, R, c_new);
        copy256_modm(c, c_new);
    }

    // Verify the ring closes: final c should equal c1
    bignum256modm c_diff;
    sub256_modm(c_diff, c, c1_scalar);
    return iszero256_modm(c_diff);
}

void clsag_make_dummy(size_t ring_size, clsag_signature_t *sig) {
    if (!sig || !sig->s || ring_size < 2) return;

    // Set dummy values (identity point and zero scalars)
    memset(sig->c1, 0, 32);
    memset(sig->D, 0, 32);
    memset(sig->I, 0, 32);
    sig->I[0] = 1; // Compressed identity point
    memset(sig->s, 0, ring_size * 32);
    sig->ring_size = ring_size;
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

static void compute_aggregation_hashes(const ring_member_t *ring, size_t ring_size,
                                     const uint8_t I[32], const uint8_t D[32], 
                                     const uint8_t C_offset[32],
                                     bignum256modm mu_P, bignum256modm mu_C) {
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
        memcpy(hash_input_P + offset, ring[i].mask, 32);
        memcpy(hash_input_C + offset, ring[i].mask, 32);
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
    
    // Compute hashes
    hash_to_scalar_clsag(hash_input_P, hash_size, mu_P);
    hash_to_scalar_clsag(hash_input_C, hash_size, mu_C);
    
    free(hash_input_P);
    free(hash_input_C);
}

static void compute_round_hash(const uint8_t message[32], const ring_member_t *ring,
                             size_t ring_size, const uint8_t C_offset[32],
                             const uint8_t L[32], const uint8_t R[32],
                             bignum256modm result) {
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
        memcpy(hash_input + offset, ring[i].mask, 32);
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