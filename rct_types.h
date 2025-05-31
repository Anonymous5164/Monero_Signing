#ifndef RCT_TYPES_H
#define RCT_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include "ecdh.h"

// RCT Transaction Types - exact match to Monero's enum
typedef enum {
    RCT_TYPE_NULL = 0,
    RCT_TYPE_FULL = 1,
    RCT_TYPE_SIMPLE = 2,
    RCT_TYPE_BULLETPROOF = 3,
    RCT_TYPE_BULLETPROOF2 = 4,
    RCT_TYPE_CLSAG = 5,
    RCT_TYPE_BULLETPROOF_PLUS = 6
} rct_type_t;

// Range Proof Types
typedef enum {
    RANGE_PROOF_BORROMEAN = 0,
    RANGE_PROOF_PADDED_BULLETPROOF = 1
} range_proof_type_t;

// RCT Configuration
typedef struct {
    range_proof_type_t range_proof_type;
    int bp_version;
} rct_config_t;

// 32-byte key structure - matches rct::key exactly
typedef struct {
    uint8_t bytes[32];
} rct_key_t;

// Commitment key pair - matches rct::ctkey exactly
typedef struct {
    rct_key_t dest;  // Public key (P) or secret key if private
    rct_key_t mask;  // Commitment (C) or commitment mask if private
} ctkey_t;

// Key vectors and matrices
typedef struct {
    rct_key_t *keys;
    size_t count;
} key_vector_t;

typedef struct {
    ctkey_t *keys;
    size_t count;
} ctkey_vector_t;

typedef struct {
    ctkey_vector_t *rows;
    size_t row_count;
} ctkey_matrix_t;

// ECDH Info vector
typedef struct {
    ecdh_tuple_t *tuples;
    size_t count;
} ecdh_info_vector_t;

// Bulletproof structure - matches rct::Bulletproof
typedef struct {
    key_vector_t V;      // Commitments (not serialized, restored from outPk)
    rct_key_t A, S, T1, T2;
    rct_key_t taux, mu;
    key_vector_t L, R;
    rct_key_t a, b, t;
} bulletproof_t;

// Bulletproof Plus structure - matches rct::BulletproofPlus
typedef struct {
    key_vector_t V;      // Commitments (not serialized, restored from outPk)
    rct_key_t A, A1, B;
    rct_key_t r1, s1, d1;
    key_vector_t L, R;
} bulletproof_plus_t;

// CLSAG signature - matches rct::clsag exactly
typedef struct {
    key_vector_t s;      // Scalar vector
    rct_key_t c1;        // Initial challenge
    rct_key_t I;         // Key image (not serialized)
    rct_key_t D;         // Commitment key image
} clsag_t;

// MLSAG signature - matches rct::mgSig exactly
typedef struct {
    rct_key_t **ss;      // Matrix of scalars [ring_size][rows]
    size_t ring_size;
    size_t rows;
    rct_key_t cc;        // Challenge
    key_vector_t II;     // Key images (not serialized)
} mlsag_t;

// Borromean signature for range proofs
typedef struct {
    rct_key_t s0[64];
    rct_key_t s1[64];
    rct_key_t ee;
} boro_sig_t;

// Range signature structure
typedef struct {
    boro_sig_t asig;
    rct_key_t Ci[64];
} range_sig_t;

// RCT Signature Prunable Part - matches rct::rctSigPrunable
typedef struct {
    // Range proofs (only one type present depending on RCT type)
    range_sig_t *range_sigs;
    size_t range_sigs_count;
    
    bulletproof_t *bulletproofs;
    size_t bulletproofs_count;
    
    bulletproof_plus_t *bulletproofs_plus;
    size_t bulletproofs_plus_count;
    
    // Ring signatures (only one type present)
    mlsag_t *MGs;           // MLSAG signatures
    size_t MGs_count;
    
    clsag_t *CLSAGs;        // CLSAG signatures  
    size_t CLSAGs_count;
    
    // Pseudo outputs (for bulletproof types, stored here instead of base)
    key_vector_t pseudo_outs;
} rct_sig_prunable_t;

// RCT Signature Base - matches rct::rctSigBase exactly
typedef struct {
    uint8_t type;                    // RCT type
    rct_key_t message;               // Transaction prefix hash (not serialized)
    ctkey_matrix_t mix_ring;         // Ring of public keys (not serialized) 
    key_vector_t pseudo_outs;        // Pseudo outputs (for RCTTypeSimple only)
    ecdh_info_vector_t ecdh_info;    // ECDH encoded outputs
    ctkey_vector_t out_pk;           // Output public keys and commitments
    uint64_t txn_fee;                // Transaction fee
} rct_sig_base_t;

// Complete RCT Signature - matches rct::rctSig exactly
typedef struct {
    rct_sig_base_t base;             // Base signature data
    rct_sig_prunable_t prunable;     // Prunable signature data
} rct_sig_t;

// Helper functions for type checking
static inline int is_rct_simple(rct_type_t type) {
    return type == RCT_TYPE_SIMPLE || type == RCT_TYPE_BULLETPROOF || 
           type == RCT_TYPE_BULLETPROOF2 || type == RCT_TYPE_CLSAG || 
           type == RCT_TYPE_BULLETPROOF_PLUS;
}

static inline int is_rct_bulletproof(rct_type_t type) {
    return type == RCT_TYPE_BULLETPROOF || type == RCT_TYPE_BULLETPROOF2 || 
           type == RCT_TYPE_CLSAG;
}

static inline int is_rct_bulletproof_plus(rct_type_t type) {
    return type == RCT_TYPE_BULLETPROOF_PLUS;
}

static inline int is_rct_clsag(rct_type_t type) {
    return type == RCT_TYPE_CLSAG || type == RCT_TYPE_BULLETPROOF_PLUS;
}

static inline int is_rct_borromean(rct_type_t type) {
    return type == RCT_TYPE_FULL || type == RCT_TYPE_SIMPLE;
}

// Memory management functions
void rct_sig_init(rct_sig_t *sig);
void rct_sig_free(rct_sig_t *sig);
void rct_sig_base_init(rct_sig_base_t *base);
void rct_sig_base_free(rct_sig_base_t *base);
void rct_sig_prunable_init(rct_sig_prunable_t *prunable);
void rct_sig_prunable_free(rct_sig_prunable_t *prunable);

// Key vector management
int key_vector_init(key_vector_t *vec, size_t count);
void key_vector_free(key_vector_t *vec);
int ctkey_vector_init(ctkey_vector_t *vec, size_t count);
void ctkey_vector_free(ctkey_vector_t *vec);
int ctkey_matrix_init(ctkey_matrix_t *matrix, size_t rows, size_t cols);
void ctkey_matrix_free(ctkey_matrix_t *matrix);
int ecdh_info_vector_init(ecdh_info_vector_t *vec, size_t count);
void ecdh_info_vector_free(ecdh_info_vector_t *vec);

// Serialization functions
int rct_serialize_sig_base(const rct_sig_base_t *base, size_t inputs, size_t outputs, 
                          uint8_t *buffer, size_t buffer_size, size_t *bytes_written);
int rct_deserialize_sig_base(rct_sig_base_t *base, size_t inputs, size_t outputs,
                            const uint8_t *buffer, size_t buffer_size, size_t *bytes_read);

// Constants - matching Monero's values exactly
extern const rct_key_t RCT_ZERO;
extern const rct_key_t RCT_ONE;  
extern const rct_key_t RCT_EIGHT;
extern const rct_key_t RCT_INV_EIGHT;
extern const rct_key_t RCT_H;        // Second generator point

#endif // RCT_TYPES_H