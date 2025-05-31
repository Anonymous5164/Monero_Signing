#include "rct_types.h"
#include "tx_prefix_hash.h"
#include <stdlib.h>
#include <string.h>

// Constants - matching Monero's rctOps.h exactly
const rct_key_t RCT_ZERO = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

const rct_key_t RCT_ONE = {{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

const rct_key_t RCT_EIGHT = {{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

const rct_key_t RCT_INV_EIGHT = {{0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06}};

const rct_key_t RCT_H = {{0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94}};

// Key vector management
int key_vector_init(key_vector_t *vec, size_t count) {
    if (!vec) return 0;
    
    vec->count = count;
    if (count == 0) {
        vec->keys = NULL;
        return 1;
    }
    
    vec->keys = malloc(count * sizeof(rct_key_t));
    if (!vec->keys) {
        vec->count = 0;
        return 0;
    }
    
    memset(vec->keys, 0, count * sizeof(rct_key_t));
    return 1;
}

void key_vector_free(key_vector_t *vec) {
    if (!vec) return;
    
    if (vec->keys) {
        free(vec->keys);
        vec->keys = NULL;
    }
    vec->count = 0;
}

int ctkey_vector_init(ctkey_vector_t *vec, size_t count) {
    if (!vec) return 0;
    
    vec->count = count;
    if (count == 0) {
        vec->keys = NULL;
        return 1;
    }
    
    vec->keys = malloc(count * sizeof(ctkey_t));
    if (!vec->keys) {
        vec->count = 0;
        return 0;
    }
    
    memset(vec->keys, 0, count * sizeof(ctkey_t));
    return 1;
}

void ctkey_vector_free(ctkey_vector_t *vec) {
    if (!vec) return;
    
    if (vec->keys) {
        free(vec->keys);
        vec->keys = NULL;
    }
    vec->count = 0;
}

int ctkey_matrix_init(ctkey_matrix_t *matrix, size_t rows, size_t cols) {
    if (!matrix || rows == 0 || cols == 0) return 0;
    
    matrix->row_count = rows;
    matrix->rows = malloc(rows * sizeof(ctkey_vector_t));
    if (!matrix->rows) {
        matrix->row_count = 0;
        return 0;
    }
    
    for (size_t i = 0; i < rows; i++) {
        if (!ctkey_vector_init(&matrix->rows[i], cols)) {
            // Cleanup on failure
            for (size_t j = 0; j < i; j++) {
                ctkey_vector_free(&matrix->rows[j]);
            }
            free(matrix->rows);
            matrix->rows = NULL;
            matrix->row_count = 0;
            return 0;
        }
    }
    
    return 1;
}

void ctkey_matrix_free(ctkey_matrix_t *matrix) {
    if (!matrix) return;
    
    if (matrix->rows) {
        for (size_t i = 0; i < matrix->row_count; i++) {
            ctkey_vector_free(&matrix->rows[i]);
        }
        free(matrix->rows);
        matrix->rows = NULL;
    }
    matrix->row_count = 0;
}

int ecdh_info_vector_init(ecdh_info_vector_t *vec, size_t count) {
    if (!vec) return 0;
    
    vec->count = count;
    if (count == 0) {
        vec->tuples = NULL;
        return 1;
    }
    
    vec->tuples = malloc(count * sizeof(ecdh_tuple_t));
    if (!vec->tuples) {
        vec->count = 0;
        return 0;
    }
    
    memset(vec->tuples, 0, count * sizeof(ecdh_tuple_t));
    return 1;
}

void ecdh_info_vector_free(ecdh_info_vector_t *vec) {
    if (!vec) return;
    
    if (vec->tuples) {
        free(vec->tuples);
        vec->tuples = NULL;
    }
    vec->count = 0;
}

// RCT signature initialization
void rct_sig_init(rct_sig_t *sig) {
    if (!sig) return;
    
    rct_sig_base_init(&sig->base);
    rct_sig_prunable_init(&sig->prunable);
}

void rct_sig_free(rct_sig_t *sig) {
    if (!sig) return;
    
    rct_sig_base_free(&sig->base);
    rct_sig_prunable_free(&sig->prunable);
}

void rct_sig_base_init(rct_sig_base_t *base) {
    if (!base) return;
    
    memset(base, 0, sizeof(rct_sig_base_t));
    base->type = RCT_TYPE_NULL;
    base->txn_fee = 0;
}

void rct_sig_base_free(rct_sig_base_t *base) {
    if (!base) return;
    
    ctkey_matrix_free(&base->mix_ring);
    key_vector_free(&base->pseudo_outs);
    ecdh_info_vector_free(&base->ecdh_info);
    ctkey_vector_free(&base->out_pk);
}

void rct_sig_prunable_init(rct_sig_prunable_t *prunable) {
    if (!prunable) return;
    
    memset(prunable, 0, sizeof(rct_sig_prunable_t));
}

void rct_sig_prunable_free(rct_sig_prunable_t *prunable) {
    if (!prunable) return;
    
    // Free range signatures
    if (prunable->range_sigs) {
        free(prunable->range_sigs);
        prunable->range_sigs = NULL;
    }
    
    // Free bulletproofs
    if (prunable->bulletproofs) {
        for (size_t i = 0; i < prunable->bulletproofs_count; i++) {
            key_vector_free(&prunable->bulletproofs[i].V);
            key_vector_free(&prunable->bulletproofs[i].L);
            key_vector_free(&prunable->bulletproofs[i].R);
        }
        free(prunable->bulletproofs);
        prunable->bulletproofs = NULL;
    }
    
    // Free bulletproof plus
    if (prunable->bulletproofs_plus) {
        for (size_t i = 0; i < prunable->bulletproofs_plus_count; i++) {
            key_vector_free(&prunable->bulletproofs_plus[i].V);
            key_vector_free(&prunable->bulletproofs_plus[i].L);
            key_vector_free(&prunable->bulletproofs_plus[i].R);
        }
        free(prunable->bulletproofs_plus);
        prunable->bulletproofs_plus = NULL;
    }
    
    // Free MLSAG signatures
    if (prunable->MGs) {
        for (size_t i = 0; i < prunable->MGs_count; i++) {
            if (prunable->MGs[i].ss) {
                for (size_t j = 0; j < prunable->MGs[i].ring_size; j++) {
                    free(prunable->MGs[i].ss[j]);
                }
                free(prunable->MGs[i].ss);
            }
            key_vector_free(&prunable->MGs[i].II);
        }
        free(prunable->MGs);
        prunable->MGs = NULL;
    }
    
    // Free CLSAG signatures
    if (prunable->CLSAGs) {
        for (size_t i = 0; i < prunable->CLSAGs_count; i++) {
            key_vector_free(&prunable->CLSAGs[i].s);
        }
        free(prunable->CLSAGs);
        prunable->CLSAGs = NULL;
    }
    
    // Free pseudo outputs
    key_vector_free(&prunable->pseudo_outs);
    
    // Reset counts
    prunable->range_sigs_count = 0;
    prunable->bulletproofs_count = 0;
    prunable->bulletproofs_plus_count = 0;
    prunable->MGs_count = 0;
    prunable->CLSAGs_count = 0;
}

// RCT Signature Base Serialization - matches rct::rctSigBase::serialize_rctsig_base exactly
int rct_serialize_sig_base(const rct_sig_base_t *base, size_t inputs, size_t outputs,
                          uint8_t *buffer, size_t buffer_size, size_t *bytes_written) {
    if (!base || !buffer || !bytes_written) {
        return 0;
    }
    
    tx_serializer_t serializer;
    if (!tx_serializer_init(&serializer, buffer, buffer_size)) {
        return 0;
    }
    
    // Serialize RCT type (uint8_t)
    if (!tx_write_bytes(&serializer, &base->type, 1)) {
        return 0;
    }
    
    // For RCTTypeNull, nothing more to serialize
    if (base->type == RCT_TYPE_NULL) {
        *bytes_written = serializer.position;
        return 1;
    }
    
    // Validate RCT type
    if (base->type != RCT_TYPE_FULL && base->type != RCT_TYPE_SIMPLE && 
        base->type != RCT_TYPE_BULLETPROOF && base->type != RCT_TYPE_BULLETPROOF2 && 
        base->type != RCT_TYPE_CLSAG && base->type != RCT_TYPE_BULLETPROOF_PLUS) {
        return 0;
    }
    
    // Serialize transaction fee (varint)
    if (!tx_write_varint(&serializer, base->txn_fee)) {
        return 0;
    }
    
    // Serialize pseudo outputs for RCTTypeSimple (moved to prunable for bulletproof types)
    if (base->type == RCT_TYPE_SIMPLE) {
        if (!tx_write_varint(&serializer, inputs)) {
            return 0;
        }
        if (base->pseudo_outs.count != inputs) {
            return 0;
        }
        for (size_t i = 0; i < inputs; i++) {
            if (!tx_write_bytes(&serializer, base->pseudo_outs.keys[i].bytes, 32)) {
                return 0;
            }
        }
    }
    
    // Serialize ECDH info
    if (!tx_write_varint(&serializer, outputs)) {
        return 0;
    }
    if (base->ecdh_info.count != outputs) {
        return 0;
    }
    
    for (size_t i = 0; i < outputs; i++) {
        if (base->type == RCT_TYPE_BULLETPROOF2 || base->type == RCT_TYPE_CLSAG || 
            base->type == RCT_TYPE_BULLETPROOF_PLUS) {
            // For v2+ types, only serialize first 8 bytes of amount (truncated)
            if (!tx_write_bytes(&serializer, base->ecdh_info.tuples[i].amount, 8)) {
                return 0;
            }
        } else {
            // For v1 types, serialize both mask and amount
            if (!tx_write_bytes(&serializer, base->ecdh_info.tuples[i].mask, 32)) {
                return 0;
            }
            if (!tx_write_bytes(&serializer, base->ecdh_info.tuples[i].amount, 32)) {
                return 0;
            }
        }
    }
    
    // Serialize output public keys (only the mask part)
    if (!tx_write_varint(&serializer, outputs)) {
        return 0;
    }
    if (base->out_pk.count != outputs) {
        return 0;
    }
    
    for (size_t i = 0; i < outputs; i++) {
        if (!tx_write_bytes(&serializer, base->out_pk.keys[i].mask.bytes, 32)) {
            return 0;
        }
    }
    
    *bytes_written = serializer.position;
    return serializer.error ? 0 : 1;
}

// Helper function to get pseudo outputs based on RCT type
key_vector_t* rct_get_pseudo_outs(rct_sig_t *sig) {
    if (!sig) return NULL;
    
    if (sig->base.type == RCT_TYPE_BULLETPROOF || sig->base.type == RCT_TYPE_BULLETPROOF2 || 
        sig->base.type == RCT_TYPE_CLSAG || sig->base.type == RCT_TYPE_BULLETPROOF_PLUS) {
        return &sig->prunable.pseudo_outs;
    } else {
        return &sig->base.pseudo_outs;
    }
}