#include "tx_prefix_hash.h"
#include "sha3.h"
#include <stdlib.h>
#include <assert.h>

// Initialize transaction serializer
int tx_serializer_init(tx_serializer_t *serializer, uint8_t *buffer, size_t capacity) {
    if (!serializer || !buffer || capacity == 0) {
        return 0;
    }
    
    serializer->data = buffer;
    serializer->capacity = capacity;
    serializer->position = 0;
    serializer->error = 0;
    
    return 1;
}

// Write raw bytes to serializer
int tx_write_bytes(tx_serializer_t *serializer, const uint8_t *data, size_t len) {
    if (!serializer || serializer->error || !data) {
        if (serializer) serializer->error = 1;
        return 0;
    }
    
    if (serializer->position + len > serializer->capacity) {
        serializer->error = 1;
        return 0;
    }
    
    memcpy(serializer->data + serializer->position, data, len);
    serializer->position += len;
    
    return 1;
}

// Calculate size needed for varint encoding
size_t tx_varint_size(uint64_t value) {
    if (value == 0) return 1;
    
    size_t size = 0;
    while (value > 0) {
        size++;
        value >>= 7;
    }
    return size;
}

// Write varint in LEB128 format (matching Python implementation exactly)
int tx_write_varint(tx_serializer_t *serializer, uint64_t value) {
    if (!serializer || serializer->error) {
        if (serializer) serializer->error = 1;
        return 0;
    }
    
    // Handle zero case
    if (value == 0) {
        uint8_t zero = 0x00;
        return tx_write_bytes(serializer, &zero, 1);
    }
    
    // LEB128 encoding - exactly like Python dump_uvarint_b_into
    while (value > 0) {
        uint64_t shifted = value >> 7;
        uint8_t byte = (value & 0x7F) | (shifted ? 0x80 : 0x00);
        
        if (!tx_write_bytes(serializer, &byte, 1)) {
            return 0;
        }
        
        value = shifted;
    }
    
    return 1;
}

// Serialize txin_gen
static int tx_serialize_txin_gen(tx_serializer_t *serializer, const txin_gen_t *gen) {
    // VARINT_FIELD(height)
    return tx_write_varint(serializer, gen->height);
}

// Serialize txin_to_script
static int tx_serialize_txin_to_script(tx_serializer_t *serializer, const txin_to_script_t *to_script) {
    // FIELD(prev) - 32 byte hash
    if (!tx_write_bytes(serializer, to_script->prev_hash, 32)) return 0;
    
    // VARINT_FIELD(prevout)
    if (!tx_write_varint(serializer, to_script->prevout)) return 0;
    
    // FIELD(sigset) - vector of bytes
    if (!tx_write_varint(serializer, to_script->sigset_len)) return 0;
    if (to_script->sigset_len > 0) {
        if (!tx_write_bytes(serializer, to_script->sigset, to_script->sigset_len)) return 0;
    }
    
    return 1;
}

// Serialize txin_to_scripthash
static int tx_serialize_txin_to_scripthash(tx_serializer_t *serializer, const txin_to_scripthash_t *to_scripthash) {
    // FIELD(prev) - 32 byte hash
    if (!tx_write_bytes(serializer, to_scripthash->prev_hash, 32)) return 0;
    
    // VARINT_FIELD(prevout)
    if (!tx_write_varint(serializer, to_scripthash->prevout)) return 0;
    
    // FIELD(script) - serialized txout_to_script
    if (!tx_write_varint(serializer, to_scripthash->script_keys_len)) return 0;
    if (to_scripthash->script_keys_len > 0) {
        if (!tx_write_bytes(serializer, to_scripthash->script_keys, to_scripthash->script_keys_len)) return 0;
    }
    
    // FIELD(sigset) - vector of bytes
    if (!tx_write_varint(serializer, to_scripthash->sigset_len)) return 0;
    if (to_scripthash->sigset_len > 0) {
        if (!tx_write_bytes(serializer, to_scripthash->sigset, to_scripthash->sigset_len)) return 0;
    }
    
    return 1;
}

// Serialize txin_to_key
static int tx_serialize_txin_to_key(tx_serializer_t *serializer, const txin_to_key_t *to_key) {
    // VARINT_FIELD(amount)
    if (!tx_write_varint(serializer, to_key->amount)) return 0;
    
    // FIELD(key_offsets) - vector of varints
    if (!tx_write_varint(serializer, to_key->key_offsets_count)) return 0;
    for (size_t i = 0; i < to_key->key_offsets_count; i++) {
        if (!tx_write_varint(serializer, to_key->key_offsets[i])) return 0;
    }
    
    // FIELD(k_image) - 32 byte key image
    if (!tx_write_bytes(serializer, to_key->k_image, 32)) return 0;
    
    return 1;
}

// Serialize transaction input variant
int tx_serialize_txin(tx_serializer_t *serializer, const txin_v_t *input) {
    if (!serializer || !input) {
        if (serializer) serializer->error = 1;
        return 0;
    }
    
    // Write variant type tag (uint8_t)
    uint8_t type_tag = (uint8_t)input->type;
    if (!tx_write_bytes(serializer, &type_tag, 1)) return 0;
    
    // Serialize variant data based on type
    switch (input->type) {
        case TXIN_GEN:
            return tx_serialize_txin_gen(serializer, &input->variant.gen);
            
        case TXIN_TO_SCRIPT:
            return tx_serialize_txin_to_script(serializer, &input->variant.to_script);
            
        case TXIN_TO_SCRIPTHASH:
            return tx_serialize_txin_to_scripthash(serializer, &input->variant.to_scripthash);
            
        case TXIN_TO_KEY:
            return tx_serialize_txin_to_key(serializer, &input->variant.to_key);
            
        default:
            serializer->error = 1;
            return 0;
    }
}

// Serialize txout_to_script
static int tx_serialize_txout_to_script(tx_serializer_t *serializer, const txout_to_script_t *to_script) {
    // FIELD(keys) - vector of public keys
    if (!tx_write_varint(serializer, to_script->keys_count)) return 0;
    if (to_script->keys_count > 0) {
        if (!tx_write_bytes(serializer, to_script->keys, to_script->keys_count * 32)) return 0;
    }
    
    // FIELD(script) - vector of bytes
    if (!tx_write_varint(serializer, to_script->script_len)) return 0;
    if (to_script->script_len > 0) {
        if (!tx_write_bytes(serializer, to_script->script, to_script->script_len)) return 0;
    }
    
    return 1;
}

// Serialize txout_to_scripthash
static int tx_serialize_txout_to_scripthash(tx_serializer_t *serializer, const txout_to_scripthash_t *to_scripthash) {
    // Just the hash - no BEGIN_SERIALIZE_OBJECT in original
    return tx_write_bytes(serializer, to_scripthash->hash, 32);
}

// Serialize txout_to_key  
static int tx_serialize_txout_to_key(tx_serializer_t *serializer, const txout_to_key_t *to_key) {
    // Just the key - no BEGIN_SERIALIZE_OBJECT in original
    return tx_write_bytes(serializer, to_key->key, 32);
}

// Serialize txout_to_tagged_key
static int tx_serialize_txout_to_tagged_key(tx_serializer_t *serializer, const txout_to_tagged_key_t *to_tagged_key) {
    // FIELD(key) - 32 byte public key
    if (!tx_write_bytes(serializer, to_tagged_key->key, 32)) return 0;
    
    // FIELD(view_tag) - 1 byte view tag
    if (!tx_write_bytes(serializer, to_tagged_key->view_tag, 1)) return 0;
    
    return 1;
}

// Serialize transaction output target variant
static int tx_serialize_txout_target(tx_serializer_t *serializer, const txout_target_v_t *target) {
    if (!serializer || !target) {
        if (serializer) serializer->error = 1;
        return 0;
    }
    
    // Write variant type tag (uint8_t)
    uint8_t type_tag = (uint8_t)target->type;
    if (!tx_write_bytes(serializer, &type_tag, 1)) return 0;
    
    // Serialize variant data based on type
    switch (target->type) {
        case TXOUT_TO_SCRIPT:
            return tx_serialize_txout_to_script(serializer, &target->variant.to_script);
            
        case TXOUT_TO_SCRIPTHASH:
            return tx_serialize_txout_to_scripthash(serializer, &target->variant.to_scripthash);
            
        case TXOUT_TO_KEY:
            return tx_serialize_txout_to_key(serializer, &target->variant.to_key);
            
        case TXOUT_TO_TAGGED_KEY:
            return tx_serialize_txout_to_tagged_key(serializer, &target->variant.to_tagged_key);
            
        default:
            serializer->error = 1;
            return 0;
    }
}

// Serialize transaction output
int tx_serialize_txout(tx_serializer_t *serializer, const tx_out_t *output) {
    if (!serializer || !output) {
        if (serializer) serializer->error = 1;
        return 0;
    }
    
    // VARINT_FIELD(amount)
    if (!tx_write_varint(serializer, output->amount)) return 0;
    
    // FIELD(target)
    return tx_serialize_txout_target(serializer, &output->target);
}

// Serialize vector of transaction inputs
int tx_serialize_txin_vector(tx_serializer_t *serializer, const txin_v_t *inputs, size_t count) {
    if (!serializer) return 0;
    
    // Write vector length as varint (from Python ContainerType.dump)
    if (!tx_write_varint(serializer, count)) return 0;
    
    // Write each element
    for (size_t i = 0; i < count; i++) {
        if (!tx_serialize_txin(serializer, &inputs[i])) return 0;
    }
    
    return 1;
}

// Serialize vector of transaction outputs
int tx_serialize_txout_vector(tx_serializer_t *serializer, const tx_out_t *outputs, size_t count) {
    if (!serializer) return 0;
    
    // Write vector length as varint (from Python ContainerType.dump)
    if (!tx_write_varint(serializer, count)) return 0;
    
    // Write each element
    for (size_t i = 0; i < count; i++) {
        if (!tx_serialize_txout(serializer, &outputs[i])) return 0;
    }
    
    return 1;
}

// Serialize complete transaction prefix
int tx_serialize_prefix(tx_serializer_t *serializer, const transaction_prefix_t *tx_prefix) {
    if (!serializer || !tx_prefix) {
        if (serializer) serializer->error = 1;
        return 0;
    }
    
    // Exact serialization order from Monero C++:
    // VARINT_FIELD(version)
    if (!tx_write_varint(serializer, tx_prefix->version)) return 0;
    
    // VARINT_FIELD(unlock_time)
    if (!tx_write_varint(serializer, tx_prefix->unlock_time)) return 0;
    
    // FIELD(vin) - vector of inputs
    if (!tx_serialize_txin_vector(serializer, tx_prefix->vin, tx_prefix->vin_count)) return 0;
    
    // FIELD(vout) - vector of outputs
    if (!tx_serialize_txout_vector(serializer, tx_prefix->vout, tx_prefix->vout_count)) return 0;
    
    // FIELD(extra) - vector of bytes
    if (!tx_write_varint(serializer, tx_prefix->extra_len)) return 0;
    if (tx_prefix->extra_len > 0) {
        if (!tx_write_bytes(serializer, tx_prefix->extra, tx_prefix->extra_len)) return 0;
    }
    
    return !serializer->error;
}

// Main function: Compute transaction prefix hash
int monero_get_transaction_prefix_hash(const transaction_prefix_t *tx_prefix, uint8_t hash_out[32]) {
    if (!tx_prefix || !hash_out) {
        return 0;
    }
    
    // Allocate serialization buffer
    uint8_t *buffer = malloc(MAX_TX_BUFFER_SIZE);
    if (!buffer) {
        return 0;
    }
    
    // Initialize serializer
    tx_serializer_t serializer;
    if (!tx_serializer_init(&serializer, buffer, MAX_TX_BUFFER_SIZE)) {
        free(buffer);
        return 0;
    }
    
    // Serialize transaction prefix
    int result = tx_serialize_prefix(&serializer, tx_prefix);
    if (!result || serializer.error) {
        free(buffer);
        return 0;
    }
    
    // Compute Keccak-256 hash (cn_fast_hash equivalent)
    keccak_256(buffer, serializer.position, hash_out);
    
    free(buffer);
    return 1;
}

// Helper function implementations

int tx_create_txin_to_key(txin_v_t *input, uint64_t amount, 
                         const uint64_t *key_offsets, size_t key_offsets_count,
                         const uint8_t key_image[32]) {
    if (!input || !key_offsets || !key_image || key_offsets_count == 0) {
        return 0;
    }
    
    input->type = TXIN_TO_KEY;
    input->variant.to_key.amount = amount;
    input->variant.to_key.key_offsets_count = key_offsets_count;
    
    // Allocate and copy key offsets
    input->variant.to_key.key_offsets = malloc(key_offsets_count * sizeof(uint64_t));
    if (!input->variant.to_key.key_offsets) {
        return 0;
    }
    memcpy(input->variant.to_key.key_offsets, key_offsets, key_offsets_count * sizeof(uint64_t));
    
    // Copy key image
    memcpy(input->variant.to_key.k_image, key_image, 32);
    
    return 1;
}

int tx_create_txout_to_key(tx_out_t *output, uint64_t amount, const uint8_t public_key[32]) {
    if (!output || !public_key) {
        return 0;
    }
    
    output->amount = amount;
    output->target.type = TXOUT_TO_KEY;
    memcpy(output->target.variant.to_key.key, public_key, 32);
    
    return 1;
}

int tx_create_txout_to_tagged_key(tx_out_t *output, uint64_t amount, 
                                 const uint8_t public_key[32], uint8_t view_tag) {
    if (!output || !public_key) {
        return 0;
    }
    
    output->amount = amount;
    output->target.type = TXOUT_TO_TAGGED_KEY;
    memcpy(output->target.variant.to_tagged_key.key, public_key, 32);
    output->target.variant.to_tagged_key.view_tag[0] = view_tag;
    
    return 1;
}

// Helper function to parse varint from buffer (for testing/debugging)
size_t tx_parse_varint(const uint8_t* buffer, size_t max_len, uint64_t* result) {
    if (!buffer || !result || max_len == 0) {
        *result = 0;
        return 0;
    }
    
    *result = 0;
    size_t pos = 0;
    int shift = 0;
    
    while (pos < max_len && shift < 64) {  // Prevent overflow
        uint8_t byte = buffer[pos++];
        *result |= ((uint64_t)(byte & 0x7F)) << shift;
        
        // If continuation bit is not set, we're done
        if ((byte & 0x80) == 0) {
            return pos;
        }
        shift += 7;
        
        // Safety check - varint shouldn't be longer than 10 bytes for 64-bit
        if (pos > 10) {
            *result = 0;
            return 0;
        }
    }
    
    // If we exit the loop without finding end, it's malformed
    *result = 0;
    return 0;
}

int tx_prefix_init(transaction_prefix_t *tx_prefix) {
    if (!tx_prefix) {
        return 0;
    }
    
    memset(tx_prefix, 0, sizeof(transaction_prefix_t));
    tx_prefix->version = 1;  // Default version
    
    return 1;
}

void tx_prefix_free(transaction_prefix_t *tx_prefix) {
    if (!tx_prefix) {
        return;
    }
    
    // Free input key_offsets arrays
    if (tx_prefix->vin) {
        for (size_t i = 0; i < tx_prefix->vin_count; i++) {
            if (tx_prefix->vin[i].type == TXIN_TO_KEY && tx_prefix->vin[i].variant.to_key.key_offsets) {
                free(tx_prefix->vin[i].variant.to_key.key_offsets);
            }
            if (tx_prefix->vin[i].type == TXIN_TO_SCRIPT && tx_prefix->vin[i].variant.to_script.sigset) {
                free(tx_prefix->vin[i].variant.to_script.sigset);
            }
            if (tx_prefix->vin[i].type == TXIN_TO_SCRIPTHASH) {
                if (tx_prefix->vin[i].variant.to_scripthash.script_keys) {
                    free(tx_prefix->vin[i].variant.to_scripthash.script_keys);
                }
                if (tx_prefix->vin[i].variant.to_scripthash.sigset) {
                    free(tx_prefix->vin[i].variant.to_scripthash.sigset);
                }
            }
        }
        free(tx_prefix->vin);
    }
    
    // Free output script arrays
    if (tx_prefix->vout) {
        for (size_t i = 0; i < tx_prefix->vout_count; i++) {
            if (tx_prefix->vout[i].target.type == TXOUT_TO_SCRIPT) {
                if (tx_prefix->vout[i].target.variant.to_script.keys) {
                    free(tx_prefix->vout[i].target.variant.to_script.keys);
                }
                if (tx_prefix->vout[i].target.variant.to_script.script) {
                    free(tx_prefix->vout[i].target.variant.to_script.script);
                }
            }
        }
        free(tx_prefix->vout);
    }
    
    // Free extra data
    if (tx_prefix->extra) {
        free(tx_prefix->extra);
    }
    
    memset(tx_prefix, 0, sizeof(transaction_prefix_t));
}