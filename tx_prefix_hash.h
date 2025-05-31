#ifndef TX_PREFIX_HASH_H
#define TX_PREFIX_HASH_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Maximum buffer sizes for serialization
#define MAX_TX_BUFFER_SIZE (1024 * 1024)  // 1MB max transaction
#define MAX_VARINT_SIZE 10                 // Max bytes for 64-bit varint
#define MAX_RING_SIZE 16                   // Reasonable ring size limit
#define MAX_OUTPUTS 64                     // Reasonable output limit
#define MAX_EXTRA_SIZE 1024                // Max extra field size

// Transaction input types (matching Monero's variant indices)
typedef enum {
    TXIN_GEN = 0xFF,
    TXIN_TO_SCRIPT = 0, 
    TXIN_TO_SCRIPTHASH = 1,
    TXIN_TO_KEY = 2
} txin_type_t;

// Transaction output target types (matching Monero's variant indices)
typedef enum {
    TXOUT_TO_SCRIPT = 0,
    TXOUT_TO_SCRIPTHASH = 1,
    TXOUT_TO_KEY = 2,
    TXOUT_TO_TAGGED_KEY = 3
} txout_target_type_t;

// Transaction input structures
typedef struct {
    uint64_t height;
} txin_gen_t;

typedef struct {
    uint8_t prev_hash[32];
    uint64_t prevout;
    uint8_t *sigset;
    size_t sigset_len;
} txin_to_script_t;

typedef struct {
    uint8_t prev_hash[32];
    uint64_t prevout;
    uint8_t *script_keys;     // Serialized txout_to_script
    size_t script_keys_len;
    uint8_t *sigset;
    size_t sigset_len;
} txin_to_scripthash_t;

typedef struct {
    uint64_t amount;
    uint64_t *key_offsets;
    size_t key_offsets_count;
    uint8_t k_image[32];      // Key image
} txin_to_key_t;

// Transaction input variant
typedef struct {
    txin_type_t type;
    union {
        txin_gen_t gen;
        txin_to_script_t to_script;
        txin_to_scripthash_t to_scripthash;
        txin_to_key_t to_key;
    } variant;
} txin_v_t;

// Transaction output target structures
typedef struct {
    uint8_t *keys;           // Array of public keys (32 bytes each)
    size_t keys_count;
    uint8_t *script;
    size_t script_len;
} txout_to_script_t;

typedef struct {
    uint8_t hash[32];
} txout_to_scripthash_t;

typedef struct {
    uint8_t key[32];         // Public key
} txout_to_key_t;

typedef struct {
    uint8_t key[32];         // Public key
    uint8_t view_tag[1];     // View tag optimization
} txout_to_tagged_key_t;

// Transaction output target variant
typedef struct {
    txout_target_type_t type;
    union {
        txout_to_script_t to_script;
        txout_to_scripthash_t to_scripthash;
        txout_to_key_t to_key;
        txout_to_tagged_key_t to_tagged_key;
    } variant;
} txout_target_v_t;

// Transaction output
typedef struct {
    uint64_t amount;
    txout_target_v_t target;
} tx_out_t;

// Transaction prefix structure (matches Monero exactly)
typedef struct {
    uint64_t version;        // Transaction version
    uint64_t unlock_time;    // Unlock time
    txin_v_t *vin;          // Transaction inputs
    size_t vin_count;
    tx_out_t *vout;         // Transaction outputs  
    size_t vout_count;
    uint8_t *extra;         // Extra data
    size_t extra_len;
} transaction_prefix_t;

// Serialization buffer for building transaction data
typedef struct {
    uint8_t *data;
    size_t capacity;
    size_t position;
    int error;
} tx_serializer_t;

// Function declarations

/**
 * @brief Initialize a transaction serializer
 * @param serializer Serializer to initialize
 * @param buffer Buffer to write to
 * @param capacity Buffer capacity
 * @return 1 on success, 0 on failure
 */
int tx_serializer_init(tx_serializer_t *serializer, uint8_t *buffer, size_t capacity);

/**
 * @brief Write raw bytes to serializer
 * @param serializer Target serializer
 * @param data Data to write
 * @param len Length of data
 * @return 1 on success, 0 on failure
 */
int tx_write_bytes(tx_serializer_t *serializer, const uint8_t *data, size_t len);

/**
 * @brief Write a varint to serializer (LEB128 format)
 * @param serializer Target serializer
 * @param value Value to write
 * @return 1 on success, 0 on failure
 */
int tx_write_varint(tx_serializer_t *serializer, uint64_t value);

/**
 * @brief Calculate size needed for varint encoding
 * @param value Value to encode
 * @return Number of bytes needed
 */
size_t tx_varint_size(uint64_t value);

/**
 * @brief Serialize a transaction input variant
 * @param serializer Target serializer
 * @param input Input to serialize
 * @return 1 on success, 0 on failure
 */
int tx_serialize_txin(tx_serializer_t *serializer, const txin_v_t *input);

/**
 * @brief Serialize a transaction output
 * @param serializer Target serializer
 * @param output Output to serialize
 * @return 1 on success, 0 on failure
 */
int tx_serialize_txout(tx_serializer_t *serializer, const tx_out_t *output);

/**
 * @brief Serialize a vector of transaction inputs
 * @param serializer Target serializer
 * @param inputs Array of inputs
 * @param count Number of inputs
 * @return 1 on success, 0 on failure
 */
int tx_serialize_txin_vector(tx_serializer_t *serializer, const txin_v_t *inputs, size_t count);

/**
 * @brief Serialize a vector of transaction outputs
 * @param serializer Target serializer
 * @param outputs Array of outputs
 * @param count Number of outputs
 * @return 1 on success, 0 on failure
 */
int tx_serialize_txout_vector(tx_serializer_t *serializer, const tx_out_t *outputs, size_t count);

/**
 * @brief Serialize the complete transaction prefix
 * @param serializer Target serializer
 * @param tx_prefix Transaction prefix to serialize
 * @return 1 on success, 0 on failure
 */
int tx_serialize_prefix(tx_serializer_t *serializer, const transaction_prefix_t *tx_prefix);

/**
 * @brief Compute transaction prefix hash (the main function!)
 * @param tx_prefix Transaction prefix to hash
 * @param hash_out Output buffer for 32-byte hash
 * @return 1 on success, 0 on failure
 */
int monero_get_transaction_prefix_hash(const transaction_prefix_t *tx_prefix, uint8_t hash_out[32]);

/**
 * @brief Helper function to create a txin_to_key input
 * @param input Output input structure
 * @param amount Input amount
 * @param key_offsets Ring member offsets
 * @param key_offsets_count Number of ring members
 * @param key_image Key image (32 bytes)
 * @return 1 on success, 0 on failure
 */
int tx_create_txin_to_key(txin_v_t *input, uint64_t amount, 
                         const uint64_t *key_offsets, size_t key_offsets_count,
                         const uint8_t key_image[32]);

/**
 * @brief Helper function to create a txout_to_key output
 * @param output Output structure
 * @param amount Output amount
 * @param public_key Destination public key (32 bytes)
 * @return 1 on success, 0 on failure
 */
int tx_create_txout_to_key(tx_out_t *output, uint64_t amount, const uint8_t public_key[32]);

/**
 * @brief Helper function to create a txout_to_tagged_key output
 * @param output Output structure
 * @param amount Output amount
 * @param public_key Destination public key (32 bytes) 
 * @param view_tag View tag byte
 * @return 1 on success, 0 on failure
 */
int tx_create_txout_to_tagged_key(tx_out_t *output, uint64_t amount, 
                                 const uint8_t public_key[32], uint8_t view_tag);

/**
 * @brief Parse a varint from buffer (for testing/debugging)
 * @param buffer Input buffer
 * @param max_len Maximum bytes to read
 * @param result Output value
 * @return Number of bytes consumed
 */
size_t tx_parse_varint(const uint8_t* buffer, size_t max_len, uint64_t* result);

/**
 * @brief Initialize a transaction prefix structure
 * @param tx_prefix Structure to initialize
 * @return 1 on success, 0 on failure
 */
int tx_prefix_init(transaction_prefix_t *tx_prefix);

/**
 * @brief Free allocated memory in transaction prefix
 * @param tx_prefix Structure to clean up
 */
void tx_prefix_free(transaction_prefix_t *tx_prefix);

#endif // TX_PREFIX_HASH_H