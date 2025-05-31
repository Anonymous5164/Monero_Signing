#ifndef UTILS_H
#define UTILS_H

#include "monero/monero.h"
#include "ed25519-donna/curve25519-donna-32bit.h"
#include "sha3.h"  // For keccak_256
#include <stdint.h>
#include <string.h> // For memcpy
#include <stdio.h>  // For printf                       
#include <stdlib.h> // For malloc/free

/**
 * Derives Monero spend and view private keys from seed
 * @param seed          Input seed, 32 bytes
 * @param spend_key     Output spend key, 32 bytes
 * @param view_key      Output view key, 32 bytes
 */
void seed_to_keys(uint8_t* seed, uint8_t* spend_key, uint8_t* view_key);

/**
 * Converts a Monero private key to public key
 * @param private_key   Input private key, 32 bytes
 * @param public_key    Output public key, 32 bytes
 * @return              1 if successful, 0 if failed
 */
int private_to_public_key(const uint8_t* private_key, uint8_t* public_key);

/**
 * Converts public keys to a Monero address
 * @param spend_pub_key    Public spend key, 32 bytes
 * @param view_pub_key     Public view key, 32 bytes
 * @param address          Output address buffer
 * @param address_size     Size of the address buffer
 * @param network_byte     Network byte (e.g., 0x12 for mainnet)
 * @return                 Length of the address if successful, 0 if failed
 */
int public_keys_to_address(const uint8_t* spend_pub_key, const uint8_t* view_pub_key, char* address, size_t address_size, uint8_t network_byte);

/**
 * Utility functions for data conversion and display
 */
void hex_to_bytes(const char* hex, uint8_t* bytes);
void print_hex(const char* label, const uint8_t* data, size_t length);

/**
 * Generate key derivation (shared secret)
 * @param tx_public_key     Transaction public key R
 * @param private_view_key  Private view key a
 * @param derivation        Output derivation D = a*R
 * @return                  1 if successful, 0 if failed
 */
int monero_generate_key_derivation(const uint8_t* tx_public_key, const uint8_t* private_view_key, uint8_t* derivation);

/**
 * Derive secret key for a specific output
 * @param derivation        Key derivation
 * @param output_index      Output index
 * @param private_spend_key Private spend key
 * @param ephemeral_secret  Output ephemeral secret key
 * @return                  1 if successful, 0 if failed
 */
int monero_derive_secret_key(const uint8_t* derivation, uint32_t output_index, 
                             const uint8_t* private_spend_key, uint8_t* ephemeral_secret);

/**
 * Derive public key for a specific output
 * @param derivation        Key derivation
 * @param output_index      Output index
 * @param public_spend_key  Public spend key
 * @param output_public_key Output public key
 * @return                  1 if successful, 0 if failed
 */
int monero_derive_public_key(const uint8_t* derivation, uint32_t output_index,
                             const uint8_t* public_spend_key, uint8_t* output_public_key);

/**
 * Generate key image for an output
 * @param public_key        One-time public key
 * @param secret_key        One-time secret key
 * @param key_image         Output key image
 * @return                  1 if successful, 0 if failed
 */
int monero_generate_key_image(const uint8_t* public_key, const uint8_t* secret_key, uint8_t* key_image);

/**
 * Hash to point on curve (for key image)
 * @param hash              Input hash
 * @param point             Output point
 * @return                  1 if successful, 0 if failed
 */
int monero_hash_to_point(const uint8_t* hash, uint8_t* point);

/**
 * Complete key image generation for a transaction output
 * @param tx_public_key     Transaction public key R
 * @param view_private_key  Private view key a
 * @param spend_private_key Private spend key b
 * @param output_index      Output index
 * @param key_image         Output key image
 * @param ephemeral_secret  Output ephemeral secret key
 * @return                  1 if successful, 0 if failed
 */
int monero_generate_key_image_for_output(const uint8_t* tx_public_key, const uint8_t* view_private_key, const uint8_t* spend_private_key, uint32_t output_index, uint8_t* key_image, uint8_t* ephemeral_secret);

int generate_deterministic_tx_key(uint32_t output_index, uint8_t tx_key[32]);

/**
 * Scalar operations
 */
int monero_sc_add(const uint8_t* a, const uint8_t* b, uint8_t* result);
int monero_sc_sub(const uint8_t* a, const uint8_t* b, uint8_t* result);
int monero_sc_mul(const uint8_t* a, const uint8_t* b, uint8_t* result);

/**
 * Point operations
 */
int monero_scalarmultKey(const uint8_t* P, const uint8_t* a, uint8_t* aP);
int monero_scalarmultBase(const uint8_t* a, uint8_t* aG);

# endif // UTILS_H