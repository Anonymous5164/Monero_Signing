#include "utils.h"

void seed_to_keys(uint8_t* seed, uint8_t* spend_key, uint8_t* view_key) {
    memcpy(spend_key, seed, 32);
    
    uint8_t hash[32];
    keccak_256(spend_key, 32, hash);
    bignum256modm hash_modm;
    expand256_modm(hash_modm, hash, 32);
    contract256_modm(view_key, hash_modm);
}


int private_to_public_key(const uint8_t* private_key, uint8_t* public_key) {
    // Check if the private key is valid (reduced form)
    bignum256modm priv;
    expand_raw256_modm(priv, private_key);
    
    // Multiply base point by scalar (private key)
    ge25519 point;
    ge25519_scalarmult_base_wrapper(&point, priv);
    
    // Encode the resulting point to the public key
    ge25519_pack(public_key, &point);
    
    return 1;
}

int public_keys_to_address(const uint8_t* spend_pub_key, const uint8_t* view_pub_key, char* address, size_t address_size, uint8_t network_byte) {
    // 1. Create a buffer with network byte + public keys
    uint8_t data[65]; // 1 byte network + 32 bytes spend pub + 32 bytes view pub
    data[0] = network_byte;
    memcpy(data + 1, spend_pub_key, 32);
    memcpy(data + 33, view_pub_key, 32);
    
    // 2. Calculate checksum (first 4 bytes of keccak hash)
    uint8_t hash[32];
    keccak_256(data, 65, hash);
    
    // 3. Combine data and checksum
    uint8_t addr_data[69]; // 65 bytes data + 4 bytes checksum
    memcpy(addr_data, data, 65);
    memcpy(addr_data + 65, hash, 4);
    
    // 4. Encode with base58
    size_t res = xmr_base58_addr_encode_check(network_byte, addr_data + 1, 64, address, address_size);
    
    return res;
}

void hex_to_bytes(const char* hex, uint8_t* bytes) {
    size_t len = strlen(hex) / 2;
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2*i, "%02hhx", &bytes[i]);
    }
}

void print_hex(const char* label, const uint8_t* data, size_t length) {
    printf("%s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Generate key derivation (shared secret)
int monero_generate_key_derivation(const uint8_t* tx_public_key, const uint8_t* private_view_key, uint8_t* derivation) {
    // Convert private view key to scalar format
    bignum256modm view_key_modm;
    expand256_modm(view_key_modm, private_view_key, 32);
    
    // Decode transaction public key to a point
    ge25519 tx_pub_point;
    if (ge25519_unpack_vartime(&tx_pub_point, tx_public_key) != 0) {
        return 0; // Error: Invalid public key
    }
    
    // Compute r = 8 * (private_view_key * tx_public_key)
    ge25519 derivation_point;
    ge25519_scalarmult(&derivation_point, &tx_pub_point, view_key_modm);
    
    // Multiply by 8 (cofactor)
    ge25519_mul8(&derivation_point, &derivation_point);
    
    // Encode the resulting point to the derivation buffer
    ge25519_pack(derivation, &derivation_point);
    
    return 1;
}

// Derive secret key for a specific output
int monero_derive_secret_key(const uint8_t* derivation, uint32_t output_index, 
                             const uint8_t* private_spend_key, uint8_t* ephemeral_secret) {
    // 1. Compute Hs(derivation || output_index)
    uint8_t buff[32 + 8]; // derivation + varint output_index
    memcpy(buff, derivation, 32);
    
    // Encode output_index as varint
    int len = xmr_write_varint(buff + 32, 8, output_index);
    if (len <= 0) return 0;
    
    // Hash to scalar
    bignum256modm scalar;
    xmr_hash_to_scalar(scalar, buff, 32 + len);
    
    // 2. Compute secret = Hs(derivation || output_index) + private_spend_key
    bignum256modm spend_key_modm;
    expand256_modm(spend_key_modm, private_spend_key, 32);
    
    // Add scalars
    bignum256modm result;
    add256_modm(result, scalar, spend_key_modm);
    
    // Convert to bytes
    contract256_modm(ephemeral_secret, result);
    
    return 1;
}

// Derive public key for a specific output
int monero_derive_public_key(const uint8_t* derivation, uint32_t output_index,
                             const uint8_t* public_spend_key, uint8_t* output_public_key) {
    // 1. Compute Hs(derivation || output_index)
    uint8_t buff[32 + 8]; // derivation + varint output_index
    memcpy(buff, derivation, 32);
    
    // Encode output_index as varint
    int len = xmr_write_varint(buff + 32, 8, output_index);
    if (len <= 0) return 0;
    
    // Hash to scalar
    bignum256modm scalar;
    xmr_hash_to_scalar(scalar, buff, 32 + len);
    
    // 2. Compute Hs(derivation || output_index) * G
    ge25519 point1;
    ge25519_scalarmult_base_wrapper(&point1, scalar);
    
    // 3. Decode public_spend_key
    ge25519 point2;
    if (ge25519_unpack_vartime(&point2, public_spend_key) != 0) {
        return 0; // Error: Invalid public key
    }
    
    // 4. Compute output_public_key = Hs(derivation || output_index) * G + public_spend_key
    ge25519 result;
    ge25519_add(&result, &point1, &point2, 0);
    
    // 5. Encode the result
    ge25519_pack(output_public_key, &result);
    
    return 1;
}

// Generate key image for an output
int monero_generate_key_image(const uint8_t* public_key, const uint8_t* secret_key, uint8_t* key_image) {
    // 1. Hash the public key to a point on the curve
    ge25519 point;
    xmr_hash_to_ec(&point, public_key, 32);
    
    // 2. Multiply the point by the secret key
    bignum256modm secret_modm;
    expand256_modm(secret_modm, secret_key, 32);
    
    ge25519 key_image_point;
    ge25519_scalarmult(&key_image_point, &point, secret_modm);
    
    // 3. Encode the resulting point to the key image
    ge25519_pack(key_image, &key_image_point);
    
    return 1;
}

// Hash to point on curve (for key image)
int monero_hash_to_point(const uint8_t* hash, uint8_t* point) {
    ge25519 point_ge;
    xmr_hash_to_ec(&point_ge, hash, 32);
    ge25519_pack(point, &point_ge);
    return 1;
}

// To be refactored

int monero_generate_key_image_for_output(const uint8_t* tx_public_key, const uint8_t* view_private_key, const uint8_t* spend_private_key, uint32_t output_index, uint8_t* key_image, uint8_t* ephemeral_secret)        
{
    // 1. Generate key derivation: D = a*R
    uint8_t derivation[32];
    if (!monero_generate_key_derivation(tx_public_key, view_private_key, derivation))
        return 0;
    
    // 2. Derive one-time private key: x = Hs(D || i) + b
    if (!monero_derive_secret_key(derivation, output_index, spend_private_key, ephemeral_secret))
        return 0;
    
    // 3. Derive one-time public key: P = Hs(D || i)*G + B
    uint8_t one_time_public[32];
    // Calculate the public spend key from the private spend key
    uint8_t spend_public_key[32];
    monero_scalarmultBase(spend_private_key, spend_public_key);
    
    if (!monero_derive_public_key(derivation, output_index, spend_public_key, one_time_public))
        return 0;
    
    // 4. Generate key image: I = x*Hp(P)
    if (!monero_generate_key_image(one_time_public, ephemeral_secret, key_image))
        return 0;
    
    return 1;
}

// Scalar addition: result = a + b mod l
int monero_sc_add(const uint8_t* a, const uint8_t* b, uint8_t* result) {
    bignum256modm a_modm, b_modm, result_modm;
    expand256_modm(a_modm, a, 32);
    expand256_modm(b_modm, b, 32);
    add256_modm(result_modm, a_modm, b_modm);
    contract256_modm(result, result_modm);
    return 1;
}

// Scalar subtraction: result = a - b mod l
int monero_sc_sub(const uint8_t* a, const uint8_t* b, uint8_t* result) {
    bignum256modm a_modm, b_modm, result_modm;
    expand256_modm(a_modm, a, 32);
    expand256_modm(b_modm, b, 32);
    sub256_modm(result_modm, a_modm, b_modm);
    contract256_modm(result, result_modm);
    return 1;
}

// Scalar multiplication: result = a * b mod l
int monero_sc_mul(const uint8_t* a, const uint8_t* b, uint8_t* result) {
    bignum256modm a_modm, b_modm, result_modm;
    expand256_modm(a_modm, a, 32);
    expand256_modm(b_modm, b, 32);
    mul256_modm(result_modm, a_modm, b_modm);
    contract256_modm(result, result_modm);
    return 1;
}

// Point multiplication by scalar: aP = a * P
int monero_scalarmultKey(const uint8_t* P, const uint8_t* a, uint8_t* aP) {
    ge25519 point, result;
    bignum256modm scalar;
    
    if (ge25519_unpack_vartime(&point, P) != 0) {
        return 0; // Error: Invalid point
    }
    
    expand256_modm(scalar, a, 32);
    ge25519_scalarmult(&result, &point, scalar);
    ge25519_pack(aP, &result);
    return 1;
}

// Multiply generator by scalar: aG = a * G
int monero_scalarmultBase(const uint8_t* a, uint8_t* aG) {
    ge25519 result;
    bignum256modm scalar;
    
    expand256_modm(scalar, a, 32);
    ge25519_scalarmult_base_wrapper(&result, scalar);
    ge25519_pack(aG, &result);
    return 1;
}