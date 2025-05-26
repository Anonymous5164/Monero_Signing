#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"
#include "pseudo_outputs.h"

int main() {
    const char* seed_hex = "887957b85b1e3529473437ff466c37ef59427a42ec20b296dc00db53f2857602";
    
    uint8_t seed[32], private_view_key[32], private_spend_key[32], public_view_key[32], public_spend_key[32];
    
    hex_to_bytes(seed_hex, seed);
    
    seed_to_keys(seed, private_spend_key, private_view_key);
    private_to_public_key(private_spend_key, public_spend_key);
    private_to_public_key(private_view_key, public_view_key);

    print_hex("Wallet Spend Key", private_spend_key, 32);
    print_hex("Wallet View Key", private_view_key, 32); 
    print_hex("Public Spend Key", public_spend_key, 32);
    print_hex("Public View Key", public_view_key, 32);

    char address[128] = {0}; // Buffer for the address
    uint8_t network_byte = 0x18; // Stagenet
    int address_len = public_keys_to_address(public_spend_key, public_view_key, address, sizeof(address), network_byte);

// Print results
if (address_len > 0) printf("Generated address (%d chars): %s\n", address_len, address);
else printf("Failed to generate address\n");

example_pseudo_output_generation();

     
    return 0;
}