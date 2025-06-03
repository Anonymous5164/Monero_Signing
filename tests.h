#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tx_prefix_hash.h"
#include "test_vectors.h"

#ifndef TESTS_H
#define TESTS_H

// Just function declarations
void test_secret_to_public_roundtrip(void);
void test_key_derivation_symmetry(void);
void test_derived_key_consistency(void);
void test_key_image_properties(void);
void test_complete_pipeline(void);
void test_clsag_roundtrip(void);
void test_pseudo_output_balance(void);
void run_all_roundtrip_tests(void);
void debug_clsag_verification(void);
void test_tx_prefix_hash(void);
void test_multiple_functions_from_file(const char* filename, int max_tests_per_type);

#endif
