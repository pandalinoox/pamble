#include "pamble/pamble_aes.h"

#include <criterion/criterion.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PAMBLE_HEX_BASE 16
#define HEX_BYTE_STRING_LENGTH 3

#define SP800_38A_KEY                                                          \
  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    char byte_string[HEX_BYTE_STRING_LENGTH] = {
        hex[i * 2],
        hex[(i * 2) + 1],
        '\0',
    };

    bytes[i] = (uint8_t)strtoul(byte_string, NULL, PAMBLE_HEX_BASE);
  }
}

static bool encrypts_to(const char *key_hex, const char *plain_hex,
                        const char *cipher_hex) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t plain_text[PAMBLE_AES_BLOCK_SIZE];
  uint8_t expected[PAMBLE_AES_BLOCK_SIZE];
  uint8_t actual[PAMBLE_AES_BLOCK_SIZE];

  hex_to_bytes(key_hex, key, sizeof(key));
  hex_to_bytes(plain_hex, plain_text, sizeof(plain_text));
  hex_to_bytes(cipher_hex, expected, sizeof(expected));

  pamble_aes256_key expanded_keys;
  pamble_expand_aes256_keys(key, &expanded_keys);
  pamble_aes256_encrypt_block(&expanded_keys, plain_text, actual);

  return memcmp(actual, expected, PAMBLE_AES_BLOCK_SIZE) == 0;
}

static void assert_encrypts_to(const char *key_hex, const char *plain_hex,
                               const char *cipher_hex) {
  cr_assert(encrypts_to(key_hex, plain_hex, cipher_hex),
            "AES-256 ciphertext does not match expected value");
}

static bool round_key_is(size_t round, const char *expected_hex) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t expected[PAMBLE_AES_BLOCK_SIZE];

  hex_to_bytes(SP800_38A_KEY, key, sizeof(key));
  hex_to_bytes(expected_hex, expected, sizeof(expected));

  pamble_aes256_key expanded_keys;
  pamble_expand_aes256_keys(key, &expanded_keys);

  return memcmp(expanded_keys.round_keys[round], expected,
                PAMBLE_AES_BLOCK_SIZE) == 0;
}

static void assert_round_key(size_t round, const char *expected_hex) {
  cr_assert(round_key_is(round, expected_hex),
            "round key %zu does not match FIPS-197 Appendix A.3", round);
}

/*
 * Known-answer tests.
 */

Test(pamble_aes, fips197_appendix_c3) {
  assert_encrypts_to(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089");
}

Test(pamble_aes, sp800_38a_f15_block1) {
  assert_encrypts_to(SP800_38A_KEY, "6bc1bee22e409f96e93d7e117393172a",
                     "f3eed1bdb5d2a03c064b5a7e3db181f8");
}

Test(pamble_aes, sp800_38a_f15_block2) {
  assert_encrypts_to(SP800_38A_KEY, "ae2d8a571e03ac9c9eb76fac45af8e51",
                     "591ccb10d410ed26dc5ba74a31362870");
}

Test(pamble_aes, sp800_38a_f15_block3) {
  assert_encrypts_to(SP800_38A_KEY, "30c81c46a35ce411e5fbc1191a0a52ef",
                     "b6ed21b99ca6f4f9f153e7b1beafed1d");
}

Test(pamble_aes, sp800_38a_f15_block4) {
  assert_encrypts_to(SP800_38A_KEY, "f69f2445df4f9b17ad2b417be66c3710",
                     "23304b7a39f9f3ff067d8d8f9e24ecc7");
}

Test(pamble_aes, all_zero_key_and_block) {
  assert_encrypts_to(
      "0000000000000000000000000000000000000000000000000000000000000000",
      "00000000000000000000000000000000", "dc95c078a2408989ad48a21492842087");
}

Test(pamble_aes, all_ones_key_and_block) {
  assert_encrypts_to(
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "ffffffffffffffffffffffffffffffff", "d5f93d6d3311cb309f23621b02fbd5e2");
}

/*
 * Key expansion.
 */

Test(pamble_aes, key_expansion_round0_is_key_first_half) {
  assert_round_key(0, "603deb1015ca71be2b73aef0857d7781");
}

Test(pamble_aes, key_expansion_round1_is_key_second_half) {
  assert_round_key(1, "1f352c073b6108d72d9810a30914dff4");
}

Test(pamble_aes, key_expansion_round2) {
  assert_round_key(2, "9ba354118e6925afa51a8b5f2067fcde");
}

Test(pamble_aes, key_expansion_last_round) {
  assert_round_key(PAMBLE_AES256_ROUNDS, "fe4890d1e6188d0b046df344706c631e");
}

/*
 * Behaviour.
 */

Test(pamble_aes, in_place_encryption) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t block[PAMBLE_AES_BLOCK_SIZE];
  uint8_t expected[PAMBLE_AES_BLOCK_SIZE];

  hex_to_bytes(SP800_38A_KEY, key, sizeof(key));
  hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", block, sizeof(block));
  hex_to_bytes("f3eed1bdb5d2a03c064b5a7e3db181f8", expected, sizeof(expected));

  pamble_aes256_key expanded_keys;
  pamble_expand_aes256_keys(key, &expanded_keys);
  pamble_aes256_encrypt_block(&expanded_keys, block, block);

  cr_assert_eq(memcmp(block, expected, PAMBLE_AES_BLOCK_SIZE), 0,
               "in-place encryption does not match expected value");
}

Test(pamble_aes, encryption_leaves_expanded_key_unchanged) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t block[PAMBLE_AES_BLOCK_SIZE] = {0};

  hex_to_bytes(SP800_38A_KEY, key, sizeof(key));

  pamble_aes256_key expanded_keys;
  pamble_expand_aes256_keys(key, &expanded_keys);

  const pamble_aes256_key before = expanded_keys;
  pamble_aes256_encrypt_block(&expanded_keys, block, block);

  cr_assert_eq(memcmp(&before, &expanded_keys, sizeof(before)), 0,
               "encrypting a block modified the expanded key");
}
