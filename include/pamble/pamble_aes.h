#pragma once

#include <stdint.h>

#define PAMBLE_AES_BLOCK_SIZE 16
#define PAMBLE_AES256_KEY_SIZE 32
#define PAMBLE_AES256_ROUNDS 14

/*
 * @brief Expanded AES-256 key schedule.
 *
 * Holds the 15 round keys (initial key addition plus 14 rounds) derived from
 * a 32-byte AES-256 key by pamble_expand_aes256_keys. Each round key is stored
 * as 16 bytes in the same column-major byte order as an AES block.
 *
 * The struct is public so it can live on the caller's stack and be shared
 * read-only between threads. It holds secret key material; wipe it when done.
 */
typedef struct {
  uint8_t round_keys[PAMBLE_AES256_ROUNDS + 1][PAMBLE_AES_BLOCK_SIZE];
} pamble_aes256_key;

/*
 * @brief Expands a 32-byte AES-256 key into its full key schedule.
 *
 * Runs the FIPS-197 key expansion once, producing all 15 round keys. Expand a
 * key once and reuse the result for every block encrypted under it.
 *
 * @param key 32-byte AES-256 key.
 * @param expanded_keys Output for the expanded key schedule.
 */
void pamble_expand_aes256_keys(const uint8_t key[static PAMBLE_AES256_KEY_SIZE],
                               pamble_aes256_key expanded_keys[static 1]);

/*
 * @brief Encrypts a single 16-byte block with AES-256.
 *
 * Applies the initial round-key addition, 13 full rounds (SubBytes,
 * ShiftRows, MixColumns, AddRoundKey), and a final round without
 * MixColumns. Only the forward cipher is provided; counter mode never needs
 * AES decryption.
 *
 * plain_text and cipher_text_buffer may point to the same block.
 *
 * @param aes256_keys Expanded key schedule from pamble_expand_aes256_keys.
 * @param plain_text 16-byte input block.
 * @param cipher_text_buffer Output for the 16-byte encrypted block.
 */
void pamble_aes256_encrypt_block(
    const pamble_aes256_key aes256_keys[static 1],
    const uint8_t plain_text[static PAMBLE_AES_BLOCK_SIZE],
    uint8_t cipher_text_buffer[static PAMBLE_AES_BLOCK_SIZE]);
