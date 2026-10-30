#include "pamble/pamble_aes.h"

#include <stddef.h>

#define KEY_WORD_SIZE sizeof(uint32_t)
#define WORDS_PER_256KEY (PAMBLE_AES256_KEY_SIZE / KEY_WORD_SIZE)
#define WORDS_PER_BLOCK (PAMBLE_AES_BLOCK_SIZE / KEY_WORD_SIZE)
#define SUB_WORD_ONLY_POSITION (WORDS_PER_256KEY / 2)

#define KEY256_WORDS_ARRAY_SIZE (WORDS_PER_BLOCK * (PAMBLE_AES256_ROUNDS + 1))

#define EMS 4

#define BITS_PER_BYTES 8

#define SBOX_SIZE 256
#define RCON_SIZE 10

static const uint8_t AES_SBOX[SBOX_SIZE] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t AES_RCON[RCON_SIZE] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
};

typedef struct {
  uint8_t bytes[KEY_WORD_SIZE];
} key_word;

/*
 * @brief Loads the 32-byte key into the first eight key-schedule words.
 *
 * Word i holds key bytes 4i through 4i + 3, in order.
 *
 * @param key 32-byte AES-256 key.
 * @param words Key-schedule words; the first WORDS_PER_256KEY are written.
 */
static void
initialize_key256_words(const uint8_t key[static PAMBLE_AES256_KEY_SIZE],
                        key_word words[static KEY256_WORDS_ARRAY_SIZE]) {

  for (size_t i = 0; i < WORDS_PER_256KEY; i++) {
    for (size_t j = 0; j < KEY_WORD_SIZE; j++) {
      words[i].bytes[j] = key[(i * KEY_WORD_SIZE) + j];
    }
  }
}

/*
 * @brief Applies the AES S-box to each byte of a word (SubWord).
 *
 * @param word Input word.
 *
 * @return The substituted word.
 */
static key_word sub_word(key_word word) {
  key_word res;
  for (size_t i = 0; i < KEY_WORD_SIZE; i++) {
    res.bytes[i] = AES_SBOX[word.bytes[i]];
  }
  return res;
}

/*
 * @brief Rotates a word left by one byte (RotWord).
 *
 * [a0, a1, a2, a3] becomes [a1, a2, a3, a0].
 *
 * @param word Input word.
 *
 * @return The rotated word.
 */
static key_word rot_word(key_word word) {
  key_word res;
  for (size_t i = 0; i < KEY_WORD_SIZE; i++) {
    res.bytes[i] = word.bytes[i + 1 < KEY_WORD_SIZE ? i + 1 : 0];
  }
  return res;
}

/*
 * @brief XORs two key-schedule words byte by byte.
 *
 * @param word1 First word.
 * @param word2 Second word.
 *
 * @return word1 XOR word2.
 */
static key_word xor_key_word(key_word word1, key_word word2) {

  key_word res;
  for (size_t i = 0; i < KEY_WORD_SIZE; i++) {
    res.bytes[i] = word1.bytes[i] ^ word2.bytes[i];
  }
  return res;
}

/*
 * @brief Derives the remaining key-schedule words from the first eight.
 *
 * For each word i from 8 to 59, takes the previous word and, every eighth
 * word, applies RotWord, SubWord and the round constant; four words later it
 * applies SubWord alone (the extra AES-256 step). The result is XORed with
 * the word eight positions back.
 *
 * @param words Key-schedule words with the first WORDS_PER_256KEY filled in.
 */
static void
generate_key256_words(key_word words[static KEY256_WORDS_ARRAY_SIZE]) {

  for (size_t i = WORDS_PER_256KEY; i < KEY256_WORDS_ARRAY_SIZE; i++) {
    key_word temp = words[i - 1];
    if (i % WORDS_PER_256KEY == 0) {
      temp = sub_word(rot_word(temp));
      temp.bytes[0] ^= AES_RCON[(i / WORDS_PER_256KEY) - 1];
    } else if (i % WORDS_PER_256KEY == SUB_WORD_ONLY_POSITION) {
      temp = sub_word(temp);
    }

    words[i] = xor_key_word(words[i - WORDS_PER_256KEY], temp);
  }
}

/*
 * @brief Packs the key-schedule words into 15 round keys of 16 bytes.
 *
 * Round key r is words 4r through 4r + 3, laid out one word per state
 * column.
 *
 * @param words Complete key-schedule words.
 * @param expanded_keys Output for the round keys.
 */
static void update_key256_expanded_keys(
    const key_word words[static KEY256_WORDS_ARRAY_SIZE],
    pamble_aes256_key expanded_keys[static 1]) {

  for (size_t i = 0; i < PAMBLE_AES256_ROUNDS + 1; i++) {
    for (size_t j = 0; j < PAMBLE_AES_BLOCK_SIZE; j++) {
      expanded_keys->round_keys[i][j] =
          words[(i * WORDS_PER_BLOCK) + (j / KEY_WORD_SIZE)]
              .bytes[j % KEY_WORD_SIZE];
    }
  }
}

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
                               pamble_aes256_key expanded_keys[static 1]) {

  key_word words[KEY256_WORDS_ARRAY_SIZE];

  initialize_key256_words(key, words);

  generate_key256_words(words);

  update_key256_expanded_keys(words, expanded_keys);
}

/*
 * @brief Loads a 16-byte block into the 4x4 AES state.
 *
 * AES fills the state column by column: matrix[row][col] = block[row + 4 *
 * col].
 *
 * @param plain_text 16-byte input block.
 * @param matrix State to fill, indexed [row][col].
 */
static void plain_text_to_encryption_matrix(
    const uint8_t plain_text[static PAMBLE_AES_BLOCK_SIZE],
    uint8_t matrix[static EMS][EMS]) {

  for (size_t i = 0; i < EMS; i++) {
    for (size_t j = 0; j < EMS; j++) {
      matrix[i][j] = plain_text[(EMS * j) + i];
    }
  }
}

/*
 * @brief XORs a round key into the state (AddRoundKey).
 *
 * @param matrix State, indexed [row][col].
 * @param round_key 16-byte round key, in the same column-major order as a
 *                  block.
 */
static void
xor_matrix_keys(uint8_t matrix[static EMS][EMS],
                const uint8_t round_key[static PAMBLE_AES_BLOCK_SIZE]) {

  for (size_t i = 0; i < EMS; i++) {
    for (size_t j = 0; j < EMS; j++) {
      matrix[i][j] ^= round_key[(EMS * j) + i];
    }
  }
}

/*
 * @brief Applies the AES S-box to every byte of the state (SubBytes).
 *
 * @param matrix State, indexed [row][col].
 */
static void sub_bytes(uint8_t matrix[static EMS][EMS]) {

  for (size_t i = 0; i < EMS; i++) {
    for (size_t j = 0; j < EMS; j++) {
      uint8_t current_byte = matrix[i][j];
      matrix[i][j] = AES_SBOX[current_byte];
    }
  }
}

/*
 * @brief Rotates row r of the state left by r bytes (ShiftRows).
 *
 * @param matrix State, indexed [row][col].
 */
static void shift_rows(uint8_t matrix[static EMS][EMS]) {

  uint8_t temp[EMS];

  for (size_t i = 0; i < EMS; i++) {
    for (size_t j = 0; j < EMS; j++) {
      temp[j] = matrix[i][j];
    }
    for (size_t j = 0; j < EMS; j++) {
      matrix[i][j] = temp[(i + j) % EMS];
    }
  }
}

/*
 * @brief Multiplies two bytes in GF(2^8) with the AES polynomial.
 *
 * Uses shift-and-add, reducing by x^8 + x^4 + x^3 + x + 1 (0x1B) whenever
 * the running multiplicand overflows a byte.
 *
 * @param opr1 First factor.
 * @param opr2 Second factor.
 *
 * @return The product in GF(2^8).
 */
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static uint8_t gf_multiplication(uint8_t opr1, uint8_t opr2) {

  static const uint8_t CONST_01 = 0x01;
  static const uint8_t CONST_80 = 0x80;
  static const uint8_t CONST_1B = 0x1B;

  uint8_t result = 0;
  for (int i = 0; i < BITS_PER_BYTES; i++) {

    if (opr2 & CONST_01) {
      result ^= opr1;
    }

    if ((opr1 & CONST_80) != 0) {
      opr1 = (uint8_t)((opr1 << 1) ^ CONST_1B);
    } else {
      opr1 = (uint8_t)(opr1 << 1);
    }

    opr2 = (uint8_t)(opr2 >> 1);
  }

  return result;
}

/*
 * @brief Mixes each column of the state (MixColumns).
 *
 * Multiplies every column by the fixed matrix
 * [[2 3 1 1] [1 2 3 1] [1 1 2 3] [3 1 1 2]] in GF(2^8).
 *
 * @param matrix State, indexed [row][col].
 */
static void mix_cols(uint8_t matrix[static EMS][EMS]) {

  static const uint8_t CONST_02 = 0x02;
  static const uint8_t CONST_03 = 0x03;

  for (size_t col = 0; col < EMS; col++) {

    uint8_t ele1 = matrix[0][col];
    uint8_t ele2 = matrix[1][col];
    uint8_t ele3 = matrix[2][col];
    uint8_t ele4 = matrix[3][col];

    matrix[0][col] = gf_multiplication(ele1, CONST_02) ^
                     gf_multiplication(ele2, CONST_03) ^ ele3 ^ ele4;

    matrix[1][col] = ele1 ^ gf_multiplication(ele2, CONST_02) ^
                     gf_multiplication(ele3, CONST_03) ^ ele4;

    matrix[2][col] = ele1 ^ ele2 ^ gf_multiplication(ele3, CONST_02) ^
                     gf_multiplication(ele4, CONST_03);

    matrix[3][col] = gf_multiplication(ele1, CONST_03) ^ ele2 ^ ele3 ^
                     gf_multiplication(ele4, CONST_02);
  }
}

/*
 * @brief Runs the 13 full AES-256 rounds.
 *
 * Round r (1 to 13) applies SubBytes, ShiftRows, MixColumns, then
 * AddRoundKey with round_keys[r].
 *
 * @param round_keys All 15 round keys; entries 1 through 13 are used.
 * @param matrix State, indexed [row][col].
 */
static void
encryption_rounds(const uint8_t round_keys[static PAMBLE_AES256_ROUNDS + 1]
                                          [PAMBLE_AES_BLOCK_SIZE],
                  uint8_t matrix[static EMS][EMS]) {

  for (size_t round = 1; round < PAMBLE_AES256_ROUNDS; round++) {
    sub_bytes(matrix);
    shift_rows(matrix);
    mix_cols(matrix);
    xor_matrix_keys(matrix, round_keys[round]);
  }
}

/*
 * @brief Runs the final AES round, which has no MixColumns.
 *
 * @param round_key The last (15th) round key.
 * @param matrix State, indexed [row][col].
 */
static void
encryption_last_round(const uint8_t round_key[static PAMBLE_AES_BLOCK_SIZE],
                      uint8_t matrix[static EMS][EMS]) {

  sub_bytes(matrix);
  shift_rows(matrix);
  xor_matrix_keys(matrix, round_key);
}

/*
 * @brief Writes the 4x4 AES state out as a 16-byte block.
 *
 * Inverse of plain_text_to_encryption_matrix: block[row + 4 * col] =
 * matrix[row][col].
 *
 * @param matrix State, indexed [row][col].
 * @param cipher_text_buffer Output for the 16-byte block.
 */
static void matrix_to_cipher_text(
    uint8_t matrix[static EMS][EMS],
    uint8_t cipher_text_buffer[static PAMBLE_AES_BLOCK_SIZE]) {

  for (size_t i = 0; i < EMS; i++) {
    for (size_t j = 0; j < EMS; j++) {
      cipher_text_buffer[(EMS * j) + i] = matrix[i][j];
    }
  }
}

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
    uint8_t cipher_text_buffer[static PAMBLE_AES_BLOCK_SIZE]) {

  uint8_t matrix[EMS][EMS];

  plain_text_to_encryption_matrix(plain_text, matrix);

  xor_matrix_keys(matrix, aes256_keys->round_keys[0]);

  encryption_rounds(aes256_keys->round_keys, matrix);

  encryption_last_round(aes256_keys->round_keys[PAMBLE_AES256_ROUNDS], matrix);

  matrix_to_cipher_text(matrix, cipher_text_buffer);
}
