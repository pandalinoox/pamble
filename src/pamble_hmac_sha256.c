#include "pamble/pamble_hmac_sha256.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BYTES_PER_BLOCK 64

#define IPAD 0x36
#define OPAD 0x5c

/*
 * @brief Normalizes an HMAC key to a single block length.
 *
 * Keys longer than the block size are hashed with SHA-256; shorter keys are
 * copied as-is. The result is right-padded with zero bytes to fill a full
 * block.
 *
 * @param key Key data to normalize.
 * @param key_length Number of bytes in key.
 * @param normalized_key Output buffer for the normalized, block-length key.
 *
 * @return PAMBLE_OK if the key was normalized successfully.
 * @return PAMBLE_INVALID_ARGUMENT if key is NULL while key_length is
 *         non-zero.
 */
static pamble_status
normalize_key(const uint8_t *key, size_t key_length,
              uint8_t normalized_key[static BYTES_PER_BLOCK]) {

  if (key == NULL && key_length != 0) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  pamble_status status;

  size_t normalized_length;

  if (key_length > BYTES_PER_BLOCK) {
    status = pamble_sha256(key, key_length, normalized_key);
    PAMBLE_RETURN_IF_ERROR(status);
    normalized_length = PAMBLE_SHA256_DIGEST_LENGTH;
  } else {
    memcpy(normalized_key, key, key_length);
    normalized_length = key_length;
  }

  memset(normalized_key + normalized_length, 0,
         BYTES_PER_BLOCK - normalized_length);

  return PAMBLE_OK;
}

/*
 * @brief XORs a normalized key with a repeated byte value.
 *
 * Used to derive the inner (ipad) and outer (opad) key from the normalized
 * HMAC key.
 *
 * @param normalized_key Block-length normalized key.
 * @param value Byte value to XOR against every key byte.
 * @param output_buffer Output buffer for the resulting block-length key.
 */
static void key_xor(const uint8_t normalized_key[static BYTES_PER_BLOCK],
                    const uint8_t value,
                    uint8_t output_buffer[BYTES_PER_BLOCK]) {

  for (int i = 0; i < BYTES_PER_BLOCK; i++) {
    output_buffer[i] = normalized_key[i] ^ value;
  }
}

/*
 * @brief Concatenates two byte arrays into a single output buffer.
 *
 * @param arr1 First array.
 * @param arr1_length Number of bytes in arr1.
 * @param arr2 Second array.
 * @param arr2_length Number of bytes in arr2.
 * @param output_buffer Output buffer for the concatenated result, sized
 *                      arr1_length + arr2_length.
 */
static void array_concat(const uint8_t *arr1, size_t arr1_length,
                         const uint8_t *arr2, size_t arr2_length,
                         uint8_t output_buffer[arr1_length + arr2_length]) {
  memcpy(output_buffer, arr1, arr1_length);
  memcpy(output_buffer + arr1_length, arr2, arr2_length);
}

/*
 * @brief Computes the HMAC-SHA256 of a message under a given key.
 *
 * This is the one-shot HMAC-SHA256 interface. It normalizes the key,
 * derives the inner and outer keys, and computes
 * SHA256((key XOR opad) || SHA256((key XOR ipad) || message)),
 * writing the resulting digest to output_buffer.
 *
 * @param key Key data.
 * @param key_length Number of bytes in key.
 * @param message Message data to authenticate.
 * @param message_length Number of bytes in message.
 * @param output_buffer Output buffer for the 32-byte HMAC digest.
 *
 * @return PAMBLE_OK if the HMAC was computed successfully.
 * @return PAMBLE_INVALID_ARGUMENT if key is NULL while key_length is
 *         non-zero, or if message is NULL while message_length is non-zero.
 */
pamble_status
pamble_hmac_sha256(const uint8_t *key, size_t key_length,
                   const uint8_t *message, size_t message_length,
                   uint8_t output_buffer[static PAMBLE_SHA256_DIGEST_LENGTH]) {

  if (key == NULL && key_length != 0) {
    return PAMBLE_INVALID_ARGUMENT;
  }
  if (message == NULL && message_length != 0) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  pamble_status status;

  uint8_t normalized_key[BYTES_PER_BLOCK];

  status = normalize_key(key, key_length, normalized_key);
  PAMBLE_RETURN_IF_ERROR(status);

  uint8_t inner_key[BYTES_PER_BLOCK];
  uint8_t outer_key[BYTES_PER_BLOCK];

  key_xor(normalized_key, IPAD, inner_key);

  key_xor(normalized_key, OPAD, outer_key);

  size_t inner_hash_input_size = BYTES_PER_BLOCK + message_length;
  size_t outer_hash_input_size = BYTES_PER_BLOCK + PAMBLE_SHA256_DIGEST_LENGTH;

  uint8_t inner_hash_input[inner_hash_input_size];
  uint8_t outer_hash_input[outer_hash_input_size];

  uint8_t inner_hash[PAMBLE_SHA256_DIGEST_LENGTH];
  uint8_t outer_hash[PAMBLE_SHA256_DIGEST_LENGTH];

  array_concat(inner_key, BYTES_PER_BLOCK, message, message_length,
               inner_hash_input);

  status = pamble_sha256(inner_hash_input, inner_hash_input_size, inner_hash);
  PAMBLE_RETURN_IF_ERROR(status);

  array_concat(outer_key, BYTES_PER_BLOCK, inner_hash,
               PAMBLE_SHA256_DIGEST_LENGTH, outer_hash_input);

  status = pamble_sha256(outer_hash_input, outer_hash_input_size, outer_hash);
  PAMBLE_RETURN_IF_ERROR(status);

  memcpy(output_buffer, outer_hash, PAMBLE_SHA256_DIGEST_LENGTH);

  return PAMBLE_OK;
}
