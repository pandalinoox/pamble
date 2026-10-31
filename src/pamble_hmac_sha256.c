#include "pamble/pamble_hmac_sha256.h"

#include <string.h>

#define BYTES_PER_BLOCK 64

#define IPAD 0x36
#define OPAD 0x5c

/*
 * @brief Normalizes an HMAC key to a single block length.
 *
 * Keys longer than the block size are hashed with SHA-256; shorter keys are
 * copied as-is (an empty, possibly NULL, key copies nothing). The result is
 * right-padded with zero bytes to fill a full block.
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
    if (key_length != 0) {
      memcpy(normalized_key, key, key_length);
    }
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
 * @brief Initializes an HMAC-SHA256 context.
 *
 * Normalizes the supplied key, derives the inner and outer keys, and
 * initializes the corresponding SHA-256 contexts.
 *
 * @param ctx HMAC-SHA256 context to initialize.
 * @param key Key data.
 * @param key_length Number of bytes in key.
 *
 * @return PAMBLE_OK if the context was initialized successfully.
 * @return PAMBLE_INVALID_ARGUMENT if ctx is NULL, or if key is NULL while
 *         key_length is non-zero.
 */
pamble_status pamble_hmac_sha256_init(pamble_hmac_sha256_ctx *ctx,
                                      const uint8_t *key, size_t key_length) {

  if (ctx == NULL) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  pamble_status status;

  uint8_t normalized_key[BYTES_PER_BLOCK];

  status = normalize_key(key, key_length, normalized_key);
  PAMBLE_RETURN_IF_ERROR(status);

  pamble_sha256_init(&ctx->inner);
  uint8_t inner_key[BYTES_PER_BLOCK];
  key_xor(normalized_key, IPAD, inner_key);
  pamble_sha256_update(&ctx->inner, inner_key, BYTES_PER_BLOCK);

  pamble_sha256_init(&ctx->outer);
  uint8_t outer_key[BYTES_PER_BLOCK];
  key_xor(normalized_key, OPAD, outer_key);
  pamble_sha256_update(&ctx->outer, outer_key, BYTES_PER_BLOCK);

  return PAMBLE_OK;
}

/*
 * @brief Updates an HMAC-SHA256 context with message data.
 *
 * Adds the supplied message data to the inner SHA-256 computation.
 *
 * @param ctx HMAC-SHA256 context to update.
 * @param message Message data to authenticate.
 * @param message_length Number of bytes in message.
 *
 * @return PAMBLE_OK if the context was updated successfully.
 * @return PAMBLE_INVALID_ARGUMENT if ctx is NULL, or if message is NULL
 *         while message_length is non-zero.
 */
pamble_status pamble_hmac_sha256_update(pamble_hmac_sha256_ctx *ctx,
                                        const uint8_t *message,
                                        size_t message_length) {
  if (ctx == NULL) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  if (message == NULL && message_length != 0) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  return pamble_sha256_update(&ctx->inner, message, message_length);
}

/*
 * @brief Finalizes an HMAC-SHA256 computation and produces the digest.
 *
 * Finalizes the inner SHA-256 computation, adds the resulting digest to the
 * outer SHA-256 computation, and writes the resulting HMAC to output_buffer.
 *
 * @param ctx HMAC-SHA256 context containing the message state.
 * @param output_buffer Output buffer for the 32-byte HMAC digest.
 *
 * @return PAMBLE_OK if finalization completed successfully.
 * @return PAMBLE_INVALID_ARGUMENT if ctx is NULL, or if the underlying
 *         SHA-256 finalization fails.
 */
pamble_status pamble_hmac_sha256_final(
    pamble_hmac_sha256_ctx *ctx,
    uint8_t output_buffer[static PAMBLE_SHA256_DIGEST_LENGTH]) {

  if (ctx == NULL) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  pamble_status status;

  uint8_t inner_hash[PAMBLE_SHA256_DIGEST_LENGTH];
  status = pamble_sha256_final(&ctx->inner, inner_hash);
  PAMBLE_RETURN_IF_ERROR(status);
  status = pamble_sha256_update(&ctx->outer, inner_hash,
                                PAMBLE_SHA256_DIGEST_LENGTH);

  PAMBLE_RETURN_IF_ERROR(status);
  status = pamble_sha256_final(&ctx->outer, output_buffer);
  PAMBLE_RETURN_IF_ERROR(status);

  return PAMBLE_OK;
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

  pamble_hmac_sha256_ctx ctx;

  status = pamble_hmac_sha256_init(&ctx, key, key_length);
  PAMBLE_RETURN_IF_ERROR(status);

  status = pamble_hmac_sha256_update(&ctx, message, message_length);
  PAMBLE_RETURN_IF_ERROR(status);

  status = pamble_hmac_sha256_final(&ctx, output_buffer);
  PAMBLE_RETURN_IF_ERROR(status);

  return PAMBLE_OK;
}
