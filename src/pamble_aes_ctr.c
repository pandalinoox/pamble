#include "pamble/pamble_aes_ctr.h"

#include <string.h>

/*
 * @brief Serializes a counter block into its 16-byte AES input form.
 *
 * Writes the 12 nonce bytes followed by the 4 counter bytes, which is the
 * exact block that is fed to the AES cipher. The counter stays big-endian as
 * stored.
 *
 * @param counter_block Counter block to serialize.
 * @param output_buffer Output for the 16-byte serialized counter block.
 */
void pamble_aes_ctr_flatten_counter_block(
    const pamble_aes_ctr_counter_block *counter_block,
    uint8_t output_buffer[static PAMBLE_AES_CTR_BLOCK_BYTES]) {

  memcpy(output_buffer, counter_block->nonce, PAMBLE_AES_CTR_NONCE_BYTES);
  memcpy(output_buffer + PAMBLE_AES_CTR_NONCE_BYTES, counter_block->value,
         PAMBLE_AES_CTR_COUNTER_BYTES);
}

/*
 * @brief Initializes an AES-256-CTR context.
 *
 * Expands the key, stores the initial counter block and marks the keystream
 * buffer as empty, so the first call to pamble_aes_ctr_update generates the
 * first keystream block from initial_counter.
 *
 * @param ctx Context to initialize.
 * @param key 32-byte AES-256 key.
 * @param initial_counter Counter block (nonce and starting counter value) used
 *        for the first keystream block.
 *
 * @return PAMBLE_OK if the context was initialized successfully.
 * @return PAMBLE_INVALID_ARGUMENT if ctx is NULL.
 */
pamble_status
pamble_aes_ctr_init(pamble_aes_ctr_ctx *ctx,
                    const uint8_t key[static PAMBLE_AES256_KEY_SIZE],
                    pamble_aes_ctr_counter_block initial_counter) {

  if (ctx == NULL) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  pamble_expand_aes256_keys(key, &ctx->expanded_aes_keys);

  ctx->counter = initial_counter;
  ctx->keystream_offset = PAMBLE_AES_BLOCK_SIZE;
  ctx->exhausted_counter = false;

  return PAMBLE_OK;
}

/*
 * @brief Adds one to the big-endian block counter.
 *
 * Increments the last counter byte and propagates the carry towards the most
 * significant byte, stopping as soon as a byte does not wrap to zero. Only
 * the counter is touched; the nonce is never modified. On an all-0xFF counter
 * the value wraps to all zeros, so callers must check is_counter_exhausted
 * first and never increment in that state.
 *
 * @param counter_block Counter block whose counter is incremented.
 */
static void
increment_counter_block(pamble_aes_ctr_counter_block *counter_block) {
  for (int i = PAMBLE_AES_CTR_COUNTER_BYTES - 1; i >= 0; i--) {
    counter_block->value[i]++;
    if (counter_block->value[i] != 0) {
      break;
    }
  }
}

/*
 * @brief Reports whether the counter is at its maximum value.
 *
 * The counter is at its maximum when every byte is 0xFF. That value is still
 * valid for one more keystream block, but it cannot be incremented without
 * wrapping and reusing counter values.
 *
 * @param counter_block Counter block to inspect.
 *
 * @return true if the counter is 0xFFFFFFFF, false otherwise.
 */
static bool is_counter_exhausted(pamble_aes_ctr_counter_block *counter_block) {
  for (size_t i = 0; i < PAMBLE_AES_CTR_COUNTER_BYTES; i++) {
    if (counter_block->value[i] != UINT8_MAX) {
      return false;
    }
  }
  return true;
}

/*
 * @brief Encrypts or decrypts the next chunk of a message.
 *
 * XORs input_message with the keystream and writes the result to
 * output_buffer. CTR mode is symmetric, so the same call encrypts plaintext
 * and decrypts ciphertext.
 *
 * Keystream is produced one 16-byte block at a time and consumed byte by
 * byte, so messages may be processed in chunks of any size: splitting a
 * message across several calls gives the same output as a single call. When a
 * block is generated, the counter is checked before it is advanced; if it was
 * already at its maximum, the context is flagged exhausted instead of
 * wrapping, and the next time a fresh block is needed
 * PAMBLE_COUNTER_EXHAUSTED is returned. The last block of the counter space
 * can therefore still be fully used.
 *
 * input_message and output_buffer may be the same buffer (in-place operation)
 * but must not otherwise overlap.
 *
 * @param ctx Context initialized with pamble_aes_ctr_init.
 * @param input_message Data to process.
 * @param input_message_length Number of bytes in input_message.
 * @param output_buffer Output for input_message_length bytes.
 *
 * @return PAMBLE_OK if all bytes were processed.
 * @return PAMBLE_INVALID_ARGUMENT if ctx is NULL, or if input_message is NULL
 *         while input_message_length is non-zero.
 * @return PAMBLE_COUNTER_EXHAUSTED if the message needs more keystream than the
 *         32-bit counter allows. Bytes processed before the limit was reached
 *         have already been written to output_buffer, and the context stays
 *         exhausted for any later call that needs a new keystream block.
 */
pamble_status
pamble_aes_ctr_update(pamble_aes_ctr_ctx *ctx, const uint8_t *input_message,
                      size_t input_message_length,
                      uint8_t output_buffer[static input_message_length]) {

  if (ctx == NULL) {
    return PAMBLE_INVALID_ARGUMENT;
  }
  if (input_message_length > 0 && input_message == NULL) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  for (size_t i = 0; i < input_message_length; i++) {
    if (ctx->keystream_offset == PAMBLE_AES_BLOCK_SIZE) {
      if (ctx->exhausted_counter) {
        return PAMBLE_COUNTER_EXHAUSTED;
      }

      uint8_t counter_plain_text[PAMBLE_AES_BLOCK_SIZE];
      pamble_aes_ctr_flatten_counter_block(&ctx->counter, counter_plain_text);
      pamble_aes256_encrypt_block(&ctx->expanded_aes_keys, counter_plain_text,
                                  ctx->keystream_block);

      ctx->exhausted_counter = is_counter_exhausted(&ctx->counter);
      if (!ctx->exhausted_counter) {

        increment_counter_block(&ctx->counter);
      }

      ctx->keystream_offset = 0;
    }
    output_buffer[i] =
        input_message[i] ^ ctx->keystream_block[ctx->keystream_offset];
    ctx->keystream_offset++;
  }

  return PAMBLE_OK;
}

/*
 * @brief Securely wipes an AES-256-CTR context.
 *
 * Overwrites the whole context, including the expanded key and any unused
 * keystream, with zeros using explicit_bzero so the compiler cannot optimize
 * the writes away. The context must be initialized again before reuse.
 *
 * @param ctx Context to wipe.
 *
 * @return PAMBLE_OK if the context was wiped.
 * @return PAMBLE_INVALID_ARGUMENT if ctx is NULL.
 */
pamble_status pamble_aes_ctr_cleanup(pamble_aes_ctr_ctx *ctx) {

  if (ctx == NULL) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  explicit_bzero(ctx, sizeof(*ctx));

  return PAMBLE_OK;
}

/*
 * @brief Encrypts or decrypts a whole message in one call.
 *
 * One-shot interface: initializes a context, processes the message and wipes
 * the context again. No state is kept after the call. Encryption and
 * decryption are the same operation.
 *
 * Cleanup runs even when processing fails, so no key material is left behind
 * on error; the first error encountered is the one returned. When the
 * arguments are rejected, the context is not initialized.
 *
 * @param key 32-byte AES-256 key.
 * @param nonce 12-byte nonce used for the first counter block.
 * @param input_message Data to process.
 * @param input_message_length Number of bytes in input_message.
 * @param output_buffer Output for input_message_length bytes; may be the same
 *        buffer as input_message.
 *
 * @return PAMBLE_OK if the message was processed successfully.
 * @return PAMBLE_INVALID_ARGUMENT if input_message is NULL while
 *         input_message_length is non-zero.
 * @return PAMBLE_COUNTER_EXHAUSTED if the message is longer than the counter
 *         allows (see pamble_aes_ctr_update).
 */
pamble_status
pamble_aes_ctr_crypt(const uint8_t key[static PAMBLE_AES256_KEY_SIZE],
                     uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES],
                     const uint8_t *input_message, size_t input_message_length,
                     uint8_t output_buffer[static input_message_length]) {

  if (input_message_length > 0 && input_message == NULL) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  pamble_status status;

  pamble_aes_ctr_ctx ctx;

  pamble_aes_ctr_counter_block initial_counter;

  memcpy(initial_counter.nonce, nonce, PAMBLE_AES_CTR_NONCE_BYTES);
  memset(initial_counter.value, 0, PAMBLE_AES_CTR_COUNTER_BYTES);

  status = pamble_aes_ctr_init(&ctx, key, initial_counter);
  PAMBLE_RETURN_IF_ERROR(status);

  status = pamble_aes_ctr_update(&ctx, input_message, input_message_length,
                                 output_buffer);

  pamble_status cleanup_status = pamble_aes_ctr_cleanup(&ctx);

  PAMBLE_RETURN_IF_ERROR(status);

  return cleanup_status;
}
