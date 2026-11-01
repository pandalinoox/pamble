#pragma once

#include "pamble/pamble_aes.h"
#include "pamble/pamble_status.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PAMBLE_AES_CTR_NONCE_BYTES 12
#define PAMBLE_AES_CTR_COUNTER_BYTES 4
#define PAMBLE_AES_CTR_BLOCK_BYTES                                             \
  (PAMBLE_AES_CTR_NONCE_BYTES + PAMBLE_AES_CTR_COUNTER_BYTES)

/*
 * @brief AES-CTR counter block, split into nonce and block counter.
 *
 * A counter block is the 16-byte value that AES encrypts to produce one block
 * of keystream. It is laid out as a 12-byte nonce followed by a 4-byte
 * big-endian counter:
 *
 *   bytes  0..11  nonce  (never modified by this module)
 *   bytes 12..15  value  (most significant byte first)
 *
 * After each keystream block is generated, value is incremented by one. The
 * counter does not carry into the nonce, so one (key, nonce) pair can protect
 * at most 2^32 blocks (64 GiB). Reaching that limit is reported as
 * PAMBLE_COUNTER_EXHAUSTED rather than wrapping around.
 *
 * Reusing a (key, nonce, counter) combination for two different messages
 * reveals the XOR of the two plaintexts. Callers must ensure every message
 * encrypted under one key gets a unique nonce.
 */
typedef struct {
  uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint8_t value[PAMBLE_AES_CTR_COUNTER_BYTES];
} pamble_aes_ctr_counter_block;

/*
 * @brief AES-256-CTR streaming context.
 *
 * Holds everything needed to encrypt or decrypt a message in several calls to
 * pamble_aes_ctr_update:
 *
 *   expanded_aes_keys  AES-256 key schedule (secret key material).
 *   counter            Counter block for the next keystream block to generate.
 *   keystream_block    Most recently generated keystream block (secret).
 *   keystream_offset   Number of bytes of keystream_block already consumed;
 *                      PAMBLE_AES_BLOCK_SIZE means a new block is needed.
 *   exhausted_counter  True once the final counter value (all 0xFF) has been
 *                      used; no further keystream can be generated.
 *
 * The fields are public so the context can live on the caller's stack but
 * should be treated as opaque. The context holds secrets and must be wiped
 * with pamble_aes_ctr_cleanup when no longer needed. A context must not be
 * used from several threads at once.
 */
typedef struct {
  pamble_aes256_key expanded_aes_keys;
  pamble_aes_ctr_counter_block counter;
  uint8_t keystream_block[PAMBLE_AES_BLOCK_SIZE];
  uint8_t keystream_offset;
  bool exhausted_counter;
} pamble_aes_ctr_ctx;

/*
 * @brief Serializes a counter block into its 16-byte AES input form.
 *
 * Writes the 12 nonce bytes followed by the 4 counter bytes, which is the
 * exact block that is fed to the AES cipher.
 *
 * @param counter_block Counter block to serialize.
 * @param output_buffer Output for the 16-byte serialized counter block.
 */
void pamble_aes_ctr_flatten_counter_block(
    const pamble_aes_ctr_counter_block *counter_block,
    uint8_t output_buffer[static PAMBLE_AES_CTR_BLOCK_BYTES]);

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
                    pamble_aes_ctr_counter_block initial_counter);

/*
 * @brief Encrypts or decrypts the next chunk of a message.
 *
 * XORs input_message with the keystream and writes the result to
 * output_buffer. CTR mode is symmetric, so the same call encrypts plaintext
 * and decrypts ciphertext.
 *
 * Messages may be processed in chunks of any size: splitting a message across
 * several calls gives the same output as a single call, because unused
 * keystream bytes are carried over between calls.
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
                      uint8_t output_buffer[static input_message_length]);

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
pamble_status pamble_aes_ctr_cleanup(pamble_aes_ctr_ctx *ctx);

/*
 * @brief Encrypts or decrypts a whole message in one call.
 *
 * One-shot interface: initializes ctx, processes the message and wipes ctx
 * again. ctx is only scratch space supplied by the caller, so no state is
 * kept after a successful call. Encryption and decryption are the same
 * operation.
 *
 * ctx is wiped on every path that gets past argument validation, including
 * when processing fails, so no key material is left behind on error. When
 * the arguments are rejected, ctx is not touched.
 *
 * @param ctx Scratch context used for the operation.
 * @param key 32-byte AES-256 key.
 * @param initial_counter Counter block used for the first keystream block.
 * @param input_message Data to process.
 * @param input_message_length Number of bytes in input_message.
 * @param output_buffer Output for input_message_length bytes; may be the same
 *        buffer as input_message.
 *
 * @return PAMBLE_OK if the message was processed successfully.
 * @return PAMBLE_INVALID_ARGUMENT if ctx is NULL, or if input_message is NULL
 *         while input_message_length is non-zero.
 * @return PAMBLE_COUNTER_EXHAUSTED if the message is longer than the counter
 *         allows (see pamble_aes_ctr_update).
 */
pamble_status
pamble_aes_ctr_crypt(pamble_aes_ctr_ctx *ctx,
                     const uint8_t key[static PAMBLE_AES256_KEY_SIZE],
                     pamble_aes_ctr_counter_block initial_counter,
                     const uint8_t *input_message, size_t input_message_length,
                     uint8_t output_buffer[static input_message_length]);
