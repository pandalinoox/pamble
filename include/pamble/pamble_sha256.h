#pragma once

#include "pamble/pamble_status.h"

#include <stddef.h>
#include <stdint.h>

#define PAMBLE_SHA256_DIGEST_LENGTH 32

typedef struct pamble_sha256_ctx pamble_sha256_ctx;

/*
 * @brief Initializes a SHA-256 context.
 *
 * Resets the hash state, internal message buffer, buffered message length,
 * and total message length.
 *
 * @param ctx SHA-256 context to initialize.
 *
 * @return PAMBLE_OK if the context was initialized successfully.
 * @return PAMBLE_INVALID_ARGUMENT if ctx is NULL.
 */
pamble_status pamble_sha256_init(pamble_sha256_ctx *ctx);

/*
 * @brief Updates a SHA-256 context with message data.
 *
 * Processes complete 512-bit blocks immediately and buffers any remaining
 * bytes for the next update or finalization operation.
 *
 * @param ctx SHA-256 context to update.
 * @param message Message data to hash.
 * @param message_length Number of bytes in message.
 *
 * @return PAMBLE_OK if the context was updated successfully.
 * @return PAMBLE_INVALID_ARGUMENT if ctx is NULL, or if message is NULL
 *         while message_length is non-zero.
 * @return PAMBLE_SIZE_OVERFLOW if the message length would exceed the
 *         maximum length representable by SHA-256.
 */
pamble_status pamble_sha256_update(pamble_sha256_ctx *ctx,
                                   const uint8_t *message,
                                   size_t message_length);

/*
 * @brief Finalizes a SHA-256 computation and produces the digest.
 *
 * Creates a copy of the supplied context, applies SHA-256 padding and the
 * original message length, processes the final block or blocks, and writes
 * the resulting digest to output_buffer.
 *
 * The supplied context is not modified.
 *
 * @param ctx SHA-256 context containing the message state.
 * @param output_buffer Output buffer for the 32-byte digest.
 *
 * @return PAMBLE_OK if finalization completed successfully.
 * @return PAMBLE_INVALID_ARGUMENT if an argument is NULL or the context
 *         contains an invalid buffered length.
 */
pamble_status
pamble_sha256_final(const pamble_sha256_ctx *ctx,
                    uint8_t output_buffer[PAMBLE_SHA256_DIGEST_LENGTH]);

/*
 * @brief Computes the SHA-256 digest of a message.
 *
 * This is the one-shot SHA-256 interface. It initializes a context, processes
 * the complete message, finalizes the computation, and writes the resulting
 * digest to output_buffer.
 *
 * @param message Message data to hash.
 * @param message_length Number of bytes in message.
 * @param output_buffer Output buffer for the 32-byte digest.
 *
 * @return PAMBLE_OK if the digest was computed successfully.
 * @return PAMBLE_INVALID_ARGUMENT if output_buffer is NULL, or if
 *         message is NULL while message_length is non-zero.
 * @return PAMBLE_SIZE_OVERFLOW if the message length exceeds the
 *         maximum length representable by SHA-256.
 */
pamble_status pamble_sha256(const uint8_t *message, size_t message_length,
                            uint8_t output_buffer[PAMBLE_SHA256_DIGEST_LENGTH]);
