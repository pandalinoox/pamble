#pragma once

#include "pamble/pamble_sha256.h"
#include "pamble/pamble_status.h"

#include <stddef.h>
#include <stdint.h>

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
                   uint8_t output_buffer[static PAMBLE_SHA256_DIGEST_LENGTH]);
