#pragma once

#include "pamble/pamble_status.h"

#include <stddef.h>
#include <stdint.h>

#define PAMBLE_PBKDF2_ITERATIONS (600 * 1000)

/*
 * @brief Frees a derived key previously allocated by pamble_pbkdf2.
 *
 * @param derived_key Derived key buffer to free. NULL is a no-op.
 */
void pamble_free_pbkdf2_dk(uint8_t *derived_key);

/*
 * @brief Derives a key from a password and salt using PBKDF2-HMAC-SHA256.
 *
 * This is the one-shot PBKDF2 interface. It derives each 32-byte output
 * block via repeated HMAC-SHA256 applications and concatenates them,
 * truncating the last block as needed, to fill dk_length bytes.
 *
 * @param password Password data used as the HMAC key.
 * @param password_length Number of bytes in password.
 * @param salt Salt data.
 * @param salt_length Number of bytes in salt.
 * @param derived_key Output parameter; on success, set to a newly
 *                     allocated dk_length-byte buffer. Caller must free
 *                     it with pamble_free_pbkdf2_dk.
 * @param dk_length Desired length, in bytes, of the derived key.
 *                   Must be non-zero.
 *
 * @return PAMBLE_OK if the key was derived successfully.
 * @return PAMBLE_INVALID_ARGUMENT if password is NULL while
 *         password_length is non-zero, if salt is NULL while salt_length
 *         is non-zero, or if derived_key is NULL or dk_length is zero.
 * @return PAMBLE_SIZE_OVERFLOW if dk_length requires more than
 *         UINT32_MAX blocks, or if allocation fails.
 * @return Any error propagated from the underlying pamble_hmac_sha256
 *         calls.
 */
pamble_status pamble_pbkdf2(const uint8_t *password, size_t password_length,
                            const uint8_t *salt, size_t salt_length,
                            uint8_t **derived_key, size_t dk_length);
