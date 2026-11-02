#pragma once

#include "pamble/pamble_status.h"

#include <stddef.h>
#include <stdint.h>

#define PAMBLE_PBKDF2_ITERATIONS (600 * 1000)

/*
 * @brief Derives a key from a password and salt using PBKDF2-HMAC-SHA256.
 *
 * This is the one-shot PBKDF2 interface. It derives each 32-byte output
 * block via repeated HMAC-SHA256 applications and concatenates them,
 * truncating the last block as needed, to fill dk_length bytes.
 *
 * @param password_length Number of bytes in password.
 * @param password Password data used as the HMAC key.
 * @param salt_length Number of bytes in salt.
 * @param salt Salt data.
 * @param dk_length Desired length, in bytes, of the derived key.
 * @param derived_key Output buffer for the derived key, sized dk_length.
 *
 * @return PAMBLE_OK if the key was derived successfully.
 * @return PAMBLE_SIZE_OVERFLOW if dk_length requires more than
 *         UINT32_MAX blocks.
 * @return Any error propagated from the underlying pamble_hmac_sha256
 *         calls.
 */
pamble_status pamble_pbkdf2(size_t password_length,
                            const uint8_t password[static password_length],
                            size_t salt_length,
                            const uint8_t salt[static salt_length],
                            size_t dk_length,
                            uint8_t derived_key[static dk_length]);
