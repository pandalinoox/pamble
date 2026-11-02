#pragma once

#include "pamble/pamble_progress.h"
#include "pamble/pamble_status.h"

#include <stddef.h>
#include <stdint.h>

#define PAMBLE_CRYPTO_VERSION 1
#define PAMBLE_CRYPTO_STEP_COUNT 5

/*
 * @brief Everything an encrypt or decrypt call needs.
 *
 *   input_path       Encrypt: file or directory to archive. Decrypt: the
 *                    encrypted file.
 *   output_path      Encrypt: file to write. Decrypt: existing directory to
 *                    extract into.
 *   password         Password bytes. May be NULL only when password_length
 *                    is zero.
 *   password_length  Number of bytes in password.
 *   progress         Where stage updates go. Leave zeroed for silence.
 */
typedef struct {
  const char *input_path;
  const char *output_path;
  const uint8_t *password;
  size_t password_length;
  pamble_progress progress;
} pamble_crypto_payload;

/*
 * @brief Archives a path, encrypts it, authenticates it and writes the result.
 *
 * Runs five stages, each reported through payload.progress:
 *
 *   [1/5] archive the input path with pamble_archive_pack
 *   [2/5] derive the AES and MAC keys with PBKDF2 (counted in iterations)
 *   [3/5] encrypt the archive in place with AES-256-CTR (counted in bytes)
 *   [4/5] compute HMAC-SHA256 over header and ciphertext (counted in bytes)
 *   [5/5] write header, ciphertext and tag
 *
 * The output is first written to "<output_path>.tmp" and renamed into place
 * only when complete, so a failure never leaves a partial file at
 * output_path. Keys and the plaintext archive are wiped before returning.
 *
 * @param payload Paths, password and progress destination.
 *
 * @return PAMBLE_OK if the encrypted file was written.
 * @return PAMBLE_INVALID_ARGUMENT if a path is NULL, or password is NULL with
 *         a non-zero length.
 * @return PAMBLE_IO_ERROR if random bytes cannot be read or the output cannot
 *         be written.
 * @return PAMBLE_SIZE_OVERFLOW if allocation fails or sizes overflow.
 * @return Any error from pamble_archive_pack, pamble_pbkdf2 or AES-CTR.
 */
pamble_status pamble_encrypt_archive(pamble_crypto_payload payload);

/*
 * @brief Reads an encrypted file, verifies it, decrypts it and extracts it.
 *
 * Runs five stages, each reported through payload.progress:
 *
 *   [1/5] read the file and check its header and exact size
 *   [2/5] derive the AES and MAC keys with PBKDF2 (counted in iterations)
 *   [3/5] recompute and compare the HMAC tag (counted in bytes)
 *   [4/5] decrypt in place with AES-256-CTR (counted in bytes)
 *   [5/5] extract with pamble_archive_unpack
 *
 * Nothing is decrypted unless the tag matches, and nothing is extracted
 * unless decryption succeeds. A malformed or wrongly sized file is rejected
 * in stage 1, before the slow key derivation.
 *
 * @param payload Paths, password and progress destination.
 *
 * @return PAMBLE_OK if the archive was extracted.
 * @return PAMBLE_INVALID_ARGUMENT if a path is NULL, or password is NULL with
 *         a non-zero length.
 * @return PAMBLE_INVALID_ARCHIVE if the magic, version or file size is wrong.
 * @return PAMBLE_AUTHENTICATION_FAILED if the tag does not match: a wrong
 *         password or a modified file.
 * @return PAMBLE_IO_ERROR if the input cannot be read.
 * @return Any error from pamble_pbkdf2, AES-CTR or pamble_archive_unpack.
 */
pamble_status pamble_decrypt_archive(pamble_crypto_payload payload);
