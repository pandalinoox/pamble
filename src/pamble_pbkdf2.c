#include "pamble/pamble_hmac_sha256.h"
#include "pamble/pamble_pdkdf2.h"

#include <stdlib.h>
#include <string.h>

#define BYTES_PER_32_BITS sizeof(uint32_t)
#define BITS_PER_BYTE 8

/*
 * @brief Encodes a block index as 4 big-endian bytes (PBKDF2's INT(i)).
 *
 * @param block_no Block index to encode (1-based).
 * @param output_buffer Output buffer for the 4-byte encoding.
 */
static void int32_be(uint32_t block_no,
                     uint8_t output_buffer[static BYTES_PER_32_BITS]) {
  for (size_t i = 0; i < BYTES_PER_32_BITS; i++) {
    output_buffer[i] =
        (uint8_t)(block_no >> ((BYTES_PER_32_BITS - 1 - i) * BITS_PER_BYTE));
  }
}

/*
 * @brief Concatenates two byte arrays into a single output buffer.
 *
 * Either array may be NULL when its length is zero; empty arrays are skipped
 * so memcpy is never called with a NULL pointer.
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
  if (arr1_length != 0) {
    memcpy(output_buffer, arr1, arr1_length);
  }
  if (arr2_length != 0) {
    memcpy(output_buffer + arr1_length, arr2, arr2_length);
  }
}

/*
 * @brief Computes one PBKDF2 iteration and XORs it into the block total.
 *
 * @param password Password data used as the HMAC key.
 * @param password_length Number of bytes in password.
 * @param u_hash In/out buffer holding U_{j-1} on entry and U_j on exit.
 * @param t_hash In/out running XOR accumulator, updated with U_j.
 *
 * @return PAMBLE_OK on success, otherwise an error from pamble_hmac_sha256.
 */
static pamble_status
process_iteration(const uint8_t *password, size_t password_length,
                  uint8_t u_hash[PAMBLE_SHA256_DIGEST_LENGTH],
                  uint8_t t_hash[PAMBLE_SHA256_DIGEST_LENGTH]) {
  pamble_status status;

  status = pamble_hmac_sha256(password, password_length, u_hash,
                              PAMBLE_SHA256_DIGEST_LENGTH, u_hash);

  PAMBLE_RETURN_IF_ERROR(status);

  for (size_t i = 0; i < PAMBLE_SHA256_DIGEST_LENGTH; i++) {
    t_hash[i] ^= u_hash[i];
  }

  return PAMBLE_OK;
}

/*
 * @brief Derives a single PBKDF2 output block, T_i.
 *
 * @param password Password data used as the HMAC key.
 * @param password_length Number of bytes in password.
 * @param salt Salt data.
 * @param salt_length Number of bytes in salt.
 * @param block_no 1-based index of the block being derived.
 * @param t_hash Output buffer for the resulting 32-byte block.
 *
 * @return PAMBLE_OK on success, otherwise an error from pamble_hmac_sha256.
 */
static pamble_status
process_block(const uint8_t *password, size_t password_length,
              const uint8_t *salt, size_t salt_length, const uint32_t block_no,
              uint8_t t_hash[PAMBLE_SHA256_DIGEST_LENGTH]) {
  pamble_status status;

  uint8_t int32_be_out[BYTES_PER_32_BITS];
  int32_be(block_no, int32_be_out);

  uint8_t salt_concat_int32_be[salt_length + BYTES_PER_32_BITS];

  array_concat(salt, salt_length, int32_be_out, BYTES_PER_32_BITS,
               salt_concat_int32_be);

  uint8_t u_hash[PAMBLE_SHA256_DIGEST_LENGTH];

  status = pamble_hmac_sha256(password, password_length, salt_concat_int32_be,
                              salt_length + BYTES_PER_32_BITS, u_hash);

  PAMBLE_RETURN_IF_ERROR(status);

  memcpy(t_hash, u_hash, PAMBLE_SHA256_DIGEST_LENGTH);

  for (uint32_t j = 2; j <= PAMBLE_PBKDF2_ITERATIONS; j++) {
    status = process_iteration(password, password_length, u_hash, t_hash);

    PAMBLE_RETURN_IF_ERROR(status);
  }

  return PAMBLE_OK;
}

/*
 * @brief Copies a derived block into the output buffer, truncating it if
 *        fewer bytes than a full block remain to be filled.
 *
 * @param t_hash Block to copy from.
 * @param block_no 1-based index of the block being written.
 * @param derived_key_free Number of derived-key bytes still unwritten.
 * @param derived_key Output buffer to copy into.
 *
 * @return Number of bytes copied.
 */
static size_t
write_block_output(const uint8_t t_hash[PAMBLE_SHA256_DIGEST_LENGTH],
                   const uint32_t block_no, size_t derived_key_free,
                   uint8_t *derived_key) {
  size_t to_copy = derived_key_free >= PAMBLE_SHA256_DIGEST_LENGTH
                       ? PAMBLE_SHA256_DIGEST_LENGTH
                       : derived_key_free;

  size_t offset = ((size_t)block_no - 1) * PAMBLE_SHA256_DIGEST_LENGTH;

  memcpy(derived_key + offset, t_hash, to_copy);

  return to_copy;
}

/*
 * @brief Frees a derived key previously allocated by pamble_pbkdf2.
 *
 * @param derived_key Derived key buffer to free. NULL is a no-op.
 */
void pamble_free_pbkdf2_dk(uint8_t *derived_key) { free(derived_key); }

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
                            uint8_t **derived_key, size_t dk_length) {
  if (password == NULL && password_length != 0) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  if (salt == NULL && salt_length != 0) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  if (derived_key == NULL || dk_length == 0) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  size_t blocks = (dk_length / PAMBLE_SHA256_DIGEST_LENGTH) +
                  (dk_length % PAMBLE_SHA256_DIGEST_LENGTH != 0);

  if (blocks > UINT32_MAX) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  *derived_key = calloc(dk_length, sizeof(uint8_t));

  if (*derived_key == NULL) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  size_t derived_key_free = dk_length;

  for (uint32_t block_no = 1; block_no <= blocks; block_no++) {
    uint8_t t_hash[PAMBLE_SHA256_DIGEST_LENGTH];

    pamble_status status = process_block(password, password_length, salt,
                                         salt_length, block_no, t_hash);

    if (status != PAMBLE_OK) {
      pamble_free_pbkdf2_dk(*derived_key);
      *derived_key = NULL;
      return status;
    }

    size_t to_copy =
        write_block_output(t_hash, block_no, derived_key_free, *derived_key);

    derived_key_free -= to_copy;
  }

  return PAMBLE_OK;
}
