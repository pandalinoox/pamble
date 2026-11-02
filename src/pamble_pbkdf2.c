#include "pamble/pamble_hmac_sha256.h"
#include "pamble/pamble_pdkdf2.h"

#include <stdlib.h>
#include <string.h>

#define BYTES_PER_32_BITS sizeof(uint32_t)
#define BITS_PER_BYTE 8

#define PROGRESS_STEPS 100
#define PROGRESS_INTERVAL (PAMBLE_PBKDF2_ITERATIONS / PROGRESS_STEPS)

/*
 * @brief Progress destination plus the event that is re-sent with a new
 *        iteration count.
 */
typedef struct {
  const pamble_progress *progress;
  pamble_progress_event event;
} iteration_reporter;

/*
 * @brief Sends the current iteration count, if a reporter is attached.
 *
 * @param reporter Reporter, or NULL for silent derivation.
 * @param done Iterations completed across all blocks so far.
 */
static void report_iterations(iteration_reporter *reporter, uint64_t done) {
  if (reporter == NULL) {
    return;
  }

  reporter->event.done = done;
  pamble_progress_emit(reporter->progress, &reporter->event);
}

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

  status = pamble_hmac_sha256(password_length, password,
                              PAMBLE_SHA256_DIGEST_LENGTH, u_hash, u_hash);

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
 * @param reporter Progress reporter, or NULL. Receives the running iteration
 *                 count every PROGRESS_INTERVAL iterations.
 *
 * @return PAMBLE_OK on success, otherwise an error from pamble_hmac_sha256.
 */
static pamble_status process_block(const uint8_t *password,
                                   size_t password_length, const uint8_t *salt,
                                   size_t salt_length, const uint32_t block_no,
                                   uint8_t t_hash[PAMBLE_SHA256_DIGEST_LENGTH],
                                   iteration_reporter *reporter) {

  const uint64_t iterations_before =
      ((uint64_t)block_no - 1) * (uint64_t)PAMBLE_PBKDF2_ITERATIONS;

  pamble_status status;

  uint8_t int32_be_out[BYTES_PER_32_BITS];
  int32_be(block_no, int32_be_out);

  uint8_t salt_concat_int32_be[salt_length + BYTES_PER_32_BITS];

  array_concat(salt, salt_length, int32_be_out, BYTES_PER_32_BITS,
               salt_concat_int32_be);

  uint8_t u_hash[PAMBLE_SHA256_DIGEST_LENGTH];

  status = pamble_hmac_sha256(password_length, password,
                              salt_length + BYTES_PER_32_BITS,
                              salt_concat_int32_be, u_hash);

  PAMBLE_RETURN_IF_ERROR(status);

  memcpy(t_hash, u_hash, PAMBLE_SHA256_DIGEST_LENGTH);

  for (uint32_t j = 2; j <= PAMBLE_PBKDF2_ITERATIONS; j++) {
    status = process_iteration(password, password_length, u_hash, t_hash);

    PAMBLE_RETURN_IF_ERROR(status);

    if (j % PROGRESS_INTERVAL == 0) {
      report_iterations(reporter, iterations_before + j);
    }
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
 * @brief Derives every output block and assembles the derived key.
 *
 * Shared body of pamble_pbkdf2 and pamble_pbkdf2_with_progress.
 *
 * @param password Password data used as the HMAC key.
 * @param password_length Number of bytes in password.
 * @param salt Salt data.
 * @param salt_length Number of bytes in salt.
 * @param derived_key Output buffer for the derived key, sized dk_length.
 * @param dk_length Desired length, in bytes, of the derived key.
 * @param reporter Progress reporter, or NULL for silent derivation.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_SIZE_OVERFLOW if dk_length requires more than UINT32_MAX
 *         blocks.
 * @return Any error propagated from pamble_hmac_sha256.
 */
static pamble_status derive_key(const uint8_t *password, size_t password_length,
                                const uint8_t *salt, size_t salt_length,
                                uint8_t *derived_key, size_t dk_length,
                                iteration_reporter *reporter) {

  size_t blocks = (dk_length / PAMBLE_SHA256_DIGEST_LENGTH) +
                  (dk_length % PAMBLE_SHA256_DIGEST_LENGTH != 0);

  if (blocks > UINT32_MAX) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  if (reporter != NULL) {
    reporter->event.total =
        (uint64_t)blocks * (uint64_t)PAMBLE_PBKDF2_ITERATIONS;
    report_iterations(reporter, 0);
  }

  size_t derived_key_free = dk_length;

  for (uint32_t block_no = 1; block_no <= blocks; block_no++) {
    uint8_t t_hash[PAMBLE_SHA256_DIGEST_LENGTH];

    pamble_status status =
        process_block(password, password_length, salt, salt_length, block_no,
                      t_hash, reporter);

    if (status != PAMBLE_OK) {
      return status;
    }

    size_t to_copy =
        write_block_output(t_hash, block_no, derived_key_free, derived_key);

    derived_key_free -= to_copy;
  }

  return PAMBLE_OK;
}

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
                            uint8_t derived_key[static dk_length]) {

  return derive_key(password, password_length, salt, salt_length, derived_key,
                    dk_length, NULL);
}

/*
 * @brief Derives a key with PBKDF2-HMAC-SHA256 and reports iteration progress.
 *
 * Same result as pamble_pbkdf2. Additionally sends stage_event to progress
 * with done set to the number of iterations completed and total set to
 * blocks * PAMBLE_PBKDF2_ITERATIONS: once at 0, then every 1% of iterations,
 * ending with done == total.
 *
 * @param password_length Number of bytes in password.
 * @param password Password data used as the HMAC key.
 * @param salt_length Number of bytes in salt.
 * @param salt Salt data.
 * @param dk_length Desired length, in bytes, of the derived key.
 * @param derived_key Output buffer for the derived key, sized dk_length.
 * @param progress Progress destination; a silent one costs nothing.
 * @param stage_event Stage, step and step_count to report under. Its done
 *                    and total fields are ignored.
 *
 * @return Same as pamble_pbkdf2.
 */
pamble_status pamble_pbkdf2_with_progress(
    size_t password_length, const uint8_t password[static password_length],
    size_t salt_length, const uint8_t salt[static salt_length],
    size_t dk_length, uint8_t derived_key[static dk_length],
    const pamble_progress progress[static 1],
    const pamble_progress_event stage_event[static 1]) {

  iteration_reporter reporter = {.progress = progress, .event = *stage_event};

  return derive_key(password, password_length, salt, salt_length, derived_key,
                    dk_length, &reporter);
}
