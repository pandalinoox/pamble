#include "pamble/pamble_crypto.h"
#include "pamble/pamble_aes_ctr.h"
#include "pamble/pamble_archive.h"
#include "pamble/pamble_hmac_sha256.h"
#include "pamble/pamble_pdkdf2.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>

#define CRYPTO_SALT_LENGTH 12
#define MAC_KEY_LENGTH 32
#define MAGIC_LENGTH 6
#define ARCHIVE_LENGTH_LENGTH 8
#define BITS_PER_BYTE 8
#define DERIVED_KEY_LENGTH (PAMBLE_AES256_KEY_SIZE + MAC_KEY_LENGTH)
#define TAG_LENGTH PAMBLE_SHA256_DIGEST_LENGTH

#define PROGRESS_CHUNK_BYTES ((size_t)1 << 20)

#define TEMP_SUFFIX ".tmp"
#define TEMP_SUFFIX_LENGTH (sizeof(TEMP_SUFFIX) - 1)

#define CRYPTO_HEADER_LENGTH                                                   \
  (MAGIC_LENGTH + sizeof(uint8_t) + CRYPTO_SALT_LENGTH +                       \
   PAMBLE_AES_CTR_NONCE_BYTES + ARCHIVE_LENGTH_LENGTH)

#define SALT_OFFSET (MAGIC_LENGTH + sizeof(uint8_t))
#define NONCE_OFFSET (SALT_OFFSET + CRYPTO_SALT_LENGTH)
#define LENGTH_OFFSET (NONCE_OFFSET + PAMBLE_AES_CTR_NONCE_BYTES)

static const uint8_t MAGIC[MAGIC_LENGTH] = {'P', 'M', 'B', 'E', 'N', 'C'};

static const uint8_t EMPTY_PASSWORD[1] = {0};

/*
 * @brief Decoded crypto header.
 */
typedef struct {
  uint8_t version;
  uint8_t salt[CRYPTO_SALT_LENGTH];
  uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint64_t archive_length;
} crypto_header;

/*
 * @brief A header together with the body it describes.
 *
 *   header          Decoded header fields.
 *   encoded_header  The header exactly as it is (or will be) on disk; this is
 *                   what the MAC covers.
 *   body            Plaintext archive or ciphertext, archive_length bytes.
 *                   Encryption and decryption work on it in place.
 *   body_length     Number of bytes in body.
 */
typedef struct {
  crypto_header header;
  uint8_t encoded_header[CRYPTO_HEADER_LENGTH];
  uint8_t *body;
  size_t body_length;
} crypto_message;

/*
 * @brief The two keys derived from the password.
 */
typedef struct {
  uint8_t aes_key[PAMBLE_AES256_KEY_SIZE];
  uint8_t mac_key[MAC_KEY_LENGTH];
} crypto_keys;

/*
 * @brief Progress destination plus the event for the current stage.
 */
typedef struct {
  const pamble_progress *progress;
  pamble_progress_event event;
} stage_reporter;

/*
 * @brief Returns the position of a stage within its operation.
 *
 * Encryption: archive 1, keys 2, encrypt 3, authenticate 4, write 5.
 * Decryption: read 1, keys 2, verify 3, decrypt 4, extract 5.
 *
 * @param stage Stage to place.
 *
 * @return 1-based step number.
 */
static unsigned stage_step(pamble_stage stage) {

  switch (stage) {
  case PAMBLE_STAGE_ARCHIVE:
  case PAMBLE_STAGE_READ:
    return 1;
  case PAMBLE_STAGE_DERIVE_KEYS:
    return 2;
  case PAMBLE_STAGE_ENCRYPT:
  case PAMBLE_STAGE_VERIFY:
    return 3;
  case PAMBLE_STAGE_AUTHENTICATE:
  case PAMBLE_STAGE_DECRYPT:
    return 4;
  case PAMBLE_STAGE_WRITE:
  case PAMBLE_STAGE_EXTRACT:
    return PAMBLE_CRYPTO_STEP_COUNT;
  }

  return 0;
}

/*
 * @brief Creates the reporter for a stage, with no total yet.
 *
 * @param progress Progress destination.
 * @param stage Stage being entered.
 *
 * @return Reporter whose event names the stage and its step.
 */
static stage_reporter start_stage(const pamble_progress *progress,
                                  pamble_stage stage) {

  const stage_reporter reporter = {
      .progress = progress,
      .event =
          {
              .stage = stage,
              .step = stage_step(stage),
              .step_count = PAMBLE_CRYPTO_STEP_COUNT,
              .done = 0,
              .total = 0,
          },
  };

  return reporter;
}

/*
 * @brief Reports how much of the current stage is done.
 *
 * With a total of zero the event is a label-only announcement.
 *
 * @param reporter Reporter for the current stage.
 * @param done Units completed so far.
 */
static void report_done(stage_reporter *reporter, uint64_t done) {
  reporter->event.done = done;
  pamble_progress_emit(reporter->progress, &reporter->event);
}

/*
 * @brief Encodes a 64-bit value as 8 big-endian bytes.
 *
 * @param value Value to encode.
 * @param output Output for the 8 bytes.
 */
static void encode_uint64(uint64_t value,
                          uint8_t output[static ARCHIVE_LENGTH_LENGTH]) {
  for (size_t i = 0; i < ARCHIVE_LENGTH_LENGTH; i++) {
    output[i] =
        (uint8_t)(value >> ((ARCHIVE_LENGTH_LENGTH - i - 1) * BITS_PER_BYTE));
  }
}

/*
 * @brief Decodes 8 big-endian bytes into a 64-bit value.
 *
 * @param input The 8 bytes.
 *
 * @return The decoded value.
 */
static uint64_t
decode_uint64(const uint8_t input[static ARCHIVE_LENGTH_LENGTH]) {
  uint64_t value = 0;

  for (size_t i = 0; i < ARCHIVE_LENGTH_LENGTH; i++) {
    value = (value << BITS_PER_BYTE) | input[i];
  }

  return value;
}

/*
 * @brief Writes a header in its on-disk form.
 *
 * Layout: magic (6) | version (1) | salt (12) | nonce (12) |
 * archive_length (8, big-endian).
 *
 * @param header Header to encode.
 * @param output Output for CRYPTO_HEADER_LENGTH bytes.
 */
static void encode_crypto_header(const crypto_header *header,
                                 uint8_t output[static CRYPTO_HEADER_LENGTH]) {

  memcpy(output, MAGIC, MAGIC_LENGTH);
  output[MAGIC_LENGTH] = header->version;
  memcpy(output + SALT_OFFSET, header->salt, CRYPTO_SALT_LENGTH);
  memcpy(output + NONCE_OFFSET, header->nonce, PAMBLE_AES_CTR_NONCE_BYTES);
  encode_uint64(header->archive_length, output + LENGTH_OFFSET);
}

/*
 * @brief Parses and checks an on-disk header.
 *
 * @param input CRYPTO_HEADER_LENGTH bytes read from the file.
 * @param header Output for the decoded fields.
 *
 * @return PAMBLE_OK if the header is valid.
 * @return PAMBLE_INVALID_ARCHIVE if the magic or version is wrong.
 * @return PAMBLE_SIZE_OVERFLOW if archive_length does not fit in size_t.
 */
static pamble_status
decode_crypto_header(const uint8_t input[static CRYPTO_HEADER_LENGTH],
                     crypto_header *header) {

  if (memcmp(input, MAGIC, MAGIC_LENGTH) != 0) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  header->version = input[MAGIC_LENGTH];

  if (header->version != PAMBLE_CRYPTO_VERSION) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  memcpy(header->salt, input + SALT_OFFSET, CRYPTO_SALT_LENGTH);
  memcpy(header->nonce, input + NONCE_OFFSET, PAMBLE_AES_CTR_NONCE_BYTES);
  header->archive_length = decode_uint64(input + LENGTH_OFFSET);

  if (header->archive_length > SIZE_MAX) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  return PAMBLE_OK;
}

/*
 * @brief Fills a buffer from the kernel's random number generator.
 *
 * @param length Number of bytes wanted.
 * @param output_buffer Output for length random bytes.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_IO_ERROR if getrandom fails.
 */
static pamble_status
get_random_crypto_bytes(size_t length, uint8_t output_buffer[static length]) {
  size_t offset = 0;

  while (offset < length) {
    ssize_t result = getrandom(output_buffer + offset, length - offset, 0);

    if (result <= 0) {
      return PAMBLE_IO_ERROR;
    }

    offset += (size_t)result;
  }

  return PAMBLE_OK;
}

/*
 * @brief Compares two tags without stopping at the first difference.
 *
 * @param received Tag read from the file.
 * @param calculated Tag computed from the file's contents.
 *
 * @return true if every byte matches.
 */
static bool tags_equal(const uint8_t received[static TAG_LENGTH],
                       const uint8_t calculated[static TAG_LENGTH]) {
  uint8_t difference = 0;

  for (size_t i = 0; i < TAG_LENGTH; i++) {
    difference |= received[i] ^ calculated[i];
  }

  return difference == 0;
}

/*
 * @brief Rejects payloads with missing paths or a NULL non-empty password.
 *
 * @param payload Payload to check.
 *
 * @return PAMBLE_OK or PAMBLE_INVALID_ARGUMENT.
 */
static pamble_status validate_payload(const pamble_crypto_payload *payload) {

  if (payload->input_path == NULL || payload->output_path == NULL) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  if (payload->password == NULL && payload->password_length != 0) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  return PAMBLE_OK;
}

/*
 * @brief Derives the AES and MAC keys from the password and header salt.
 *
 * Runs PBKDF2 for DERIVED_KEY_LENGTH bytes and splits the result: the first
 * 32 bytes are the AES key, the next 32 the MAC key. The combined output is
 * wiped before returning.
 *
 * @param payload Supplies the password.
 * @param header Supplies the salt.
 * @param reporter Reporter for the key-derivation stage.
 * @param keys Output for the two keys.
 *
 * @return PAMBLE_OK or an error from pamble_pbkdf2_with_progress.
 */
static pamble_status derive_keys(const pamble_crypto_payload *payload,
                                 const crypto_header *header,
                                 const stage_reporter *reporter,
                                 crypto_keys *keys) {

  const uint8_t *password =
      payload->password != NULL ? payload->password : EMPTY_PASSWORD;

  uint8_t derived_key[DERIVED_KEY_LENGTH];

  pamble_status status = pamble_pbkdf2_with_progress(
      payload->password_length, password, CRYPTO_SALT_LENGTH, header->salt,
      DERIVED_KEY_LENGTH, derived_key, reporter->progress, &reporter->event);

  if (status == PAMBLE_OK) {
    memcpy(keys->aes_key, derived_key, PAMBLE_AES256_KEY_SIZE);
    memcpy(keys->mac_key, derived_key + PAMBLE_AES256_KEY_SIZE, MAC_KEY_LENGTH);
  }

  explicit_bzero(derived_key, sizeof(derived_key));

  return status;
}

/*
 * @brief Encrypts or decrypts the message body in place with AES-256-CTR.
 *
 * Works through the body in PROGRESS_CHUNK_BYTES pieces and reports the byte
 * count after each. The counter starts at the header nonce followed by a zero
 * block counter, the same as pamble_aes_ctr_crypt, so the output matches a
 * single one-shot call.
 *
 * @param keys Supplies the AES key.
 * @param message Header (nonce) and body to transform.
 * @param reporter Reporter for the encrypt or decrypt stage.
 *
 * @return PAMBLE_OK or an error from the AES-CTR functions.
 */
static pamble_status crypt_body(const crypto_keys *keys,
                                crypto_message *message,
                                stage_reporter *reporter) {

  pamble_aes_ctr_counter_block initial_counter;

  memcpy(initial_counter.nonce, message->header.nonce,
         PAMBLE_AES_CTR_NONCE_BYTES);
  memset(initial_counter.value, 0, PAMBLE_AES_CTR_COUNTER_BYTES);

  pamble_aes_ctr_ctx ctx;

  pamble_status status =
      pamble_aes_ctr_init(&ctx, keys->aes_key, initial_counter);
  PAMBLE_RETURN_IF_ERROR(status);

  reporter->event.total = message->body_length;
  report_done(reporter, 0);

  size_t offset = 0;

  while (status == PAMBLE_OK && offset < message->body_length) {
    const size_t remaining = message->body_length - offset;
    const size_t piece =
        remaining < PROGRESS_CHUNK_BYTES ? remaining : PROGRESS_CHUNK_BYTES;

    status = pamble_aes_ctr_update(&ctx, message->body + offset, piece,
                                   message->body + offset);
    offset += piece;

    if (status == PAMBLE_OK) {
      report_done(reporter, offset);
    }
  }

  const pamble_status cleanup_status = pamble_aes_ctr_cleanup(&ctx);

  PAMBLE_RETURN_IF_ERROR(status);

  return cleanup_status;
}

/*
 * @brief Feeds the body to an HMAC context in progress-sized pieces.
 *
 * @param ctx Initialized HMAC context.
 * @param message Body to authenticate.
 * @param reporter Reporter for the authenticate or verify stage.
 *
 * @return PAMBLE_OK or an error from pamble_hmac_sha256_update.
 */
static pamble_status mac_body(pamble_hmac_sha256_ctx *ctx,
                              const crypto_message *message,
                              stage_reporter *reporter) {

  reporter->event.total = message->body_length;
  report_done(reporter, 0);

  size_t offset = 0;

  while (offset < message->body_length) {
    const size_t remaining = message->body_length - offset;
    const size_t piece =
        remaining < PROGRESS_CHUNK_BYTES ? remaining : PROGRESS_CHUNK_BYTES;

    pamble_status status =
        pamble_hmac_sha256_update(ctx, message->body + offset, piece);
    PAMBLE_RETURN_IF_ERROR(status);

    offset += piece;
    report_done(reporter, offset);
  }

  return PAMBLE_OK;
}

/*
 * @brief Computes HMAC-SHA256(mac_key, encoded_header || body).
 *
 * Streams the header and then the body, so no combined copy is made. The
 * HMAC context is wiped before returning.
 *
 * @param keys Supplies the MAC key.
 * @param message Header and ciphertext to authenticate.
 * @param reporter Reporter for the authenticate or verify stage.
 * @param tag Output for the 32-byte tag.
 *
 * @return PAMBLE_OK or an error from the HMAC functions.
 */
static pamble_status compute_tag(const crypto_keys *keys,
                                 const crypto_message *message,
                                 stage_reporter *reporter,
                                 uint8_t tag[static TAG_LENGTH]) {

  pamble_hmac_sha256_ctx ctx;

  pamble_status status =
      pamble_hmac_sha256_init(&ctx, keys->mac_key, MAC_KEY_LENGTH);

  if (status == PAMBLE_OK) {
    status = pamble_hmac_sha256_update(&ctx, message->encoded_header,
                                       CRYPTO_HEADER_LENGTH);
  }

  if (status == PAMBLE_OK) {
    status = mac_body(&ctx, message, reporter);
  }

  if (status == PAMBLE_OK) {
    status = pamble_hmac_sha256_final(&ctx, tag);
  }

  explicit_bzero(&ctx, sizeof(ctx));

  return status;
}

/*
 * @brief Fills in a fresh header for a packed archive.
 *
 * Draws a random salt and nonce, records the body length and encodes the
 * header.
 *
 * @param message Message whose body is already set.
 *
 * @return PAMBLE_OK, or PAMBLE_IO_ERROR if random bytes are unavailable.
 */
static pamble_status new_header(crypto_message *message) {

  message->header.version = PAMBLE_CRYPTO_VERSION;
  message->header.archive_length = message->body_length;

  pamble_status status =
      get_random_crypto_bytes(CRYPTO_SALT_LENGTH, message->header.salt);
  PAMBLE_RETURN_IF_ERROR(status);

  status = get_random_crypto_bytes(PAMBLE_AES_CTR_NONCE_BYTES,
                                   message->header.nonce);
  PAMBLE_RETURN_IF_ERROR(status);

  encode_crypto_header(&message->header, message->encoded_header);

  return PAMBLE_OK;
}

/*
 * @brief Writes header, ciphertext and tag to an open file.
 *
 * @param file File to write to.
 * @param message Header and ciphertext.
 * @param tag 32-byte tag.
 *
 * @return true if every byte was written and the file closed cleanly.
 */
static bool write_sealed_file(FILE *file, const crypto_message *message,
                              const uint8_t tag[static TAG_LENGTH]) {

  bool written = (fwrite(message->encoded_header, 1, CRYPTO_HEADER_LENGTH,
                         file) == CRYPTO_HEADER_LENGTH &&
                  fwrite(message->body, 1, message->body_length, file) ==
                      message->body_length &&
                  fwrite(tag, 1, TAG_LENGTH, file) == TAG_LENGTH) != 0;

  if (fclose(file) != 0) {
    written = false;
  }

  return written;
}

/*
 * @brief Writes the encrypted file via a temporary file and a rename.
 *
 * Writes "<output_path>.tmp", then renames it over output_path. On failure
 * the temporary file is removed and output_path is left as it was.
 *
 * @param output_path Final path of the encrypted file.
 * @param message Header and ciphertext.
 * @param tag 32-byte tag.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_SIZE_OVERFLOW if the temporary path cannot be allocated.
 * @return PAMBLE_IO_ERROR if writing or renaming fails.
 */
static pamble_status write_output(const char *output_path,
                                  const crypto_message *message,
                                  const uint8_t tag[static TAG_LENGTH]) {

  const size_t path_length = strlen(output_path);

  char *temp_path = malloc(path_length + TEMP_SUFFIX_LENGTH + 1);

  if (temp_path == NULL) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  memcpy(temp_path, output_path, path_length);
  memcpy(temp_path + path_length, TEMP_SUFFIX, TEMP_SUFFIX_LENGTH + 1);

  pamble_status status = PAMBLE_OK;

  FILE *file = fopen(temp_path, "wb");

  if (file == NULL || !write_sealed_file(file, message, tag) ||
      rename(temp_path, output_path) != 0) {
    status = PAMBLE_IO_ERROR;
    remove(temp_path);
  }

  free(temp_path);

  return status;
}

/*
 * @brief Reads exactly length bytes from a file.
 *
 * @param file File to read.
 * @param buffer Output for length bytes.
 * @param length Number of bytes to read.
 *
 * @return true if all bytes were read.
 */
static bool read_exact(FILE *file, uint8_t *buffer, size_t length) {
  return (length == 0 || fread(buffer, 1, length, file) == length) != 0;
}

/*
 * @brief Reads header, ciphertext and tag from an open file.
 *
 * Checks the header and requires the file size to be exactly header +
 * archive_length + tag before allocating anything, so a damaged or
 * hand-crafted length is rejected without a large allocation.
 *
 * @param file Open input file.
 * @param message Output for the header and the allocated ciphertext body.
 * @param tag Output for the stored tag.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_INVALID_ARCHIVE if the header is bad or the size is wrong.
 * @return PAMBLE_IO_ERROR if the file cannot be inspected or read.
 * @return PAMBLE_SIZE_OVERFLOW if allocation fails.
 */
static pamble_status read_sealed_file(FILE *file, crypto_message *message,
                                      uint8_t tag[static TAG_LENGTH]) {

  struct stat info;

  if (fstat(fileno(file), &info) != 0) {
    return PAMBLE_IO_ERROR;
  }

  if (!read_exact(file, message->encoded_header, CRYPTO_HEADER_LENGTH)) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  pamble_status status =
      decode_crypto_header(message->encoded_header, &message->header);
  PAMBLE_RETURN_IF_ERROR(status);

  const uint64_t body_length = message->header.archive_length;

  if (info.st_size < 0 || body_length > (uint64_t)info.st_size ||
      (uint64_t)info.st_size - body_length !=
          CRYPTO_HEADER_LENGTH + TAG_LENGTH) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  message->body_length = (size_t)body_length;
  message->body = malloc(message->body_length != 0 ? message->body_length : 1);

  if (message->body == NULL) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  if (!read_exact(file, message->body, message->body_length) ||
      !read_exact(file, tag, TAG_LENGTH)) {
    return PAMBLE_IO_ERROR;
  }

  return PAMBLE_OK;
}

/*
 * @brief Opens the input file and reads it with read_sealed_file.
 *
 * @param input_path Path of the encrypted file.
 * @param message Output for the header and ciphertext.
 * @param tag Output for the stored tag.
 *
 * @return PAMBLE_IO_ERROR if the file cannot be opened, otherwise the result
 *         of read_sealed_file.
 */
static pamble_status read_input(const char *input_path, crypto_message *message,
                                uint8_t tag[static TAG_LENGTH]) {

  FILE *file = fopen(input_path, "rb");

  if (file == NULL) {
    return PAMBLE_IO_ERROR;
  }

  const pamble_status status = read_sealed_file(file, message, tag);

  fclose(file);

  return status;
}

/*
 * @brief Runs the five encryption stages.
 *
 * Leaves cleanup of keys and body to the caller, so every exit path is
 * cleaned up in one place.
 *
 * @param payload Paths, password and progress destination.
 * @param message Output: the packed archive, later its ciphertext.
 * @param keys Output: the derived keys.
 *
 * @return PAMBLE_OK or the first error from any stage.
 */
static pamble_status seal(const pamble_crypto_payload *payload,
                          crypto_message *message, crypto_keys *keys) {

  const pamble_progress *progress = &payload->progress;

  stage_reporter reporter = start_stage(progress, PAMBLE_STAGE_ARCHIVE);
  report_done(&reporter, 0);

  pamble_status status = pamble_archive_pack(
      payload->input_path, &message->body, &message->body_length);
  PAMBLE_RETURN_IF_ERROR(status);

  if (message->body_length > SIZE_MAX - CRYPTO_HEADER_LENGTH - TAG_LENGTH) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  status = new_header(message);
  PAMBLE_RETURN_IF_ERROR(status);

  reporter = start_stage(progress, PAMBLE_STAGE_DERIVE_KEYS);
  status = derive_keys(payload, &message->header, &reporter, keys);
  PAMBLE_RETURN_IF_ERROR(status);

  reporter = start_stage(progress, PAMBLE_STAGE_ENCRYPT);
  status = crypt_body(keys, message, &reporter);
  PAMBLE_RETURN_IF_ERROR(status);

  uint8_t tag[TAG_LENGTH];

  reporter = start_stage(progress, PAMBLE_STAGE_AUTHENTICATE);
  status = compute_tag(keys, message, &reporter, tag);
  PAMBLE_RETURN_IF_ERROR(status);

  reporter = start_stage(progress, PAMBLE_STAGE_WRITE);
  report_done(&reporter, 0);

  return write_output(payload->output_path, message, tag);
}

/*
 * @brief Runs the five decryption stages.
 *
 * Leaves cleanup of keys and body to the caller, so every exit path is
 * cleaned up in one place.
 *
 * @param payload Paths, password and progress destination.
 * @param message Output: the ciphertext, later the plaintext archive.
 * @param keys Output: the derived keys.
 *
 * @return PAMBLE_OK or the first error from any stage.
 */
static pamble_status unseal(const pamble_crypto_payload *payload,
                            crypto_message *message, crypto_keys *keys) {

  const pamble_progress *progress = &payload->progress;

  uint8_t received_tag[TAG_LENGTH];
  uint8_t calculated_tag[TAG_LENGTH];

  stage_reporter reporter = start_stage(progress, PAMBLE_STAGE_READ);
  report_done(&reporter, 0);

  pamble_status status = read_input(payload->input_path, message, received_tag);
  PAMBLE_RETURN_IF_ERROR(status);

  reporter = start_stage(progress, PAMBLE_STAGE_DERIVE_KEYS);
  status = derive_keys(payload, &message->header, &reporter, keys);
  PAMBLE_RETURN_IF_ERROR(status);

  reporter = start_stage(progress, PAMBLE_STAGE_VERIFY);
  status = compute_tag(keys, message, &reporter, calculated_tag);
  PAMBLE_RETURN_IF_ERROR(status);

  if (!tags_equal(received_tag, calculated_tag)) {
    return PAMBLE_AUTHENTICATION_FAILED;
  }

  reporter = start_stage(progress, PAMBLE_STAGE_DECRYPT);
  status = crypt_body(keys, message, &reporter);
  PAMBLE_RETURN_IF_ERROR(status);

  reporter = start_stage(progress, PAMBLE_STAGE_EXTRACT);
  report_done(&reporter, 0);

  return pamble_archive_unpack(message->body, message->body_length,
                               payload->output_path);
}

/*
 * @brief Wipes and frees a message body.
 *
 * @param message Message whose body to release; the body pointer is cleared.
 */
static void release_body(crypto_message *message) {

  if (message->body == NULL) {
    return;
  }

  explicit_bzero(message->body, message->body_length);
  free(message->body);
  message->body = NULL;
}

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
pamble_status pamble_encrypt_archive(pamble_crypto_payload payload) {

  pamble_status status = validate_payload(&payload);
  PAMBLE_RETURN_IF_ERROR(status);

  crypto_message message = {.body = NULL, .body_length = 0};
  crypto_keys keys;

  status = seal(&payload, &message, &keys);

  explicit_bzero(&keys, sizeof(keys));
  release_body(&message);

  return status;
}

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
pamble_status pamble_decrypt_archive(pamble_crypto_payload payload) {

  pamble_status status = validate_payload(&payload);
  PAMBLE_RETURN_IF_ERROR(status);

  crypto_message message = {.body = NULL, .body_length = 0};
  crypto_keys keys;

  status = unseal(&payload, &message, &keys);

  explicit_bzero(&keys, sizeof(keys));
  release_body(&message);

  return status;
}
