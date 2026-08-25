#include <pamble/pamble_sha256.h>
#include <string.h>

/*
 * constants
 */
#define BITS_PER_BYTE 8

#define BYTES_PER_BLOCK 64
#define BYTES_PER_LENGTH_FIELD (sizeof(uint64_t))

#define PADDING_BYTE 0x80

#define H_VALUES_SIZE 8
#define K_VALUES_SIZE 64

#define BYTES_PER_WORD (sizeof(uint32_t))
#define BITS_PER_WORD (BYTES_PER_WORD * BITS_PER_BYTE)
#define INITIAL_WORD_COUNT (BYTES_PER_BLOCK / BYTES_PER_WORD)
#define WORDS_STATE_SIZE 64

#define SIGMA1_ROT1 7
#define SIGMA1_ROT2 18
#define SIGMA1_SHFT 3

#define SIGMA2_ROT1 17
#define SIGMA2_ROT2 19
#define SIGMA2_SHFT 10

#define OFFSET_W16 16
#define OFFSET_W15 15
#define OFFSET_W7 7
#define OFFSET_W2 2

#define WORKING_VARIABLES_SIZE 8

#define COMPRESSION_SIGMA1_ROT1 6
#define COMPRESSION_SIGMA1_ROT2 11
#define COMPRESSION_SIGMA1_ROT3 25

#define COMPRESSION_SIGMA0_ROT1 2
#define COMPRESSION_SIGMA0_ROT2 13
#define COMPRESSION_SIGMA0_ROT3 22

#define RETURN_IF_ERROR(status)                                                \
  do {                                                                         \
    if ((status) != PAMBLE_SHA256_OK) {                                        \
      return (status);                                                         \
    }                                                                          \
  } while (0)

enum { WV_A = 0, WV_B, WV_C, WV_D, WV_E, WV_F, WV_G, WV_H };

struct pamble_sha256_ctx {
  uint32_t hash_state[H_VALUES_SIZE];
  uint8_t buffer[BYTES_PER_BLOCK];
  size_t buffer_length;
  uint64_t message_length;
};

static const uint32_t H_VALUES[H_VALUES_SIZE] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

static const uint32_t K_VALUES[K_VALUES_SIZE] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/*
 * @brief Initializes the hash state with the SHA-256 initial values.
 *
 * @param hash_state Array containing the hash state to initialize.
 *
 * @return PAMBLE_SHA256_OK if the hash state was initialized successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if hash_state is NULL.
 */
static pamble_sha256_status
initialize_h_values(uint32_t hash_state[H_VALUES_SIZE]) {
  if (hash_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  memcpy(hash_state, H_VALUES, sizeof(H_VALUES));

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Initializes a SHA-256 context.
 *
 * Resets the hash state, internal message buffer, buffered message length,
 * and total message length.
 *
 * @param ctx SHA-256 context to initialize.
 *
 * @return PAMBLE_SHA256_OK if the context was initialized successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if ctx is NULL.
 */
pamble_sha256_status pamble_sha256_init(pamble_sha256_ctx *ctx) {
  if (ctx == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  pamble_sha256_status status = initialize_h_values(ctx->hash_state);

  RETURN_IF_ERROR(status);

  ctx->buffer_length = 0;
  ctx->message_length = 0;

  memset(ctx->buffer, 0, BYTES_PER_BLOCK);

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Converts four big-endian bytes into a 32-bit word.
 *
 * @param padded_message_block Four bytes containing the word in big-endian
 *                            order.
 * @param concatenated_word Output location for the resulting 32-bit word.
 *
 * @return PAMBLE_SHA256_OK if the word was converted successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if an argument is NULL.
 */
static pamble_sha256_status
bytes_to_word(const uint8_t padded_message_block[BYTES_PER_WORD],
              uint32_t *concatenated_word) {
  if (padded_message_block == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (concatenated_word == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  *concatenated_word = 0;

  for (size_t i = 0; i < BYTES_PER_WORD; i++) {
    *concatenated_word |= (uint32_t)padded_message_block[i]
                          << (BYTES_PER_WORD - i - 1) * BITS_PER_BYTE;
  }

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Initializes the first 16 words of the SHA-256 message schedule.
 *
 * Converts the 512-bit message block from bytes into 32-bit big-endian words.
 *
 * @param words_state Message schedule to initialize.
 * @param padded_message_block 512-bit message block.
 *
 * @return PAMBLE_SHA256_OK if the initial words were initialized successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if an argument is NULL.
 */
static pamble_sha256_status
initialize_initial_words(uint32_t words_state[WORDS_STATE_SIZE],
                         const uint8_t padded_message_block[BYTES_PER_BLOCK]) {
  if (words_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (padded_message_block == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  for (size_t i = 0; i < INITIAL_WORD_COUNT; i++) {
    pamble_sha256_status status = bytes_to_word(
        &padded_message_block[i * BYTES_PER_WORD], &words_state[i]);

    RETURN_IF_ERROR(status);
  }

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Rotates a 32-bit word to the right.
 *
 * @param word Word to rotate.
 * @param round Number of bit positions to rotate.
 *
 * @return The rotated 32-bit word.
 */
static uint32_t right_rotate(const uint32_t word, size_t round) {
  const size_t shift = round % BITS_PER_WORD;

  if (shift == 0) {
    return word;
  }

  return (word >> shift) | (word << (BITS_PER_WORD - shift));
}

/*
 * @brief Computes the SHA-256 small sigma-1 function.
 *
 * @param word Input 32-bit word.
 *
 * @return Result of the SHA-256 small sigma-1 function.
 */
static uint32_t sigma1(uint32_t word) {
  return right_rotate(word, SIGMA1_ROT1) ^ right_rotate(word, SIGMA1_ROT2) ^
         (word >> SIGMA1_SHFT);
}

/*
 * @brief Computes the SHA-256 small sigma-2 function.
 *
 * @param word Input 32-bit word.
 *
 * @return Result of the SHA-256 small sigma-2 function.
 */
static uint32_t sigma2(uint32_t word) {
  return right_rotate(word, SIGMA2_ROT1) ^ right_rotate(word, SIGMA2_ROT2) ^
         (word >> SIGMA2_SHFT);
}

/*
 * @brief Expands the first 16 message words into the complete 64-word schedule.
 *
 * @param words_state Message schedule containing the initial 16 words.
 *
 * @return PAMBLE_SHA256_OK if the message schedule was expanded successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if words_state is NULL.
 */
static pamble_sha256_status
expand_words_state(uint32_t words_state[WORDS_STATE_SIZE]) {
  if (words_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  for (size_t i = INITIAL_WORD_COUNT; i < WORDS_STATE_SIZE; i++) {
    words_state[i] =
        words_state[i - OFFSET_W16] + sigma1(words_state[i - OFFSET_W15]) +
        words_state[i - OFFSET_W7] + sigma2(words_state[i - OFFSET_W2]);
  }

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Initializes the complete SHA-256 message schedule.
 *
 * Initializes the first 16 words from the message block and expands them
 * into the remaining 48 words.
 *
 * @param words_state Message schedule to initialize.
 * @param padded_message_block 512-bit message block.
 *
 * @return PAMBLE_SHA256_OK if the message schedule was initialized
 * successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if an argument is NULL.
 */
static pamble_sha256_status
initialize_words_state(uint32_t words_state[WORDS_STATE_SIZE],
                       const uint8_t padded_message_block[BYTES_PER_BLOCK]) {
  if (words_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (padded_message_block == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  pamble_sha256_status status;

  status = initialize_initial_words(words_state, padded_message_block);
  RETURN_IF_ERROR(status);

  status = expand_words_state(words_state);
  RETURN_IF_ERROR(status);

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Initializes the working variables for a compression operation.
 *
 * Copies the current hash state into the eight working variables.
 *
 * @param working_variables_state Working variables to initialize.
 * @param hash_state Current SHA-256 hash state.
 *
 * @return PAMBLE_SHA256_OK if the working variables were initialized
 *         successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if an argument is NULL.
 */
static pamble_sha256_status initialize_working_variable_values(
    uint32_t working_variables_state[WORKING_VARIABLES_SIZE],
    uint32_t hash_state[H_VALUES_SIZE]) {
  if (working_variables_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (hash_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  memcpy(working_variables_state, hash_state,
         sizeof(uint32_t) * WORKING_VARIABLES_SIZE);

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Performs a single SHA-256 compression round.
 *
 * Updates the eight working variables using the supplied round constant
 * and expanded message word.
 *
 * @param working_variables_state Working variables for the compression.
 * @param round_constant SHA-256 round constant for the current round.
 * @param expanded_word Message schedule word for the current round.
 */
static void sha256_compression_round(
    uint32_t working_variables_state[WORKING_VARIABLES_SIZE],
    uint32_t round_constant, uint32_t expanded_word) {
  const uint32_t var_a = working_variables_state[WV_A];
  const uint32_t var_b = working_variables_state[WV_B];
  const uint32_t var_c = working_variables_state[WV_C];
  const uint32_t var_d = working_variables_state[WV_D];
  const uint32_t var_e = working_variables_state[WV_E];
  const uint32_t var_f = working_variables_state[WV_F];
  const uint32_t var_g = working_variables_state[WV_G];
  const uint32_t var_h = working_variables_state[WV_H];

  const uint32_t es1 = right_rotate(var_e, COMPRESSION_SIGMA1_ROT1) ^
                       right_rotate(var_e, COMPRESSION_SIGMA1_ROT2) ^
                       right_rotate(var_e, COMPRESSION_SIGMA1_ROT3);

  const uint32_t chs = (var_e & var_f) ^ ((~var_e) & var_g);

  const uint32_t temp1 = var_h + es1 + chs + round_constant + expanded_word;

  const uint32_t es0 = right_rotate(var_a, COMPRESSION_SIGMA0_ROT1) ^
                       right_rotate(var_a, COMPRESSION_SIGMA0_ROT2) ^
                       right_rotate(var_a, COMPRESSION_SIGMA0_ROT3);

  const uint32_t maj = (var_a & var_b) ^ (var_a & var_c) ^ (var_b & var_c);

  const uint32_t temp2 = es0 + maj;

  working_variables_state[WV_H] = var_g;
  working_variables_state[WV_G] = var_f;
  working_variables_state[WV_F] = var_e;
  working_variables_state[WV_E] = var_d + temp1;
  working_variables_state[WV_D] = var_c;
  working_variables_state[WV_C] = var_b;
  working_variables_state[WV_B] = var_a;
  working_variables_state[WV_A] = temp1 + temp2;
}

/*
 * @brief Performs all 64 SHA-256 compression rounds.
 *
 * @param words_state Expanded 64-word message schedule.
 * @param working_variables_state Working variables for the compression.
 *
 * @return PAMBLE_SHA256_OK if compression completed successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if an argument is NULL.
 */
static pamble_sha256_status words_state_compression(
    const uint32_t words_state[WORDS_STATE_SIZE],
    uint32_t working_variables_state[WORKING_VARIABLES_SIZE]) {
  if (words_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (working_variables_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  for (size_t i = 0; i < WORDS_STATE_SIZE; i++) {
    sha256_compression_round(working_variables_state, K_VALUES[i],
                             words_state[i]);
  }

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Adds the compressed working variables to the hash state.
 *
 * @param hash_state Current SHA-256 hash state.
 * @param working_variables_state Compressed working variables.
 *
 * @return PAMBLE_SHA256_OK if the hash state was updated successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if an argument is NULL.
 */
static pamble_sha256_status update_hash_state(
    uint32_t hash_state[H_VALUES_SIZE],
    const uint32_t working_variables_state[WORKING_VARIABLES_SIZE]) {
  if (hash_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (working_variables_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  for (size_t i = 0; i < H_VALUES_SIZE; i++) {
    hash_state[i] += working_variables_state[i];
  }

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Processes a single 512-bit message block.
 *
 * Builds the message schedule, performs the SHA-256 compression function,
 * and updates the supplied hash state.
 *
 * @param block 512-bit message block to process.
 * @param hash_state SHA-256 hash state to update.
 *
 * @return PAMBLE_SHA256_OK if the block was processed successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if an argument is NULL.
 */
static pamble_sha256_status
process_message_block(const uint8_t block[BYTES_PER_BLOCK],
                      uint32_t hash_state[H_VALUES_SIZE]) {
  if (block == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (hash_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  uint32_t words_state[WORDS_STATE_SIZE];
  uint32_t working_variables_state[WORKING_VARIABLES_SIZE];

  pamble_sha256_status status;

  status = initialize_words_state(words_state, block);
  RETURN_IF_ERROR(status);

  status =
      initialize_working_variable_values(working_variables_state, hash_state);
  RETURN_IF_ERROR(status);

  status = words_state_compression(words_state, working_variables_state);
  RETURN_IF_ERROR(status);

  status = update_hash_state(hash_state, working_variables_state);
  RETURN_IF_ERROR(status);

  return PAMBLE_SHA256_OK;
}

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
 * @return PAMBLE_SHA256_OK if the context was updated successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if ctx is NULL, or if message is NULL
 *         while message_length is non-zero.
 * @return PAMBLE_SHA256_SIZE_OVERFLOW if the message length would exceed the
 *         maximum length representable by SHA-256.
 */
pamble_sha256_status pamble_sha256_update(pamble_sha256_ctx *ctx,
                                          const uint8_t *message,
                                          size_t message_length) {
  if (ctx == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (message == NULL && message_length != 0) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (message_length > (UINT64_MAX / BITS_PER_BYTE) - ctx->message_length) {
    return PAMBLE_SHA256_SIZE_OVERFLOW;
  }

  size_t message_offset = 0;

  if (ctx->buffer_length != 0) {
    const size_t empty_cells = BYTES_PER_BLOCK - ctx->buffer_length;

    const size_t to_copy =
        empty_cells > message_length ? message_length : empty_cells;

    memcpy(ctx->buffer + ctx->buffer_length, message, to_copy);

    ctx->buffer_length += to_copy;
    message_offset += to_copy;

    if (ctx->buffer_length == BYTES_PER_BLOCK) {
      pamble_sha256_status status =
          process_message_block(ctx->buffer, ctx->hash_state);

      RETURN_IF_ERROR(status);

      ctx->buffer_length = 0;
    }
  }

  while (message_length - message_offset >= BYTES_PER_BLOCK) {
    pamble_sha256_status status =
        process_message_block(message + message_offset, ctx->hash_state);

    RETURN_IF_ERROR(status);

    message_offset += BYTES_PER_BLOCK;
  }

  if (message_length > message_offset) {
    const size_t message_remaining = message_length - message_offset;

    memcpy(ctx->buffer, message + message_offset, message_remaining);

    ctx->buffer_length = message_remaining;
  }

  ctx->message_length += (uint64_t)message_length;

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Encodes a 64-bit bit length as a big-endian byte sequence.
 *
 * @param bit_length Message length in bits.
 * @param ctx_buffer Output buffer for the encoded length.
 *
 * @return PAMBLE_SHA256_OK if the length was encoded successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if ctx_buffer is NULL.
 */
static pamble_sha256_status
encode_length(uint64_t bit_length, uint8_t ctx_buffer[BYTES_PER_LENGTH_FIELD]) {
  if (ctx_buffer == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  for (size_t i = 0; i < BYTES_PER_LENGTH_FIELD; i++) {
    ctx_buffer[i] = (uint8_t)(bit_length >>
                              (BYTES_PER_LENGTH_FIELD - i - 1) * BITS_PER_BYTE);
  }

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Converts a 32-bit hash state word into big-endian bytes.
 *
 * @param hash_state_chunk Hash state word to convert.
 * @param output_buffer_chunk Output buffer for the resulting bytes.
 *
 * @return PAMBLE_SHA256_OK if the word was converted successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if an argument is NULL.
 */
static pamble_sha256_status
word_to_byte(const uint32_t *hash_state_chunk,
             uint8_t output_buffer_chunk[BYTES_PER_WORD]) {
  if (hash_state_chunk == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (output_buffer_chunk == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  for (size_t i = 0; i < BYTES_PER_WORD; i++) {
    output_buffer_chunk[i] =
        (uint8_t)(*hash_state_chunk >>
                  (BYTES_PER_WORD - i - 1) * BITS_PER_BYTE);
  }

  return PAMBLE_SHA256_OK;
}

/*
 * @brief Exports the hash state as a SHA-256 digest.
 *
 * Converts all eight 32-bit hash state words into the 32-byte big-endian
 * digest representation.
 *
 * @param hash_state Final SHA-256 hash state.
 * @param output_buffer Output buffer for the 32-byte digest.
 *
 * @return PAMBLE_SHA256_OK if the digest was exported successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if an argument is NULL.
 */
static pamble_sha256_status
export_digest(const uint32_t hash_state[H_VALUES_SIZE],
              uint8_t output_buffer[PAMBLE_SHA256_DIGEST_LENGTH]) {
  if (hash_state == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (output_buffer == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  for (size_t i = 0; i < H_VALUES_SIZE; i++) {
    pamble_sha256_status status =
        word_to_byte(&hash_state[i], &output_buffer[i * BYTES_PER_WORD]);

    RETURN_IF_ERROR(status);
  }

  return PAMBLE_SHA256_OK;
}

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
 * @return PAMBLE_SHA256_OK if finalization completed successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if an argument is NULL or the context
 *         contains an invalid buffered length.
 */
pamble_sha256_status
pamble_sha256_final(const pamble_sha256_ctx *ctx,
                    uint8_t output_buffer[PAMBLE_SHA256_DIGEST_LENGTH]) {
  if (ctx == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (output_buffer == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (ctx->buffer_length >= BYTES_PER_BLOCK) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  pamble_sha256_ctx final_ctx = *ctx;

  const uint64_t bit_length = final_ctx.message_length * BITS_PER_BYTE;

  final_ctx.buffer[final_ctx.buffer_length++] = PADDING_BYTE;

  if (final_ctx.buffer_length > BYTES_PER_BLOCK - BYTES_PER_LENGTH_FIELD) {
    memset(final_ctx.buffer + final_ctx.buffer_length, 0,
           BYTES_PER_BLOCK - final_ctx.buffer_length);

    pamble_sha256_status status =
        process_message_block(final_ctx.buffer, final_ctx.hash_state);

    RETURN_IF_ERROR(status);

    final_ctx.buffer_length = 0;
  }

  memset(final_ctx.buffer + final_ctx.buffer_length, 0,
         (BYTES_PER_BLOCK - BYTES_PER_LENGTH_FIELD) - final_ctx.buffer_length);

  pamble_sha256_status status = encode_length(
      bit_length, &final_ctx.buffer[BYTES_PER_BLOCK - BYTES_PER_LENGTH_FIELD]);

  RETURN_IF_ERROR(status);

  status = process_message_block(final_ctx.buffer, final_ctx.hash_state);
  RETURN_IF_ERROR(status);

  status = export_digest(final_ctx.hash_state, output_buffer);
  RETURN_IF_ERROR(status);

  return PAMBLE_SHA256_OK;
}

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
 * @return PAMBLE_SHA256_OK if the digest was computed successfully.
 * @return PAMBLE_SHA256_INVALID_ARGUMENT if output_buffer is NULL, or if
 *         message is NULL while message_length is non-zero.
 * @return PAMBLE_SHA256_SIZE_OVERFLOW if the message length exceeds the
 *         maximum length representable by SHA-256.
 */
pamble_sha256_status
pamble_sha256(const uint8_t *message, size_t message_length,
              uint8_t output_buffer[PAMBLE_SHA256_DIGEST_LENGTH]) {
  if (output_buffer == NULL) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  if (message == NULL && message_length != 0) {
    return PAMBLE_SHA256_INVALID_ARGUMENT;
  }

  pamble_sha256_ctx ctx;

  pamble_sha256_status status = pamble_sha256_init(&ctx);
  RETURN_IF_ERROR(status);

  status = pamble_sha256_update(&ctx, message, message_length);
  RETURN_IF_ERROR(status);

  status = pamble_sha256_final(&ctx, output_buffer);
  RETURN_IF_ERROR(status);

  return PAMBLE_SHA256_OK;
}
