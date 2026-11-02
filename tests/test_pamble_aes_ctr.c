#include "pamble/pamble_aes_ctr.h"

#include <criterion/criterion.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PAMBLE_HEX_BASE 16
#define HEX_BYTE_STRING_LENGTH 3
#define HEX_CHARS_PER_BYTE 2

#define SP800_38A_KEY                                                          \
  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
#define SP800_38A_NONCE "f0f1f2f3f4f5f6f7f8f9fafb"
#define SP800_38A_COUNTER "fcfdfeff"
#define SP800_38A_PLAIN_TEXT                                                   \
  "6bc1bee22e409f96e93d7e117393172a"                                           \
  "ae2d8a571e03ac9c9eb76fac45af8e51"                                           \
  "30c81c46a35ce411e5fbc1191a0a52ef"                                           \
  "f69f2445df4f9b17ad2b417be66c3710"
#define SP800_38A_CIPHER_TEXT                                                  \
  "601ec313775789a5b7a7f504bbf3d228"                                           \
  "f443e3ca4d62b59aca84e990cacaf5c5"                                           \
  "2b0930daa23de94ce87017ba2d84988d"                                           \
  "dfc9c58db67aada613c2dd08457941a6"
#define SP800_38A_BYTES 64
#define SP800_38A_PARTIAL_LENGTH 37

#define SEQ_KEY                                                                \
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define SEQ_NONCE "000102030405060708090a0b"
#define KEYSTREAM_COUNTER_ZERO "bddc4ccab15066ccc1fe6b0cba133eb6"
#define KEYSTREAM_COUNTER_MAX "9d52ea871d37e206b64e902d1d857e44"
#define KEYSTREAM_ACROSS_BYTE_CARRY                                            \
  "d5c9d675e44ab6eafee9f1dfde858a89"                                           \
  "0ed4aea758de0bdb6cfcf5552f35d073"

#define ROUND_TRIP_MESSAGE_LENGTH 101
#define ROUND_TRIP_MULTIPLIER 7
#define ROUND_TRIP_OFFSET 3

#define CLEANUP_TEST_PLAIN_TEXT_LEN 5
#define EXHAUSTION_OVERFLOW_BYTES 4
#define SENTINEL_BYTE 0xAA
#define SINGLE_BYTE_LENGTH 1

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    char byte_string[HEX_BYTE_STRING_LENGTH] = {
        hex[i * HEX_CHARS_PER_BYTE],
        hex[(i * HEX_CHARS_PER_BYTE) + 1],
        '\0',
    };

    bytes[i] = (uint8_t)strtoul(byte_string, NULL, PAMBLE_HEX_BASE);
  }
}

static pamble_aes_ctr_counter_block make_counter(const char *nonce_hex,
                                                 const char *counter_hex) {
  pamble_aes_ctr_counter_block block;

  hex_to_bytes(nonce_hex, block.nonce, sizeof(block.nonce));
  hex_to_bytes(counter_hex, block.value, sizeof(block.value));

  return block;
}

static void assert_bytes_equal_hex(const uint8_t *actual, const char *hex,
                                   size_t length, const char *message) {
  uint8_t expected[SP800_38A_BYTES];

  hex_to_bytes(hex, expected, length);
  cr_assert_eq(memcmp(actual, expected, length), 0, "%s", message);
}

static bool is_all_zero(const void *data, size_t length) {
  const uint8_t *bytes = data;

  for (size_t i = 0; i < length; ++i) {
    if (bytes[i] != 0) {
      return false;
    }
  }
  return true;
}

static pamble_status stream_crypt(const uint8_t *key,
                                  pamble_aes_ctr_counter_block counter,
                                  const uint8_t *input, size_t length,
                                  uint8_t *output) {
  pamble_aes_ctr_ctx ctx;

  pamble_status status = pamble_aes_ctr_init(&ctx, key, counter);
  if (status != PAMBLE_OK) {
    return status;
  }

  status = pamble_aes_ctr_update(&ctx, input, length, output);
  pamble_status cleanup_status = pamble_aes_ctr_cleanup(&ctx);

  if (status != PAMBLE_OK) {
    return status;
  }
  return cleanup_status;
}

Test(pamble_aes_ctr, constants_match_aes_block_size) {
  cr_assert_eq(PAMBLE_AES_CTR_NONCE_BYTES, 12);
  cr_assert_eq(PAMBLE_AES_CTR_COUNTER_BYTES, 4);
  cr_assert_eq(PAMBLE_AES_CTR_BLOCK_BYTES, PAMBLE_AES_BLOCK_SIZE);
}

Test(pamble_aes_ctr, flatten_counter_block_is_nonce_then_counter) {
  pamble_aes_ctr_counter_block block =
      make_counter("000102030405060708090a0b", "0c0d0e0f");
  uint8_t flat[PAMBLE_AES_CTR_BLOCK_BYTES];

  pamble_aes_ctr_flatten_counter_block(&block, flat);

  assert_bytes_equal_hex(flat, "000102030405060708090a0b0c0d0e0f", sizeof(flat),
                         "flattened counter block is wrong");
}

Test(pamble_aes_ctr, sp800_38a_f55_streaming_init_update) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t plain_text[SP800_38A_BYTES];
  uint8_t output[SP800_38A_BYTES];
  pamble_aes_ctr_ctx ctx;

  hex_to_bytes(SP800_38A_KEY, key, sizeof(key));
  hex_to_bytes(SP800_38A_PLAIN_TEXT, plain_text, sizeof(plain_text));

  cr_assert_eq(pamble_aes_ctr_init(
                   &ctx, key, make_counter(SP800_38A_NONCE, SP800_38A_COUNTER)),
               PAMBLE_OK);
  cr_assert_eq(
      pamble_aes_ctr_update(&ctx, plain_text, sizeof(plain_text), output),
      PAMBLE_OK);
  cr_assert_eq(pamble_aes_ctr_cleanup(&ctx), PAMBLE_OK);

  assert_bytes_equal_hex(output, SP800_38A_CIPHER_TEXT, sizeof(output),
                         "streaming ciphertext does not match F.5.5");
}

Test(pamble_aes_ctr, sp800_38a_f55_streaming_decrypt) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t cipher_text[SP800_38A_BYTES];
  uint8_t output[SP800_38A_BYTES];

  hex_to_bytes(SP800_38A_KEY, key, sizeof(key));
  hex_to_bytes(SP800_38A_CIPHER_TEXT, cipher_text, sizeof(cipher_text));

  cr_assert_eq(stream_crypt(key,
                            make_counter(SP800_38A_NONCE, SP800_38A_COUNTER),
                            cipher_text, sizeof(cipher_text), output),
               PAMBLE_OK);

  assert_bytes_equal_hex(output, SP800_38A_PLAIN_TEXT, sizeof(output),
                         "decryption does not recover the plain text");
}

Test(pamble_aes_ctr, partial_final_block_is_a_prefix_of_the_keystream) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t plain_text[SP800_38A_BYTES];
  uint8_t output[SP800_38A_BYTES];
  const size_t length = SP800_38A_PARTIAL_LENGTH;

  hex_to_bytes(SP800_38A_KEY, key, sizeof(key));
  hex_to_bytes(SP800_38A_PLAIN_TEXT, plain_text, sizeof(plain_text));

  cr_assert_eq(stream_crypt(key,
                            make_counter(SP800_38A_NONCE, SP800_38A_COUNTER),
                            plain_text, length, output),
               PAMBLE_OK);

  assert_bytes_equal_hex(output, SP800_38A_CIPHER_TEXT, length,
                         "partial message is not a prefix of the F.5.5 output");
}

Test(pamble_aes_ctr, keystream_for_counter_zero) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint8_t zeros[PAMBLE_AES_BLOCK_SIZE] = {0};
  uint8_t output[PAMBLE_AES_BLOCK_SIZE];

  hex_to_bytes(SEQ_KEY, key, sizeof(key));
  hex_to_bytes(SEQ_NONCE, nonce, sizeof(nonce));

  cr_assert_eq(pamble_aes_ctr_crypt(key, nonce, zeros, sizeof(zeros), output),
               PAMBLE_OK);

  assert_bytes_equal_hex(output, KEYSTREAM_COUNTER_ZERO, sizeof(output),
                         "keystream for counter 0 is wrong");
}

Test(pamble_aes_ctr, counter_carries_across_bytes) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t zeros[2 * PAMBLE_AES_BLOCK_SIZE] = {0};
  uint8_t output[2 * PAMBLE_AES_BLOCK_SIZE];

  hex_to_bytes(SEQ_KEY, key, sizeof(key));

  cr_assert_eq(stream_crypt(key, make_counter(SEQ_NONCE, "000000ff"), zeros,
                            sizeof(zeros), output),
               PAMBLE_OK);

  assert_bytes_equal_hex(output, KEYSTREAM_ACROSS_BYTE_CARRY, sizeof(output),
                         "counter carry produced the wrong keystream");
}

Test(pamble_aes_ctr, one_shot_matches_streaming_from_counter_zero) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint8_t plain_text[SP800_38A_BYTES];
  uint8_t one_shot_output[SP800_38A_BYTES];
  uint8_t streaming_output[SP800_38A_BYTES];

  hex_to_bytes(SP800_38A_KEY, key, sizeof(key));
  hex_to_bytes(SP800_38A_NONCE, nonce, sizeof(nonce));
  hex_to_bytes(SP800_38A_PLAIN_TEXT, plain_text, sizeof(plain_text));

  cr_assert_eq(pamble_aes_ctr_crypt(key, nonce, plain_text, sizeof(plain_text),
                                    one_shot_output),
               PAMBLE_OK);
  cr_assert_eq(stream_crypt(key, make_counter(SP800_38A_NONCE, "00000000"),
                            plain_text, sizeof(plain_text), streaming_output),
               PAMBLE_OK);

  cr_assert_eq(
      memcmp(one_shot_output, streaming_output, sizeof(one_shot_output)), 0,
      "one-shot output differs from streaming output starting at counter 0");
}

Test(pamble_aes_ctr, one_shot_does_not_modify_the_nonce) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint8_t original_nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint8_t zeros[3 * PAMBLE_AES_BLOCK_SIZE] = {0};
  uint8_t output[sizeof(zeros)];

  hex_to_bytes(SEQ_KEY, key, sizeof(key));
  hex_to_bytes(SEQ_NONCE, nonce, sizeof(nonce));
  memcpy(original_nonce, nonce, sizeof(nonce));

  cr_assert_eq(pamble_aes_ctr_crypt(key, nonce, zeros, sizeof(zeros), output),
               PAMBLE_OK);

  cr_assert_eq(memcmp(nonce, original_nonce, sizeof(nonce)), 0,
               "one-shot encrypt modified the caller's nonce");
}

Test(pamble_aes_ctr, chunked_update_matches_one_shot_for_every_split) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t plain_text[SP800_38A_BYTES];
  uint8_t expected[SP800_38A_BYTES];

  hex_to_bytes(SP800_38A_KEY, key, sizeof(key));
  hex_to_bytes(SP800_38A_PLAIN_TEXT, plain_text, sizeof(plain_text));
  hex_to_bytes(SP800_38A_CIPHER_TEXT, expected, sizeof(expected));

  for (size_t split = 0; split <= sizeof(plain_text); ++split) {
    uint8_t output[SP800_38A_BYTES] = {0};
    pamble_aes_ctr_ctx ctx;

    cr_assert_eq(
        pamble_aes_ctr_init(&ctx, key,
                            make_counter(SP800_38A_NONCE, SP800_38A_COUNTER)),
        PAMBLE_OK);
    cr_assert_eq(pamble_aes_ctr_update(&ctx, plain_text, split, output),
                 PAMBLE_OK);
    cr_assert_eq(pamble_aes_ctr_update(&ctx, plain_text + split,
                                       sizeof(plain_text) - split,
                                       output + split),
                 PAMBLE_OK);

    cr_assert_eq(memcmp(output, expected, sizeof(expected)), 0,
                 "output differs when split at byte %zu", split);
  }
}

Test(pamble_aes_ctr, one_byte_at_a_time_matches_one_shot) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t plain_text[SP800_38A_BYTES];
  uint8_t output[SP800_38A_BYTES];
  pamble_aes_ctr_ctx ctx;

  hex_to_bytes(SP800_38A_KEY, key, sizeof(key));
  hex_to_bytes(SP800_38A_PLAIN_TEXT, plain_text, sizeof(plain_text));

  cr_assert_eq(pamble_aes_ctr_init(
                   &ctx, key, make_counter(SP800_38A_NONCE, SP800_38A_COUNTER)),
               PAMBLE_OK);

  for (size_t i = 0; i < sizeof(plain_text); ++i) {
    cr_assert_eq(pamble_aes_ctr_update(&ctx, &plain_text[i], SINGLE_BYTE_LENGTH,
                                       &output[i]),
                 PAMBLE_OK);
  }

  assert_bytes_equal_hex(output, SP800_38A_CIPHER_TEXT, sizeof(output),
                         "byte-wise streaming does not match F.5.5");
}

Test(pamble_aes_ctr, in_place_operation) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t buffer[SP800_38A_BYTES];

  hex_to_bytes(SP800_38A_KEY, key, sizeof(key));
  hex_to_bytes(SP800_38A_PLAIN_TEXT, buffer, sizeof(buffer));

  cr_assert_eq(stream_crypt(key,
                            make_counter(SP800_38A_NONCE, SP800_38A_COUNTER),
                            buffer, sizeof(buffer), buffer),
               PAMBLE_OK);

  assert_bytes_equal_hex(buffer, SP800_38A_CIPHER_TEXT, sizeof(buffer),
                         "in-place encryption does not match F.5.5");
}

Test(pamble_aes_ctr, one_shot_in_place_round_trip) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint8_t buffer[SP800_38A_BYTES];
  uint8_t original[SP800_38A_BYTES];

  hex_to_bytes(SEQ_KEY, key, sizeof(key));
  hex_to_bytes(SEQ_NONCE, nonce, sizeof(nonce));
  hex_to_bytes(SP800_38A_PLAIN_TEXT, buffer, sizeof(buffer));
  memcpy(original, buffer, sizeof(buffer));

  cr_assert_eq(pamble_aes_ctr_crypt(key, nonce, buffer, sizeof(buffer), buffer),
               PAMBLE_OK);
  cr_assert_neq(memcmp(buffer, original, sizeof(buffer)), 0,
                "in-place one-shot did not change the buffer");
  cr_assert_eq(pamble_aes_ctr_crypt(key, nonce, buffer, sizeof(buffer), buffer),
               PAMBLE_OK);
  cr_assert_eq(memcmp(buffer, original, sizeof(buffer)), 0,
               "in-place one-shot round trip did not restore the message");
}

Test(pamble_aes_ctr, round_trip_restores_message) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  const size_t message_length = ROUND_TRIP_MESSAGE_LENGTH;
  uint8_t message[message_length];
  uint8_t encrypted[sizeof(message)];
  uint8_t decrypted[sizeof(message)];

  hex_to_bytes(SEQ_KEY, key, sizeof(key));
  hex_to_bytes(SEQ_NONCE, nonce, sizeof(nonce));
  for (size_t i = 0; i < sizeof(message); ++i) {
    message[i] = (uint8_t)((i * ROUND_TRIP_MULTIPLIER) + ROUND_TRIP_OFFSET);
  }

  cr_assert_eq(
      pamble_aes_ctr_crypt(key, nonce, message, sizeof(message), encrypted),
      PAMBLE_OK);
  cr_assert_neq(memcmp(message, encrypted, sizeof(message)), 0,
                "ciphertext equals plain text");
  cr_assert_eq(
      pamble_aes_ctr_crypt(key, nonce, encrypted, sizeof(encrypted), decrypted),
      PAMBLE_OK);

  cr_assert_eq(memcmp(message, decrypted, sizeof(message)), 0,
               "round trip did not restore the message");
}

Test(pamble_aes_ctr, different_nonces_give_different_keystreams) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t first_nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint8_t second_nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint8_t zeros[PAMBLE_AES_BLOCK_SIZE] = {0};
  uint8_t first[PAMBLE_AES_BLOCK_SIZE];
  uint8_t second[PAMBLE_AES_BLOCK_SIZE];

  hex_to_bytes(SEQ_KEY, key, sizeof(key));
  hex_to_bytes(SEQ_NONCE, first_nonce, sizeof(first_nonce));
  hex_to_bytes("ffffffffffffffffffffffff", second_nonce, sizeof(second_nonce));

  cr_assert_eq(
      pamble_aes_ctr_crypt(key, first_nonce, zeros, sizeof(zeros), first),
      PAMBLE_OK);
  cr_assert_eq(
      pamble_aes_ctr_crypt(key, second_nonce, zeros, sizeof(zeros), second),
      PAMBLE_OK);

  cr_assert_neq(memcmp(first, second, sizeof(first)), 0,
                "different nonces produced the same keystream");
}

Test(pamble_aes_ctr, init_stores_counter_and_marks_keystream_empty) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  pamble_aes_ctr_ctx ctx;
  pamble_aes_ctr_counter_block counter = make_counter(SEQ_NONCE, "01020304");

  hex_to_bytes(SEQ_KEY, key, sizeof(key));

  cr_assert_eq(pamble_aes_ctr_init(&ctx, key, counter), PAMBLE_OK);

  cr_assert_eq(memcmp(&ctx.counter, &counter, sizeof(counter)), 0);
  cr_assert_eq(ctx.keystream_offset, PAMBLE_AES_BLOCK_SIZE);
  cr_assert_not(ctx.exhausted_counter);
}

Test(pamble_aes_ctr, counter_is_big_endian_and_advances_per_block) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t zeros[2 * PAMBLE_AES_BLOCK_SIZE] = {0};
  uint8_t output[sizeof(zeros)];
  pamble_aes_ctr_ctx ctx;
  const uint8_t expected_counter[PAMBLE_AES_CTR_COUNTER_BYTES] = {
      0x00,
      0x00,
      0x01,
      0x01,
  };

  hex_to_bytes(SEQ_KEY, key, sizeof(key));

  cr_assert_eq(
      pamble_aes_ctr_init(&ctx, key, make_counter(SEQ_NONCE, "000000ff")),
      PAMBLE_OK);
  cr_assert_eq(pamble_aes_ctr_update(&ctx, zeros, sizeof(zeros), output),
               PAMBLE_OK);

  cr_assert_eq(
      memcmp(ctx.counter.value, expected_counter, sizeof(expected_counter)), 0,
      "counter did not advance to expected value");
}

Test(pamble_aes_ctr, nonce_is_never_modified) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t zeros[3 * PAMBLE_AES_BLOCK_SIZE] = {0};
  uint8_t output[sizeof(zeros)];
  pamble_aes_ctr_ctx ctx;
  pamble_aes_ctr_counter_block counter = make_counter(SEQ_NONCE, "fffffffd");

  hex_to_bytes(SEQ_KEY, key, sizeof(key));

  cr_assert_eq(pamble_aes_ctr_init(&ctx, key, counter), PAMBLE_OK);
  cr_assert_eq(pamble_aes_ctr_update(&ctx, zeros, sizeof(zeros), output),
               PAMBLE_OK);

  cr_assert_eq(memcmp(ctx.counter.nonce, counter.nonce, sizeof(counter.nonce)),
               0, "counter carry leaked into the nonce");
}

Test(pamble_aes_ctr, cleanup_zeroes_the_whole_context) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  const uint8_t plain_text[CLEANUP_TEST_PLAIN_TEXT_LEN] = {1, 2, 3, 4, 5};
  uint8_t output[sizeof(plain_text)];
  pamble_aes_ctr_ctx ctx;

  hex_to_bytes(SEQ_KEY, key, sizeof(key));

  cr_assert_eq(
      pamble_aes_ctr_init(&ctx, key, make_counter(SEQ_NONCE, "00000000")),
      PAMBLE_OK);
  cr_assert_eq(
      pamble_aes_ctr_update(&ctx, plain_text, sizeof(plain_text), output),
      PAMBLE_OK);
  cr_assert_not(is_all_zero(&ctx, sizeof(ctx)),
                "context is unexpectedly blank");

  cr_assert_eq(pamble_aes_ctr_cleanup(&ctx), PAMBLE_OK);

  cr_assert(is_all_zero(&ctx, sizeof(ctx)), "cleanup left data in the context");
}

Test(pamble_aes_ctr, empty_message_succeeds_and_consumes_no_keystream) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t output[SINGLE_BYTE_LENGTH] = {SENTINEL_BYTE};
  pamble_aes_ctr_ctx ctx;
  pamble_aes_ctr_counter_block counter = make_counter(SEQ_NONCE, "00000007");

  hex_to_bytes(SEQ_KEY, key, sizeof(key));

  cr_assert_eq(pamble_aes_ctr_init(&ctx, key, counter), PAMBLE_OK);
  cr_assert_eq(pamble_aes_ctr_update(&ctx, NULL, 0, output), PAMBLE_OK);

  cr_assert_eq(output[0], SENTINEL_BYTE, "empty update wrote to the output");
  cr_assert_eq(memcmp(&ctx.counter, &counter, sizeof(counter)), 0,
               "empty update advanced the counter");
  cr_assert_eq(ctx.keystream_offset, PAMBLE_AES_BLOCK_SIZE);
}

Test(pamble_aes_ctr, one_shot_empty_message_succeeds_and_writes_nothing) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint8_t output[SINGLE_BYTE_LENGTH] = {SENTINEL_BYTE};

  hex_to_bytes(SEQ_KEY, key, sizeof(key));
  hex_to_bytes(SEQ_NONCE, nonce, sizeof(nonce));

  cr_assert_eq(pamble_aes_ctr_crypt(key, nonce, NULL, 0, output), PAMBLE_OK);
  cr_assert_eq(output[0], SENTINEL_BYTE, "empty one-shot wrote to the output");
}

Test(pamble_aes_ctr, last_counter_value_is_still_usable) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t zeros[PAMBLE_AES_BLOCK_SIZE] = {0};
  uint8_t output[PAMBLE_AES_BLOCK_SIZE];
  pamble_aes_ctr_ctx ctx;

  hex_to_bytes(SEQ_KEY, key, sizeof(key));

  cr_assert_eq(
      pamble_aes_ctr_init(&ctx, key, make_counter(SEQ_NONCE, "ffffffff")),
      PAMBLE_OK);
  cr_assert_eq(pamble_aes_ctr_update(&ctx, zeros, sizeof(zeros), output),
               PAMBLE_OK);

  assert_bytes_equal_hex(output, KEYSTREAM_COUNTER_MAX, sizeof(output),
                         "keystream for counter ffffffff is wrong");
  cr_assert(ctx.exhausted_counter);
}

Test(pamble_aes_ctr, counter_does_not_wrap_after_the_last_block) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t zeros[PAMBLE_AES_BLOCK_SIZE + 1] = {0};
  uint8_t output[sizeof(zeros)];
  pamble_aes_ctr_ctx ctx;
  const uint8_t max_counter[PAMBLE_AES_CTR_COUNTER_BYTES] = {
      0xFF,
      0xFF,
      0xFF,
      0xFF,
  };

  hex_to_bytes(SEQ_KEY, key, sizeof(key));

  cr_assert_eq(
      pamble_aes_ctr_init(&ctx, key, make_counter(SEQ_NONCE, "ffffffff")),
      PAMBLE_OK);

  cr_assert_eq(pamble_aes_ctr_update(&ctx, zeros, sizeof(zeros), output),
               PAMBLE_COUNTER_EXHAUSTED);

  cr_assert_eq(memcmp(ctx.counter.value, max_counter, sizeof(max_counter)), 0,
               "counter wrapped instead of staying at its maximum");
}

Test(pamble_aes_ctr, exhaustion_keeps_bytes_written_before_the_limit) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t zeros[PAMBLE_AES_BLOCK_SIZE + EXHAUSTION_OVERFLOW_BYTES] = {0};
  uint8_t output[sizeof(zeros)];
  pamble_aes_ctr_ctx ctx;

  memset(output, SENTINEL_BYTE, sizeof(output));
  hex_to_bytes(SEQ_KEY, key, sizeof(key));

  cr_assert_eq(
      pamble_aes_ctr_init(&ctx, key, make_counter(SEQ_NONCE, "ffffffff")),
      PAMBLE_OK);
  cr_assert_eq(pamble_aes_ctr_update(&ctx, zeros, sizeof(zeros), output),
               PAMBLE_COUNTER_EXHAUSTED);

  assert_bytes_equal_hex(output, KEYSTREAM_COUNTER_MAX, PAMBLE_AES_BLOCK_SIZE,
                         "bytes before the limit were not written");
  for (size_t i = PAMBLE_AES_BLOCK_SIZE; i < sizeof(output); ++i) {
    cr_assert_eq(output[i], SENTINEL_BYTE,
                 "byte %zu was written after exhaustion", i);
  }
}

Test(pamble_aes_ctr, exhaustion_is_sticky) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE];
  uint8_t zeros[PAMBLE_AES_BLOCK_SIZE] = {0};
  uint8_t output[PAMBLE_AES_BLOCK_SIZE];
  uint8_t one_byte_in = 0;
  uint8_t one_byte_out = 0;
  pamble_aes_ctr_ctx ctx;

  hex_to_bytes(SEQ_KEY, key, sizeof(key));

  cr_assert_eq(
      pamble_aes_ctr_init(&ctx, key, make_counter(SEQ_NONCE, "ffffffff")),
      PAMBLE_OK);
  cr_assert_eq(pamble_aes_ctr_update(&ctx, zeros, sizeof(zeros), output),
               PAMBLE_OK);

  cr_assert_eq(pamble_aes_ctr_update(&ctx, &one_byte_in, SINGLE_BYTE_LENGTH,
                                     &one_byte_out),
               PAMBLE_COUNTER_EXHAUSTED);
  cr_assert_eq(pamble_aes_ctr_update(&ctx, &one_byte_in, SINGLE_BYTE_LENGTH,
                                     &one_byte_out),
               PAMBLE_COUNTER_EXHAUSTED);
}

Test(pamble_aes_ctr, init_rejects_null_context) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE] = {0};

  cr_assert_eq(
      pamble_aes_ctr_init(NULL, key, make_counter(SEQ_NONCE, "00000000")),
      PAMBLE_INVALID_ARGUMENT);
}

Test(pamble_aes_ctr, update_rejects_null_context) {
  uint8_t input[SINGLE_BYTE_LENGTH] = {0};
  uint8_t output[SINGLE_BYTE_LENGTH];

  cr_assert_eq(pamble_aes_ctr_update(NULL, input, sizeof(input), output),
               PAMBLE_INVALID_ARGUMENT);
}

Test(pamble_aes_ctr, update_rejects_null_input_with_nonzero_length) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE] = {0};
  uint8_t output[SINGLE_BYTE_LENGTH];
  pamble_aes_ctr_ctx ctx;

  cr_assert_eq(
      pamble_aes_ctr_init(&ctx, key, make_counter(SEQ_NONCE, "00000000")),
      PAMBLE_OK);

  cr_assert_eq(pamble_aes_ctr_update(&ctx, NULL, SINGLE_BYTE_LENGTH, output),
               PAMBLE_INVALID_ARGUMENT);
}

Test(pamble_aes_ctr, cleanup_rejects_null_context) {
  cr_assert_eq(pamble_aes_ctr_cleanup(NULL), PAMBLE_INVALID_ARGUMENT);
}

Test(pamble_aes_ctr, encrypt_rejects_null_input_with_nonzero_length) {
  uint8_t key[PAMBLE_AES256_KEY_SIZE] = {0};
  uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint8_t output[SINGLE_BYTE_LENGTH];

  hex_to_bytes(SEQ_NONCE, nonce, sizeof(nonce));

  cr_assert_eq(
      pamble_aes_ctr_crypt(key, nonce, NULL, SINGLE_BYTE_LENGTH, output),
      PAMBLE_INVALID_ARGUMENT);
}
