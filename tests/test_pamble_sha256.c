#include "pamble/pamble_sha256.h"

#include <criterion/criterion.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PAMBLE_HEX_BASE 16

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    char byte_string[3] = {hex[i * 2], hex[(i * 2) + 1], '\0'};

    bytes[i] = (uint8_t)strtoul(byte_string, NULL, PAMBLE_HEX_BASE);
  }
}

static void assert_digest(const uint8_t actual[PAMBLE_SHA256_DIGEST_LENGTH],
                          const char *expected_hex) {
  uint8_t expected[PAMBLE_SHA256_DIGEST_LENGTH];

  hex_to_bytes(expected_hex, expected, PAMBLE_SHA256_DIGEST_LENGTH);

  cr_assert_eq(memcmp(actual, expected, PAMBLE_SHA256_DIGEST_LENGTH), 0,
               "SHA-256 digest does not match expected value");
}

Test(pamble_sha256, empty_message) {
  uint8_t digest[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status = pamble_sha256(NULL, 0, digest);

  cr_assert_eq(status, PAMBLE_OK);

  assert_digest(
      digest,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

Test(pamble_sha256, single_byte) {
  static const uint8_t message[] = "a";
  uint8_t digest[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status = pamble_sha256(message, sizeof(message) - 1, digest);

  cr_assert_eq(status, PAMBLE_OK);

  assert_digest(digest, "ca978112ca1bbdcafac231b39a23dc4d"
                        "a786eff8147c4e72b9807785afee48bb");
}

Test(pamble_sha256, abc) {
  static const uint8_t message[] = "abc";
  uint8_t digest[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status = pamble_sha256(message, sizeof(message) - 1, digest);

  cr_assert_eq(status, PAMBLE_OK);

  assert_digest(
      digest,
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

Test(pamble_sha256, standard_test_vector) {
  static const uint8_t message[] =
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

  uint8_t digest[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status = pamble_sha256(message, sizeof(message) - 1, digest);

  cr_assert_eq(status, PAMBLE_OK);

  assert_digest(
      digest,
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

Test(pamble_sha256, null_output_buffer) {
  static const uint8_t message[] = "abc";

  pamble_status status = pamble_sha256(message, sizeof(message) - 1, NULL);

  cr_assert_eq(status, PAMBLE_INVALID_ARGUMENT);
}

Test(pamble_sha256, null_message_with_nonzero_length) {
  uint8_t digest[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status = pamble_sha256(NULL, 3, digest);

  cr_assert_eq(status, PAMBLE_INVALID_ARGUMENT);
}

Test(pamble_sha256, null_message_with_zero_length) {
  uint8_t digest[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status = pamble_sha256(NULL, 0, digest);

  cr_assert_eq(status, PAMBLE_OK);

  assert_digest(
      digest,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}
