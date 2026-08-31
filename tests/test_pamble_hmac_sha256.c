#include "pamble/pamble_hmac_sha256.h"

#include <criterion/criterion.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PAMBLE_HEX_BASE 16
#define HEX_BYTE_STRING_LENGTH 3
#define RFC4231_CASE1_KEY_LEN 20
#define RFC4231_CASE3_KEY_LEN 20
#define RFC4231_CASE3_MSG_LEN 50
#define RFC4231_CASE4_KEY_LEN 32
#define RFC4231_CASE4_MSG_LEN 50
#define LARGE_KEY_LEN 131
#define NULL_KEY_TEST_LEN 20
#define NULL_MSG_TEST_LEN 3
#define BYTE_FILL_AA 0xaa
#define BYTE_FILL_DD 0xdd
#define BYTE_FILL_CD 0xcd

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    char byte_string[HEX_BYTE_STRING_LENGTH] = {hex[i * 2], hex[(i * 2) + 1],
                                                '\0'};

    bytes[i] = (uint8_t)strtoul(byte_string, NULL, PAMBLE_HEX_BASE);
  }
}

static void assert_mac(const uint8_t actual[PAMBLE_SHA256_DIGEST_LENGTH],
                       const char *expected_hex) {
  uint8_t expected[PAMBLE_SHA256_DIGEST_LENGTH];

  hex_to_bytes(expected_hex, expected, PAMBLE_SHA256_DIGEST_LENGTH);

  cr_assert_eq(memcmp(actual, expected, PAMBLE_SHA256_DIGEST_LENGTH), 0,
               "HMAC-SHA256 does not match expected value");
}

Test(pamble_hmac_sha256, rfc4231_case1) {
  static const uint8_t key[RFC4231_CASE1_KEY_LEN] = {
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
  static const uint8_t message[] = "Hi There";
  uint8_t mac[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status =
      pamble_hmac_sha256(key, sizeof(key), message, sizeof(message) - 1, mac);

  cr_assert_eq(status, PAMBLE_OK);

  assert_mac(
      mac, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

Test(pamble_hmac_sha256, rfc4231_case2) {
  static const uint8_t key[] = "Jefe";
  static const uint8_t message[] = "what do ya want for nothing?";
  uint8_t mac[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status = pamble_hmac_sha256(key, sizeof(key) - 1, message,
                                            sizeof(message) - 1, mac);

  cr_assert_eq(status, PAMBLE_OK);

  assert_mac(
      mac, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

Test(pamble_hmac_sha256, rfc4231_case3) {
  uint8_t key[RFC4231_CASE3_KEY_LEN];
  uint8_t message[RFC4231_CASE3_MSG_LEN];

  memset(key, BYTE_FILL_AA, sizeof(key));
  memset(message, BYTE_FILL_DD, sizeof(message));

  uint8_t mac[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status =
      pamble_hmac_sha256(key, sizeof(key), message, sizeof(message), mac);

  cr_assert_eq(status, PAMBLE_OK);

  assert_mac(
      mac, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
}

Test(pamble_hmac_sha256, rfc4231_case4) {
  static const uint8_t key[RFC4231_CASE4_KEY_LEN] = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
      0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
      0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
  uint8_t message[RFC4231_CASE4_MSG_LEN];

  memset(message, BYTE_FILL_CD, sizeof(message));

  uint8_t mac[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status =
      pamble_hmac_sha256(key, sizeof(key), message, sizeof(message), mac);

  cr_assert_eq(status, PAMBLE_OK);

  assert_mac(
      mac, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
}

Test(pamble_hmac_sha256, key_longer_than_block_size) {
  uint8_t key[LARGE_KEY_LEN];
  static const uint8_t message[] =
      "Test Using Larger Than Block-Size Key - Hash Key First";

  memset(key, BYTE_FILL_AA, sizeof(key));

  uint8_t mac[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status =
      pamble_hmac_sha256(key, sizeof(key), message, sizeof(message) - 1, mac);

  cr_assert_eq(status, PAMBLE_OK);

  assert_mac(
      mac, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

Test(pamble_hmac_sha256, key_and_message_longer_than_block_size) {
  uint8_t key[LARGE_KEY_LEN];
  static const uint8_t message[] =
      "This is a test using a larger than block-size key and a larger "
      "than block-size data. The key needs to be hashed before being "
      "used by the HMAC algorithm.";

  memset(key, BYTE_FILL_AA, sizeof(key));

  uint8_t mac[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status =
      pamble_hmac_sha256(key, sizeof(key), message, sizeof(message) - 1, mac);

  cr_assert_eq(status, PAMBLE_OK);

  assert_mac(
      mac, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
}

Test(pamble_hmac_sha256, empty_key_and_message) {
  uint8_t mac[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status = pamble_hmac_sha256(NULL, 0, NULL, 0, mac);

  cr_assert_eq(status, PAMBLE_OK);

  assert_mac(
      mac, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
}

Test(pamble_hmac_sha256, null_key_with_nonzero_length) {
  static const uint8_t message[] = "abc";
  uint8_t mac[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status = pamble_hmac_sha256(NULL, NULL_KEY_TEST_LEN, message,
                                            sizeof(message) - 1, mac);

  cr_assert_eq(status, PAMBLE_INVALID_ARGUMENT);
}

Test(pamble_hmac_sha256, null_message_with_nonzero_length) {
  static const uint8_t key[] = "key";
  uint8_t mac[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status =
      pamble_hmac_sha256(key, sizeof(key) - 1, NULL, NULL_MSG_TEST_LEN, mac);

  cr_assert_eq(status, PAMBLE_INVALID_ARGUMENT);
}

Test(pamble_hmac_sha256, null_message_with_zero_length) {
  static const uint8_t key[] = "key";
  uint8_t mac[PAMBLE_SHA256_DIGEST_LENGTH];

  pamble_status status = pamble_hmac_sha256(key, sizeof(key) - 1, NULL, 0, mac);

  cr_assert_eq(status, PAMBLE_OK);

  assert_mac(
      mac, "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0");
}
