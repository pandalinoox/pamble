#include "pamble/pamble_pdkdf2.h"

#include <criterion/criterion.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PAMBLE_HEX_BASE 16
#define HEX_BYTE_STRING_LENGTH 3
#define DK_LEN_ONE_BLOCK 32
#define DK_LEN_TWO_BLOCKS 64
#define DK_LEN_TRUNCATED 40
#define NULL_PASSWORD_TEST_LEN 8
#define NULL_SALT_TEST_LEN 4

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    char byte_string[HEX_BYTE_STRING_LENGTH] = {
        hex[i * 2],
        hex[(i * 2) + 1],
        '\0',
    };

    bytes[i] = (uint8_t)strtoul(byte_string, NULL, PAMBLE_HEX_BASE);
  }
}

static uint8_t *expected_bytes(const char *expected_hex, size_t dk_length) {
  uint8_t *expected = malloc(dk_length);

  cr_assert_not_null(expected);

  hex_to_bytes(expected_hex, expected, dk_length);

  return expected;
}

static void assert_dk(const uint8_t *actual, const char *expected_hex,
                      size_t dk_length) {
  uint8_t *expected = expected_bytes(expected_hex, dk_length);

  cr_assert_eq(memcmp(actual, expected, dk_length), 0,
               "PBKDF2 derived key does not match expected value");

  free(expected);
}

Test(pamble_pbkdf2, known_answer_case1) {
  static const uint8_t password[] = "password";
  static const uint8_t salt[] = "salt";
  uint8_t *derived_key;

  pamble_status status =
      pamble_pbkdf2(password, sizeof(password) - 1, salt, sizeof(salt) - 1,
                    &derived_key, DK_LEN_ONE_BLOCK);

  cr_assert_eq(status, PAMBLE_OK);

  assert_dk(derived_key,
            "669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178",
            DK_LEN_ONE_BLOCK);

  pamble_free_pbkdf2_dk(derived_key);
}

Test(pamble_pbkdf2, known_answer_case_multi_block) {
  static const uint8_t password[] = "password";
  static const uint8_t salt[] = "salt";
  uint8_t *derived_key;

  pamble_status status =
      pamble_pbkdf2(password, sizeof(password) - 1, salt, sizeof(salt) - 1,
                    &derived_key, DK_LEN_TWO_BLOCKS);

  cr_assert_eq(status, PAMBLE_OK);

  assert_dk(derived_key,
            "669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178"
            "e0547923c484decfa97a12eb6316e0d3a3787de6065ae832d403588adfc9757c",
            DK_LEN_TWO_BLOCKS);

  pamble_free_pbkdf2_dk(derived_key);
}

Test(pamble_pbkdf2, known_answer_case_truncated_block) {
  static const uint8_t password[] = "password";
  static const uint8_t salt[] = "salt";
  uint8_t *derived_key;

  pamble_status status =
      pamble_pbkdf2(password, sizeof(password) - 1, salt, sizeof(salt) - 1,
                    &derived_key, DK_LEN_TRUNCATED);

  cr_assert_eq(status, PAMBLE_OK);

  assert_dk(derived_key,
            "669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178"
            "e0547923c484decf",
            DK_LEN_TRUNCATED);

  pamble_free_pbkdf2_dk(derived_key);
}

Test(pamble_pbkdf2, empty_password) {
  static const uint8_t salt[] = "salt";
  uint8_t *derived_key;

  pamble_status status = pamble_pbkdf2(NULL, 0, salt, sizeof(salt) - 1,
                                       &derived_key, DK_LEN_ONE_BLOCK);

  cr_assert_eq(status, PAMBLE_OK);

  assert_dk(derived_key,
            "4ad0a00a18521498d5b3b28f40eccf49e0c25404c0d7bfcb4021b044c1cc42b1",
            DK_LEN_ONE_BLOCK);

  pamble_free_pbkdf2_dk(derived_key);
}

Test(pamble_pbkdf2, empty_salt) {
  static const uint8_t password[] = "password";
  uint8_t *derived_key;

  pamble_status status = pamble_pbkdf2(password, sizeof(password) - 1, NULL, 0,
                                       &derived_key, DK_LEN_ONE_BLOCK);

  cr_assert_eq(status, PAMBLE_OK);

  assert_dk(derived_key,
            "fdc25be00b18ba5c79d8bf7a452d98c248b11f2c7e9c871d24f1f880381e95cf",
            DK_LEN_ONE_BLOCK);

  pamble_free_pbkdf2_dk(derived_key);
}

Test(pamble_pbkdf2, empty_password_and_salt) {
  uint8_t *derived_key;

  pamble_status status =
      pamble_pbkdf2(NULL, 0, NULL, 0, &derived_key, DK_LEN_ONE_BLOCK);

  cr_assert_eq(status, PAMBLE_OK);

  assert_dk(derived_key,
            "3106cb5743a54114a36bb7d3b2afa0242360b58243264728a9ca208548082281",
            DK_LEN_ONE_BLOCK);

  pamble_free_pbkdf2_dk(derived_key);
}

Test(pamble_pbkdf2, null_password_with_nonzero_length) {
  static const uint8_t salt[] = "salt";
  uint8_t *derived_key;

  pamble_status status =
      pamble_pbkdf2(NULL, NULL_PASSWORD_TEST_LEN, salt, sizeof(salt) - 1,
                    &derived_key, DK_LEN_ONE_BLOCK);

  cr_assert_eq(status, PAMBLE_INVALID_ARGUMENT);
}

Test(pamble_pbkdf2, null_salt_with_nonzero_length) {
  static const uint8_t password[] = "password";
  uint8_t *derived_key;

  pamble_status status =
      pamble_pbkdf2(password, sizeof(password) - 1, NULL, NULL_SALT_TEST_LEN,
                    &derived_key, DK_LEN_ONE_BLOCK);

  cr_assert_eq(status, PAMBLE_INVALID_ARGUMENT);
}

Test(pamble_pbkdf2, null_derived_key_output_param) {
  static const uint8_t password[] = "password";
  static const uint8_t salt[] = "salt";

  pamble_status status =
      pamble_pbkdf2(password, sizeof(password) - 1, salt, sizeof(salt) - 1,
                    NULL, DK_LEN_ONE_BLOCK);

  cr_assert_eq(status, PAMBLE_INVALID_ARGUMENT);
}

Test(pamble_pbkdf2, zero_dk_length) {
  static const uint8_t password[] = "password";
  static const uint8_t salt[] = "salt";
  uint8_t *derived_key;

  pamble_status status = pamble_pbkdf2(password, sizeof(password) - 1, salt,
                                       sizeof(salt) - 1, &derived_key, 0);

  cr_assert_eq(status, PAMBLE_INVALID_ARGUMENT);
}
