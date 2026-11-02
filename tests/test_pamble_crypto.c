#include "pamble/pamble_archive.h"
#include "pamble/pamble_crypto.h"
#include "pamble/pamble_pdkdf2.h"

#include <criterion/criterion.h>
#include <ftw.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEMP_TEMPLATE "/tmp/pamble_crypto_XXXXXX"
#define TEMP_TEMPLATE_SIZE 32
#define PATH_BUFFER_SIZE 512
#define NFTW_OPEN_FDS 16
#define BITS_PER_BYTE 8
#define READ_BUFFER_SIZE 4096

#define MAGIC_LENGTH 6
#define VERSION_OFFSET 6
#define SALT_OFFSET 7
#define SALT_AND_NONCE_LENGTH 24
#define LENGTH_OFFSET 31
#define LENGTH_FIELD_LENGTH 8
#define HEADER_LENGTH 39
#define TAG_LENGTH 32
#define MODE_DIR 0755
#define BAD_VERSION 9

#define CRAFTED_BODY_LENGTH 10
#define CLAIMED_BODY_LENGTH 100
#define BINARY_LENGTH 3000
#define BYTE_RANGE 256
#define STAGE_COUNT 9

#define DERIVED_KEY_BLOCKS 2
#define SLOW_TEST_TIMEOUT 300

static const char PASSWORD[] = "correct horse battery staple";
static const char WRONG_PASSWORD[] = "correct horse battery stapler";
static const char NOTE[] = "hello pamble";

typedef struct {
  char root[TEMP_TEMPLATE_SIZE];
} workspace;

typedef struct {
  bool in_order;
  unsigned last_step;
  bool seen[STAGE_COUNT];
  pamble_progress_event last[STAGE_COUNT];
} progress_log;

static void must(bool succeeded, const char *what) {
  cr_assert(succeeded, "test setup failed: %s", what);
}

static int remove_entry(const char *path, const struct stat *info, int flag,
                        struct FTW *ftw) {
  (void)info;
  (void)flag;
  (void)ftw;
  return remove(path);
}

static void workspace_init(workspace *wks) {
  strcpy(wks->root, TEMP_TEMPLATE);
  must(mkdtemp(wks->root) != NULL, "mkdtemp");
}

static void workspace_cleanup(workspace *wks) {
  nftw(wks->root, remove_entry, NFTW_OPEN_FDS, FTW_DEPTH | FTW_PHYS);
}

static void join(char out[static PATH_BUFFER_SIZE], const char *base,
                 const char *name) {
  int written = snprintf(out, PATH_BUFFER_SIZE, "%s/%s", base, name);
  must((written > 0 && written < PATH_BUFFER_SIZE) != 0, "path too long");
}

static bool write_bytes(const char *path, const uint8_t *bytes, size_t length) {
  FILE *file = fopen(path, "wb");

  if (file == NULL) {
    return false;
  }

  const bool written =
      (length == 0 || fwrite(bytes, 1, length, file) == length) != 0;

  return (fclose(file) == 0 && written) != 0;
}

static void make_dir(const workspace *wks, const char *relative) {
  char path[PATH_BUFFER_SIZE];
  join(path, wks->root, relative);
  must(mkdir(path, MODE_DIR) == 0, "mkdir");
}

static void make_file(const workspace *wks, const char *relative,
                      const uint8_t *bytes, size_t length) {
  char path[PATH_BUFFER_SIZE];
  join(path, wks->root, relative);
  must(write_bytes(path, bytes, length), "write file");
}

static void make_tree(const workspace *wks) {
  uint8_t binary[BINARY_LENGTH];

  for (size_t i = 0; i < sizeof(binary); i++) {
    binary[i] = (uint8_t)(i % BYTE_RANGE);
  }

  make_dir(wks, "input");
  make_dir(wks, "input/data");
  make_dir(wks, "input/data/sub");
  make_file(wks, "input/data/note.txt", (const uint8_t *)NOTE,
            sizeof(NOTE) - 1);
  make_file(wks, "input/data/sub/data.bin", binary, sizeof(binary));
  make_dir(wks, "out1");
  make_dir(wks, "out2");
}

static bool file_equals(const char *path_a, const char *path_b) {
  FILE *file_a = fopen(path_a, "rb");
  FILE *file_b = fopen(path_b, "rb");

  bool equal = (file_a != NULL && file_b != NULL) != 0;

  while (equal) {
    uint8_t chunk_a[READ_BUFFER_SIZE];
    uint8_t chunk_b[READ_BUFFER_SIZE];

    const size_t read_a = fread(chunk_a, 1, sizeof(chunk_a), file_a);
    const size_t read_b = fread(chunk_b, 1, sizeof(chunk_b), file_b);

    equal = ((read_a == read_b && memcmp(chunk_a, chunk_b, read_a) == 0) != 0);

    if (read_a == 0) {
      break;
    }
  }

  if (file_a != NULL) {
    fclose(file_a);
  }
  if (file_b != NULL) {
    fclose(file_b);
  }

  return equal;
}

static bool relative_files_equal(const workspace *wks, const char *left,
                                 const char *right) {
  char path_a[PATH_BUFFER_SIZE];
  char path_b[PATH_BUFFER_SIZE];
  join(path_a, wks->root, left);
  join(path_b, wks->root, right);
  return file_equals(path_a, path_b);
}

static bool tree_restored(const workspace *wks) {
  return (relative_files_equal(wks, "input/data/note.txt",
                               "out1/data/note.txt") &&
          relative_files_equal(wks, "input/data/sub/data.bin",
                               "out1/data/sub/data.bin")) != 0;
}

static bool path_missing(const workspace *wks, const char *relative) {
  char path[PATH_BUFFER_SIZE];
  join(path, wks->root, relative);

  struct stat info;
  return lstat(path, &info) != 0;
}

static bool read_file(const char *path, uint8_t **bytes, size_t *length) {
  FILE *file = fopen(path, "rb");

  if (file == NULL) {
    return false;
  }

  struct stat info;
  bool read_ok = (fstat(fileno(file), &info) == 0 && info.st_size > 0) != 0;

  if (read_ok) {
    *length = (size_t)info.st_size;
    *bytes = malloc(*length);
    read_ok =
        ((*bytes != NULL && fread(*bytes, 1, *length, file) == *length) != 0);
  }

  fclose(file);
  return read_ok;
}

static void log_event(void *context, const pamble_progress_event *event) {
  progress_log *log = context;

  if (event->step < log->last_step ||
      event->step_count != PAMBLE_CRYPTO_STEP_COUNT ||
      (unsigned)event->stage >= STAGE_COUNT) {
    log->in_order = false;
    return;
  }

  log->last_step = event->step;
  log->seen[event->stage] = true;
  log->last[event->stage] = *event;
}

static pamble_progress logging_progress(progress_log *log) {
  memset(log, 0, sizeof(*log));
  log->in_order = true;

  const pamble_progress progress = {.report = log_event, .context = log};
  return progress;
}

static bool stage_completed(const progress_log *log, pamble_stage stage,
                            unsigned step) {
  const pamble_progress_event *event = &log->last[stage];
  return (log->seen[stage] && event->step == step &&
          event->done == event->total) != 0;
}

static bool encrypt_progress_ok(const progress_log *log) {
  const pamble_progress_event *keys = &log->last[PAMBLE_STAGE_DERIVE_KEYS];

  return (log->in_order && log->last_step == PAMBLE_CRYPTO_STEP_COUNT &&
          stage_completed(log, PAMBLE_STAGE_ARCHIVE, 1) &&
          stage_completed(log, PAMBLE_STAGE_DERIVE_KEYS, 2) &&
          keys->total == (uint64_t)DERIVED_KEY_BLOCKS *
                             (uint64_t)PAMBLE_PBKDF2_ITERATIONS &&
          stage_completed(log, PAMBLE_STAGE_ENCRYPT, 3) &&
          log->last[PAMBLE_STAGE_ENCRYPT].total > 0 &&
          stage_completed(log, PAMBLE_STAGE_AUTHENTICATE, 4) &&
          stage_completed(log, PAMBLE_STAGE_WRITE, PAMBLE_CRYPTO_STEP_COUNT)) !=
         0;
}

static bool decrypt_progress_ok(const progress_log *log) {
  return (log->in_order && log->last_step == PAMBLE_CRYPTO_STEP_COUNT &&
          stage_completed(log, PAMBLE_STAGE_READ, 1) &&
          stage_completed(log, PAMBLE_STAGE_DERIVE_KEYS, 2) &&
          stage_completed(log, PAMBLE_STAGE_VERIFY, 3) &&
          stage_completed(log, PAMBLE_STAGE_DECRYPT, 4) &&
          stage_completed(log, PAMBLE_STAGE_EXTRACT,
                          PAMBLE_CRYPTO_STEP_COUNT)) != 0;
}

static pamble_crypto_payload make_payload(const workspace *wks,
                                          const char *input_relative,
                                          const char *output_relative,
                                          char paths[2][PATH_BUFFER_SIZE]) {
  join(paths[0], wks->root, input_relative);
  join(paths[1], wks->root, output_relative);

  const pamble_crypto_payload payload = {
      .input_path = paths[0],
      .output_path = paths[1],
      .password = (const uint8_t *)PASSWORD,
      .password_length = sizeof(PASSWORD) - 1,
  };

  return payload;
}

static void encrypt_tree(const workspace *wks, const char *output_relative) {
  char paths[2][PATH_BUFFER_SIZE];
  pamble_crypto_payload payload =
      make_payload(wks, "input/data", output_relative, paths);

  must(pamble_encrypt_archive(payload) == PAMBLE_OK, "encrypt");
}

static void flip_byte(const workspace *wks, const char *relative,
                      size_t offset) {
  char path[PATH_BUFFER_SIZE];
  join(path, wks->root, relative);

  uint8_t *bytes = NULL;
  size_t length = 0;
  must((read_file(path, &bytes, &length) && offset < length) != 0, "read file");

  bytes[offset] ^= 1;
  const bool written = write_bytes(path, bytes, length);
  free(bytes);
  must(written, "rewrite file");
}

typedef struct {
  const char *magic;
  uint8_t version;
  uint64_t claimed_length;
  size_t actual_length;
  size_t extra;
} crafted_file;

static void write_crafted(const workspace *wks, const char *relative,
                          const crafted_file *spec) {
  const size_t total =
      HEADER_LENGTH + spec->actual_length + TAG_LENGTH + spec->extra;
  uint8_t *bytes = calloc(total, 1);
  must(bytes != NULL, "calloc");

  memcpy(bytes, spec->magic, MAGIC_LENGTH);
  bytes[VERSION_OFFSET] = spec->version;

  for (size_t i = 0; i < LENGTH_FIELD_LENGTH; i++) {
    bytes[LENGTH_OFFSET + i] =
        (uint8_t)(spec->claimed_length >>
                  ((LENGTH_FIELD_LENGTH - i - 1) * BITS_PER_BYTE));
  }

  char path[PATH_BUFFER_SIZE];
  join(path, wks->root, relative);
  const bool written = write_bytes(path, bytes, total);
  free(bytes);
  must(written, "write crafted file");
}

static pamble_status decrypt_crafted(const workspace *wks,
                                     const crafted_file *spec,
                                     progress_log *log) {
  write_crafted(wks, "crafted.pmb", spec);

  char paths[2][PATH_BUFFER_SIZE];
  pamble_crypto_payload payload =
      make_payload(wks, "crafted.pmb", "out1", paths);
  payload.progress = logging_progress(log);

  return pamble_decrypt_archive(payload);
}

Test(pamble_crypto, round_trip_restores_tree_and_reports_progress,
     .timeout = SLOW_TEST_TIMEOUT) {
  workspace wks;
  workspace_init(&wks);
  make_tree(&wks);

  char paths[2][PATH_BUFFER_SIZE];
  progress_log encrypt_log;
  progress_log decrypt_log;

  pamble_crypto_payload sealing =
      make_payload(&wks, "input/data", "secret.pmb", paths);
  sealing.progress = logging_progress(&encrypt_log);
  const pamble_status sealed = pamble_encrypt_archive(sealing);

  char open_paths[2][PATH_BUFFER_SIZE];
  pamble_crypto_payload opening =
      make_payload(&wks, "secret.pmb", "out1", open_paths);
  opening.progress = logging_progress(&decrypt_log);
  const pamble_status opened = pamble_decrypt_archive(opening);

  const bool restored = tree_restored(&wks);
  const bool encrypt_ok = encrypt_progress_ok(&encrypt_log);
  const bool decrypt_ok = decrypt_progress_ok(&decrypt_log);
  const bool no_temp_left = path_missing(&wks, "secret.pmb.tmp");

  workspace_cleanup(&wks);

  cr_assert(sealed == PAMBLE_OK && opened == PAMBLE_OK && restored &&
                encrypt_ok && decrypt_ok && no_temp_left,
            "sealed=%d opened=%d restored=%d encrypt_progress=%d "
            "decrypt_progress=%d no_temp_left=%d",
            sealed, opened, restored, encrypt_ok, decrypt_ok, no_temp_left);
}

Test(pamble_crypto, wrong_password_fails_authentication,
     .timeout = SLOW_TEST_TIMEOUT) {
  workspace wks;
  workspace_init(&wks);
  make_tree(&wks);
  encrypt_tree(&wks, "secret.pmb");

  char paths[2][PATH_BUFFER_SIZE];
  pamble_crypto_payload payload =
      make_payload(&wks, "secret.pmb", "out1", paths);
  payload.password = (const uint8_t *)WRONG_PASSWORD;
  payload.password_length = sizeof(WRONG_PASSWORD) - 1;

  const pamble_status status = pamble_decrypt_archive(payload);
  const bool nothing_extracted = path_missing(&wks, "out1/data");

  workspace_cleanup(&wks);

  cr_assert(status == PAMBLE_AUTHENTICATION_FAILED && nothing_extracted,
            "status=%d nothing_extracted=%d", status, nothing_extracted);
}

Test(pamble_crypto, modified_ciphertext_fails_authentication,
     .timeout = SLOW_TEST_TIMEOUT) {
  workspace wks;
  workspace_init(&wks);
  make_tree(&wks);
  encrypt_tree(&wks, "secret.pmb");
  flip_byte(&wks, "secret.pmb", HEADER_LENGTH + 1);

  char paths[2][PATH_BUFFER_SIZE];
  const pamble_crypto_payload payload =
      make_payload(&wks, "secret.pmb", "out1", paths);

  const pamble_status status = pamble_decrypt_archive(payload);
  const bool nothing_extracted = path_missing(&wks, "out1/data");

  workspace_cleanup(&wks);

  cr_assert(status == PAMBLE_AUTHENTICATION_FAILED && nothing_extracted,
            "status=%d nothing_extracted=%d", status, nothing_extracted);
}

Test(pamble_crypto, layout_and_fresh_salt_and_nonce,
     .timeout = SLOW_TEST_TIMEOUT) {
  workspace wks;
  workspace_init(&wks);
  make_tree(&wks);
  encrypt_tree(&wks, "first.pmb");
  encrypt_tree(&wks, "second.pmb");

  char input[PATH_BUFFER_SIZE];
  char first_path[PATH_BUFFER_SIZE];
  char second_path[PATH_BUFFER_SIZE];
  join(input, wks.root, "input/data");
  join(first_path, wks.root, "first.pmb");
  join(second_path, wks.root, "second.pmb");

  uint8_t *archive = NULL;
  size_t archive_length = 0;
  uint8_t *first = NULL;
  uint8_t *second = NULL;
  size_t first_length = 0;
  size_t second_length = 0;

  must(pamble_archive_pack(input, &archive, &archive_length) == PAMBLE_OK,
       "pack");
  must((read_file(first_path, &first, &first_length) &&
        read_file(second_path, &second, &second_length)) != 0,
       "read encrypted files");
  pamble_free_archive(archive);

  const bool sized =
      (first_length == HEADER_LENGTH + archive_length + TAG_LENGTH &&
       second_length == first_length) != 0;
  const bool magic = (memcmp(first, "PMBENC", MAGIC_LENGTH) == 0 &&
                      first[VERSION_OFFSET] == PAMBLE_CRYPTO_VERSION) != 0;
  const bool fresh = (memcmp(first + SALT_OFFSET, second + SALT_OFFSET,
                             SALT_AND_NONCE_LENGTH) != 0 &&
                      memcmp(first + HEADER_LENGTH, second + HEADER_LENGTH,
                             archive_length) != 0) != 0;

  free(first);
  free(second);
  workspace_cleanup(&wks);

  cr_assert(sized && magic && fresh, "sized=%d magic=%d fresh=%d", sized, magic,
            fresh);
}

Test(pamble_crypto, rejects_bad_magic) {
  workspace wks;
  workspace_init(&wks);
  progress_log log;

  const crafted_file spec = {
      .magic = "NOTPMB",
      .version = PAMBLE_CRYPTO_VERSION,
      .claimed_length = CRAFTED_BODY_LENGTH,
      .actual_length = CRAFTED_BODY_LENGTH,
  };
  const pamble_status status = decrypt_crafted(&wks, &spec, &log);
  workspace_cleanup(&wks);

  cr_assert(status == PAMBLE_INVALID_ARCHIVE &&
                !log.seen[PAMBLE_STAGE_DERIVE_KEYS],
            "status=%d", status);
}

Test(pamble_crypto, rejects_bad_version) {
  workspace wks;
  workspace_init(&wks);
  progress_log log;

  const crafted_file spec = {
      .magic = "PMBENC",
      .version = BAD_VERSION,
      .claimed_length = CRAFTED_BODY_LENGTH,
      .actual_length = CRAFTED_BODY_LENGTH,
  };
  const pamble_status status = decrypt_crafted(&wks, &spec, &log);
  workspace_cleanup(&wks);

  cr_assert(status == PAMBLE_INVALID_ARCHIVE &&
                !log.seen[PAMBLE_STAGE_DERIVE_KEYS],
            "status=%d", status);
}

Test(pamble_crypto, rejects_truncated_body) {
  workspace wks;
  workspace_init(&wks);
  progress_log log;

  const crafted_file spec = {
      .magic = "PMBENC",
      .version = PAMBLE_CRYPTO_VERSION,
      .claimed_length = CLAIMED_BODY_LENGTH,
      .actual_length = CRAFTED_BODY_LENGTH,
  };
  const pamble_status status = decrypt_crafted(&wks, &spec, &log);
  workspace_cleanup(&wks);

  cr_assert(status == PAMBLE_INVALID_ARCHIVE &&
                !log.seen[PAMBLE_STAGE_DERIVE_KEYS],
            "status=%d", status);
}

Test(pamble_crypto, rejects_trailing_bytes) {
  workspace wks;
  workspace_init(&wks);
  progress_log log;

  const crafted_file spec = {
      .magic = "PMBENC",
      .version = PAMBLE_CRYPTO_VERSION,
      .claimed_length = CRAFTED_BODY_LENGTH,
      .actual_length = CRAFTED_BODY_LENGTH,
      .extra = 1,
  };
  const pamble_status status = decrypt_crafted(&wks, &spec, &log);
  workspace_cleanup(&wks);

  cr_assert(status == PAMBLE_INVALID_ARCHIVE &&
                !log.seen[PAMBLE_STAGE_DERIVE_KEYS],
            "status=%d", status);
}

Test(pamble_crypto, rejects_file_shorter_than_header) {
  workspace wks;
  workspace_init(&wks);
  make_file(&wks, "short.pmb", (const uint8_t *)"PMBENC", MAGIC_LENGTH);

  char paths[2][PATH_BUFFER_SIZE];
  const pamble_crypto_payload payload =
      make_payload(&wks, "short.pmb", "out1", paths);

  const pamble_status status = pamble_decrypt_archive(payload);
  workspace_cleanup(&wks);

  cr_assert_eq(status, PAMBLE_INVALID_ARCHIVE);
}

Test(pamble_crypto, decrypt_missing_file_is_io_error) {
  workspace wks;
  workspace_init(&wks);

  char paths[2][PATH_BUFFER_SIZE];
  const pamble_crypto_payload payload =
      make_payload(&wks, "missing.pmb", "out1", paths);

  const pamble_status status = pamble_decrypt_archive(payload);
  workspace_cleanup(&wks);

  cr_assert_eq(status, PAMBLE_IO_ERROR);
}

Test(pamble_crypto, encrypt_missing_input_fails_before_key_derivation) {
  workspace wks;
  workspace_init(&wks);
  progress_log log;

  char paths[2][PATH_BUFFER_SIZE];
  pamble_crypto_payload payload =
      make_payload(&wks, "missing", "secret.pmb", paths);
  payload.progress = logging_progress(&log);

  const pamble_status status = pamble_encrypt_archive(payload);
  const bool no_output = (path_missing(&wks, "secret.pmb") &&
                          path_missing(&wks, "secret.pmb.tmp")) != 0;
  workspace_cleanup(&wks);

  cr_assert(status == PAMBLE_IO_ERROR && no_output &&
                !log.seen[PAMBLE_STAGE_DERIVE_KEYS],
            "status=%d no_output=%d", status, no_output);
}

Test(pamble_crypto, null_paths_are_rejected) {
  const pamble_crypto_payload no_input = {
      .output_path = "out",
      .password = (const uint8_t *)"pw",
      .password_length = 2,
  };
  const pamble_crypto_payload no_output = {
      .input_path = "in",
      .password = (const uint8_t *)"pw",
      .password_length = 2,
  };

  const bool rejected =
      (pamble_encrypt_archive(no_input) == PAMBLE_INVALID_ARGUMENT &&
       pamble_encrypt_archive(no_output) == PAMBLE_INVALID_ARGUMENT &&
       pamble_decrypt_archive(no_input) == PAMBLE_INVALID_ARGUMENT &&
       pamble_decrypt_archive(no_output) == PAMBLE_INVALID_ARGUMENT) != 0;

  cr_assert(rejected, "a NULL path was accepted");
}

Test(pamble_crypto, null_password_with_length_is_rejected) {
  const pamble_crypto_payload payload = {
      .input_path = "in",
      .output_path = "out",
      .password_length = 1,
  };

  const bool rejected =
      (pamble_encrypt_archive(payload) == PAMBLE_INVALID_ARGUMENT &&
       pamble_decrypt_archive(payload) == PAMBLE_INVALID_ARGUMENT) != 0;

  cr_assert(rejected, "NULL password with non-zero length was accepted");
}
