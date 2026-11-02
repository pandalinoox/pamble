#include "pamble/pamble_archive.h"

#include <criterion/criterion.h>
#include <ftw.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEMP_TEMPLATE "/tmp/pamble_archive_XXXXXX"
#define TEMP_TEMPLATE_SIZE 32
#define PATH_BUFFER_SIZE 512
#define NFTW_OPEN_FDS 16
#define BITS_PER_BYTE 8

#define MAGIC_LENGTH 4
#define HEADER_LENGTH 5
#define ENTRY_FIXED_LENGTH 15
#define MODE_LENGTH 4
#define PATH_LENGTH_LENGTH 2
#define CONTENT_LENGTH_LENGTH 8
#define CRAFTED_ARCHIVE_SIZE 256

#define ENTRY_END 0
#define ENTRY_FILE 1
#define ENTRY_DIRECTORY 2
#define ENTRY_UNKNOWN 3

#define MODE_FILE 0644
#define MODE_DIR 0755
#define MODE_EXEC 0750
#define MODE_SETUID 04755
#define MODE_PERMISSION_MASK 0777

#define BINARY_CONTENT_LENGTH 300
#define BYTE_RANGE 256
#define BAD_VERSION 99

#define MISSING_PATH "/tmp/pamble_does_not_exist_42"

static const uint8_t MAGIC[MAGIC_LENGTH] = {'P', 'M', 'B', 'A'};

typedef struct {
  char input[TEMP_TEMPLATE_SIZE];
  char output[TEMP_TEMPLATE_SIZE];
} workspace;

typedef struct {
  uint8_t type;
  uint32_t mode;
  const char *path;
  const char *content;
} crafted_entry;

/*
 * Setup helpers. Each one aborts the test through a single assertion when
 * the environment cannot be prepared.
 */

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

static void make_temp_dir(char path[static TEMP_TEMPLATE_SIZE]) {
  strcpy(path, TEMP_TEMPLATE);
  must(mkdtemp(path) != NULL, "mkdtemp");
}

static void workspace_init(workspace *wks) {
  make_temp_dir(wks->input);
  make_temp_dir(wks->output);
}

static void workspace_cleanup(workspace *wks) {
  nftw(wks->input, remove_entry, NFTW_OPEN_FDS, FTW_DEPTH | FTW_PHYS);
  nftw(wks->output, remove_entry, NFTW_OPEN_FDS, FTW_DEPTH | FTW_PHYS);
}

static void join(char out[static PATH_BUFFER_SIZE], const char *base,
                 const char *name) {
  int written = snprintf(out, PATH_BUFFER_SIZE, "%s/%s", base, name);
  must((written > 0 && written < PATH_BUFFER_SIZE) != 0, "path too long");
}

static bool write_bytes(const char *path, const uint8_t *content,
                        size_t content_length) {
  FILE *file = fopen(path, "wb");

  if (file == NULL) {
    return false;
  }

  const bool written =
      (content_length == 0 ||
       fwrite(content, 1, content_length, file) == content_length) != 0;
  const bool closed = fclose(file) == 0;

  return (written && closed) != 0;
}

static void input_file(const workspace *wks, const char *relative,
                       const uint8_t *content, size_t content_length) {
  char path[PATH_BUFFER_SIZE];
  join(path, wks->input, relative);
  must(write_bytes(path, content, content_length), "write input file");
}

static void input_dir(const workspace *wks, const char *relative) {
  char path[PATH_BUFFER_SIZE];
  join(path, wks->input, relative);
  must(mkdir(path, MODE_DIR) == 0, "mkdir input dir");
}

static void pack_ok(const char *path, uint8_t **archive, size_t *length) {
  pamble_status status = pamble_archive_pack(path, archive, length);
  must((status == PAMBLE_OK && *archive != NULL) != 0, "pamble_archive_pack");
}

static void pack_input(const workspace *wks, const char *relative,
                       uint8_t **archive, size_t *length) {
  char path[PATH_BUFFER_SIZE];
  join(path, wks->input, relative);
  pack_ok(path, archive, length);
}

/*
 * Checks. These return a result instead of asserting, so each test makes a
 * single assertion over everything it verifies.
 */

static bool output_has_content(const workspace *wks, const char *relative,
                               const uint8_t *expected,
                               size_t expected_length) {
  char path[PATH_BUFFER_SIZE];
  join(path, wks->output, relative);

  FILE *file = fopen(path, "rb");

  if (file == NULL) {
    return false;
  }

  uint8_t actual[BINARY_CONTENT_LENGTH + 1];
  const size_t actual_length = fread(actual, 1, sizeof(actual), file);
  fclose(file);

  return (actual_length == expected_length &&
          (expected_length == 0 ||
           memcmp(actual, expected, expected_length) == 0)) != 0;
}

static bool output_is_dir(const workspace *wks, const char *relative) {
  char path[PATH_BUFFER_SIZE];
  join(path, wks->output, relative);

  struct stat info;
  return (lstat(path, &info) == 0 && S_ISDIR(info.st_mode)) != 0;
}

static bool output_is_missing(const workspace *wks, const char *relative) {
  char path[PATH_BUFFER_SIZE];
  join(path, wks->output, relative);

  struct stat info;
  return lstat(path, &info) != 0;
}

static bool output_has_mode(const workspace *wks, const char *relative,
                            mode_t mode) {
  char path[PATH_BUFFER_SIZE];
  join(path, wks->output, relative);

  struct stat info;
  return (stat(path, &info) == 0 &&
          (info.st_mode & MODE_PERMISSION_MASK) == mode) != 0;
}

/*
 * Archive crafting. Fields are written as raw bytes: the format is
 * length-prefixed, so no NUL terminator is ever stored.
 */

static size_t put_bytes(uint8_t *out, const uint8_t *bytes, size_t length) {
  if (length != 0) {
    memcpy(out, bytes, length);
  }
  return length;
}

static size_t put_be(uint8_t *out, uint64_t value, size_t width) {
  for (size_t i = 0; i < width; i++) {
    out[i] = (uint8_t)(value >> ((width - i - 1) * BITS_PER_BYTE));
  }
  return width;
}

static size_t put_header(uint8_t *out, uint8_t version) {
  size_t offset = put_bytes(out, MAGIC, MAGIC_LENGTH);
  out[offset++] = version;
  return offset;
}

static size_t put_entry(uint8_t *out, const crafted_entry *entry) {
  const size_t path_length = strlen(entry->path);
  const size_t content_length = strlen(entry->content);
  size_t offset = 0;

  out[offset++] = entry->type;
  offset += put_be(out + offset, entry->mode, MODE_LENGTH);
  offset += put_be(out + offset, path_length, PATH_LENGTH_LENGTH);
  offset += put_be(out + offset, content_length, CONTENT_LENGTH_LENGTH);
  offset += put_bytes(out + offset, (const uint8_t *)entry->path, path_length);
  offset +=
      put_bytes(out + offset, (const uint8_t *)entry->content, content_length);

  return offset;
}

static size_t put_end(uint8_t *out) {
  out[0] = ENTRY_END;
  return 1;
}

static size_t craft_single_entry(uint8_t *out, const crafted_entry *entry) {
  size_t offset = put_header(out, PAMBLE_ARCHIVE_VERSION);
  offset += put_entry(out + offset, entry);
  offset += put_end(out + offset);
  return offset;
}

static bool unpack_returns(const uint8_t *archive, size_t length,
                           const workspace *wks, pamble_status expected) {
  return pamble_archive_unpack(archive, length, wks->output) == expected;
}

/*
 * Round trips.
 */

Test(pamble_archive, single_file_round_trip) {
  workspace wks;
  workspace_init(&wks);

  static const uint8_t content[] = "hello pamble";
  input_file(&wks, "note.txt", content, sizeof(content) - 1);

  uint8_t *archive;
  size_t archive_length;
  pack_input(&wks, "note.txt", &archive, &archive_length);

  const bool round_tripped =
      (unpack_returns(archive, archive_length, &wks, PAMBLE_OK) &&
       output_has_content(&wks, "note.txt", content, sizeof(content) - 1)) != 0;

  pamble_free_archive(archive);
  workspace_cleanup(&wks);

  cr_assert(round_tripped, "single file did not round-trip");
}

Test(pamble_archive, directory_tree_round_trip) {
  workspace wks;
  workspace_init(&wks);

  uint8_t binary[BINARY_CONTENT_LENGTH];
  for (size_t i = 0; i < sizeof(binary); i++) {
    binary[i] = (uint8_t)(i % BYTE_RANGE);
  }
  static const uint8_t readme[] = "top level";
  static const uint8_t deep[] = "deep file";

  input_dir(&wks, "project");
  input_file(&wks, "project/README", readme, sizeof(readme) - 1);
  input_file(&wks, "project/empty.bin", NULL, 0);
  input_file(&wks, "project/data.bin", binary, sizeof(binary));
  input_dir(&wks, "project/empty_dir");
  input_dir(&wks, "project/a");
  input_dir(&wks, "project/a/b");
  input_file(&wks, "project/a/b/deep.txt", deep, sizeof(deep) - 1);

  uint8_t *archive;
  size_t archive_length;
  pack_input(&wks, "project", &archive, &archive_length);

  const bool round_tripped =
      (unpack_returns(archive, archive_length, &wks, PAMBLE_OK) &&
       output_is_dir(&wks, "project") &&
       output_has_content(&wks, "project/README", readme, sizeof(readme) - 1) &&
       output_has_content(&wks, "project/empty.bin", NULL, 0) &&
       output_has_content(&wks, "project/data.bin", binary, sizeof(binary)) &&
       output_is_dir(&wks, "project/empty_dir") &&
       output_is_dir(&wks, "project/a/b") &&
       output_has_content(&wks, "project/a/b/deep.txt", deep,
                          sizeof(deep) - 1)) != 0;

  pamble_free_archive(archive);
  workspace_cleanup(&wks);

  cr_assert(round_tripped, "directory tree did not round-trip");
}

Test(pamble_archive, trailing_slash_uses_basename) {
  workspace wks;
  workspace_init(&wks);

  input_dir(&wks, "dir");

  uint8_t *archive;
  size_t archive_length;
  pack_input(&wks, "dir/", &archive, &archive_length);

  const bool extracted =
      (unpack_returns(archive, archive_length, &wks, PAMBLE_OK) &&
       output_is_dir(&wks, "dir")) != 0;

  pamble_free_archive(archive);
  workspace_cleanup(&wks);

  cr_assert(extracted, "trailing slash did not resolve to basename");
}

Test(pamble_archive, exact_layout_for_single_file) {
  workspace wks;
  workspace_init(&wks);

  static const uint8_t content[] = "ab";
  char file_path[PATH_BUFFER_SIZE];
  join(file_path, wks.input, "f");
  input_file(&wks, "f", content, sizeof(content) - 1);
  must(chmod(file_path, MODE_FILE) == 0, "chmod");

  uint8_t *archive;
  size_t archive_length;
  pack_ok(file_path, &archive, &archive_length);

  uint8_t expected[CRAFTED_ARCHIVE_SIZE];
  const size_t expected_length =
      craft_single_entry(expected, &(crafted_entry){
                                       .type = ENTRY_FILE,
                                       .mode = MODE_FILE,
                                       .path = "f",
                                       .content = "ab",
                                   });

  const bool matches = (archive_length == expected_length &&
                        memcmp(archive, expected, expected_length) == 0) != 0;

  pamble_free_archive(archive);
  workspace_cleanup(&wks);

  cr_assert(matches, "archive bytes do not match the documented layout");
}

Test(pamble_archive, packing_is_deterministic) {
  workspace wks;
  workspace_init(&wks);

  static const char *names[] = {
      "tree/zeta",
      "tree/alpha",
      "tree/mid",
      "tree/beta",
  };

  input_dir(&wks, "tree");
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    input_file(&wks, names[i], (const uint8_t *)names[i], strlen(names[i]));
  }

  uint8_t *first;
  uint8_t *second;
  size_t first_length;
  size_t second_length;
  pack_input(&wks, "tree", &first, &first_length);
  pack_input(&wks, "tree", &second, &second_length);

  const bool identical = (first_length == second_length &&
                          memcmp(first, second, first_length) == 0) != 0;

  pamble_free_archive(first);
  pamble_free_archive(second);
  workspace_cleanup(&wks);

  cr_assert(identical, "packing the same tree twice gave different bytes");
}

Test(pamble_archive, preserves_file_mode) {
  workspace wks;
  workspace_init(&wks);

  static const uint8_t script[] = "#!/bin/sh\n";
  char file_path[PATH_BUFFER_SIZE];
  join(file_path, wks.input, "run.sh");
  input_file(&wks, "run.sh", script, sizeof(script) - 1);
  must(chmod(file_path, MODE_EXEC) == 0, "chmod");

  uint8_t *archive;
  size_t archive_length;
  pack_ok(file_path, &archive, &archive_length);

  const bool preserved =
      (unpack_returns(archive, archive_length, &wks, PAMBLE_OK) &&
       output_has_mode(&wks, "run.sh", MODE_EXEC)) != 0;

  pamble_free_archive(archive);
  workspace_cleanup(&wks);

  cr_assert(preserved, "file mode was not preserved");
}

Test(pamble_archive, skips_symlinks) {
  workspace wks;
  workspace_init(&wks);

  static const uint8_t content[] = "x";
  char link_path[PATH_BUFFER_SIZE];
  join(link_path, wks.input, "links/link.txt");

  input_dir(&wks, "links");
  input_file(&wks, "links/real.txt", content, sizeof(content) - 1);
  must(symlink("real.txt", link_path) == 0, "symlink");

  uint8_t *archive;
  size_t archive_length;
  pack_input(&wks, "links", &archive, &archive_length);

  const bool skipped =
      (unpack_returns(archive, archive_length, &wks, PAMBLE_OK) &&
       output_has_content(&wks, "links/real.txt", content,
                          sizeof(content) - 1) &&
       output_is_missing(&wks, "links/link.txt")) != 0;

  pamble_free_archive(archive);
  workspace_cleanup(&wks);

  cr_assert(skipped, "symlink inside directory was not skipped");
}

/*
 * Packing errors.
 */

Test(pamble_archive, pack_null_arguments) {
  uint8_t *archive;
  size_t archive_length;

  const bool rejected = (pamble_archive_pack(NULL, &archive, &archive_length) ==
                             PAMBLE_INVALID_ARGUMENT &&
                         pamble_archive_pack("/tmp", NULL, &archive_length) ==
                             PAMBLE_INVALID_ARGUMENT &&
                         pamble_archive_pack("/tmp", &archive, NULL) ==
                             PAMBLE_INVALID_ARGUMENT) != 0;

  cr_assert(rejected, "NULL argument was accepted");
}

Test(pamble_archive, pack_rejects_unnamed_roots) {
  static const char *roots[] = {"/", ".", "..", ""};

  bool rejected = true;

  for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
    uint8_t *archive;
    size_t archive_length;

    rejected = ((rejected &&
                 pamble_archive_pack(roots[i], &archive, &archive_length) ==
                     PAMBLE_INVALID_ARGUMENT &&
                 archive == NULL) != 0);
  }

  cr_assert(rejected, "root without a usable basename was accepted");
}

Test(pamble_archive, pack_missing_path) {
  uint8_t *archive;
  size_t archive_length;

  const bool rejected =
      (pamble_archive_pack(MISSING_PATH, &archive, &archive_length) ==
           PAMBLE_IO_ERROR &&
       archive == NULL) != 0;

  cr_assert(rejected, "missing input path was not reported as IO error");
}

Test(pamble_archive, pack_rejects_symlink_root) {
  workspace wks;
  workspace_init(&wks);

  char link_path[PATH_BUFFER_SIZE];
  join(link_path, wks.input, "root_link");
  must(symlink(wks.output, link_path) == 0, "symlink");

  uint8_t *archive;
  size_t archive_length;
  const pamble_status status =
      pamble_archive_pack(link_path, &archive, &archive_length);

  workspace_cleanup(&wks);

  cr_assert_eq(status, PAMBLE_INVALID_ARGUMENT);
}

/*
 * Unpacking errors.
 */

Test(pamble_archive, unpack_invalid_arguments) {
  workspace wks;
  workspace_init(&wks);

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  const size_t length = craft_single_entry(archive, &(crafted_entry){
                                                        .type = ENTRY_DIRECTORY,
                                                        .mode = MODE_DIR,
                                                        .path = "d",
                                                        .content = "",
                                                    });

  char file_path[PATH_BUFFER_SIZE];
  join(file_path, wks.input, "plain");
  input_file(&wks, "plain", NULL, 0);

  const bool rejected =
      (pamble_archive_unpack(NULL, 1, wks.output) == PAMBLE_INVALID_ARGUMENT &&
       pamble_archive_unpack(archive, length, NULL) ==
           PAMBLE_INVALID_ARGUMENT &&
       pamble_archive_unpack(archive, length, file_path) ==
           PAMBLE_INVALID_ARGUMENT &&
       pamble_archive_unpack(archive, length, MISSING_PATH) ==
           PAMBLE_INVALID_ARGUMENT) != 0;

  workspace_cleanup(&wks);

  cr_assert(rejected, "invalid unpack argument was accepted");
}

Test(pamble_archive, unpack_empty_archive) {
  workspace wks;
  workspace_init(&wks);

  const bool rejected = unpack_returns(NULL, 0, &wks, PAMBLE_INVALID_ARCHIVE);

  workspace_cleanup(&wks);

  cr_assert(rejected, "empty archive was accepted");
}

Test(pamble_archive, unpack_header_only_archive) {
  workspace wks;
  workspace_init(&wks);

  uint8_t archive[HEADER_LENGTH + 1];
  size_t length = put_header(archive, PAMBLE_ARCHIVE_VERSION);
  length += put_end(archive + length);

  const bool accepted = unpack_returns(archive, length, &wks, PAMBLE_OK);

  workspace_cleanup(&wks);

  cr_assert(accepted, "header-only archive was rejected");
}

Test(pamble_archive, unpack_bad_magic) {
  workspace wks;
  workspace_init(&wks);

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  const size_t length = craft_single_entry(archive, &(crafted_entry){
                                                        .type = ENTRY_DIRECTORY,
                                                        .mode = MODE_DIR,
                                                        .path = "d",
                                                        .content = "",
                                                    });
  archive[0] = 'X';

  const bool rejected =
      unpack_returns(archive, length, &wks, PAMBLE_INVALID_ARCHIVE);

  workspace_cleanup(&wks);

  cr_assert(rejected, "bad magic was accepted");
}

Test(pamble_archive, unpack_bad_version) {
  workspace wks;
  workspace_init(&wks);

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  const size_t length = craft_single_entry(archive, &(crafted_entry){
                                                        .type = ENTRY_DIRECTORY,
                                                        .mode = MODE_DIR,
                                                        .path = "d",
                                                        .content = "",
                                                    });
  archive[MAGIC_LENGTH] = BAD_VERSION;

  const bool rejected =
      unpack_returns(archive, length, &wks, PAMBLE_INVALID_ARCHIVE);

  workspace_cleanup(&wks);

  cr_assert(rejected, "bad version was accepted");
}

Test(pamble_archive, unpack_every_truncation) {
  workspace wks;
  workspace_init(&wks);

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  const size_t length = craft_single_entry(archive, &(crafted_entry){
                                                        .type = ENTRY_FILE,
                                                        .mode = MODE_FILE,
                                                        .path = "dir_name",
                                                        .content = "content",
                                                    });

  size_t accepted_at = length;

  for (size_t cut = 0; cut < length && accepted_at == length; cut++) {
    if (!unpack_returns(archive, cut, &wks, PAMBLE_INVALID_ARCHIVE)) {
      accepted_at = cut;
    }
  }

  const bool untouched = output_is_missing(&wks, "dir_name");

  workspace_cleanup(&wks);

  cr_assert(accepted_at == length && untouched,
            "truncation at %zu accepted or output written", accepted_at);
}

Test(pamble_archive, unpack_trailing_bytes) {
  workspace wks;
  workspace_init(&wks);

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  size_t length = craft_single_entry(archive, &(crafted_entry){
                                                  .type = ENTRY_DIRECTORY,
                                                  .mode = MODE_DIR,
                                                  .path = "d",
                                                  .content = "",
                                              });
  archive[length++] = 0;

  const bool rejected =
      unpack_returns(archive, length, &wks, PAMBLE_INVALID_ARCHIVE);

  workspace_cleanup(&wks);

  cr_assert(rejected, "trailing bytes were accepted");
}

Test(pamble_archive, unpack_unknown_entry_type) {
  workspace wks;
  workspace_init(&wks);

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  const size_t length = craft_single_entry(archive, &(crafted_entry){
                                                        .type = ENTRY_UNKNOWN,
                                                        .mode = MODE_FILE,
                                                        .path = "u",
                                                        .content = "",
                                                    });

  const bool rejected =
      unpack_returns(archive, length, &wks, PAMBLE_INVALID_ARCHIVE);

  workspace_cleanup(&wks);

  cr_assert(rejected, "unknown entry type was accepted");
}

Test(pamble_archive, unpack_directory_with_content) {
  workspace wks;
  workspace_init(&wks);

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  const size_t length = craft_single_entry(archive, &(crafted_entry){
                                                        .type = ENTRY_DIRECTORY,
                                                        .mode = MODE_DIR,
                                                        .path = "d",
                                                        .content = "oops",
                                                    });

  const bool rejected =
      unpack_returns(archive, length, &wks, PAMBLE_INVALID_ARCHIVE);

  workspace_cleanup(&wks);

  cr_assert(rejected, "directory with content was accepted");
}

Test(pamble_archive, unpack_rejects_special_mode_bits) {
  workspace wks;
  workspace_init(&wks);

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  const size_t length = craft_single_entry(archive, &(crafted_entry){
                                                        .type = ENTRY_FILE,
                                                        .mode = MODE_SETUID,
                                                        .path = "f",
                                                        .content = "x",
                                                    });

  const bool rejected =
      unpack_returns(archive, length, &wks, PAMBLE_INVALID_ARCHIVE);

  workspace_cleanup(&wks);

  cr_assert(rejected, "setuid mode bit was accepted");
}

Test(pamble_archive, unpack_rejects_unsafe_paths) {
  workspace wks;
  workspace_init(&wks);

  static const char *unsafe[] = {
      "",  "/abs", "..",   "../evil", "a/..",  "a/../b",
      ".", "./a",  "a//b", "a/",      "a/./b",
  };
  static const size_t unsafe_count = sizeof(unsafe) / sizeof(unsafe[0]);

  size_t accepted_at = unsafe_count;

  for (size_t i = 0; i < unsafe_count && accepted_at == unsafe_count; i++) {
    uint8_t archive[CRAFTED_ARCHIVE_SIZE];
    const size_t length = craft_single_entry(archive, &(crafted_entry){
                                                          .type = ENTRY_FILE,
                                                          .mode = MODE_FILE,
                                                          .path = unsafe[i],
                                                          .content = "x",
                                                      });

    if (!unpack_returns(archive, length, &wks, PAMBLE_INVALID_ARCHIVE)) {
      accepted_at = i;
    }
  }

  workspace_cleanup(&wks);

  cr_assert(accepted_at == unsafe_count, "unsafe path \"%s\" accepted",
            accepted_at < unsafe_count ? unsafe[accepted_at] : "");
}

Test(pamble_archive, unpack_rejects_nul_in_path) {
  workspace wks;
  workspace_init(&wks);

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  const size_t length = craft_single_entry(archive, &(crafted_entry){
                                                        .type = ENTRY_FILE,
                                                        .mode = MODE_FILE,
                                                        .path = "ab",
                                                        .content = "",
                                                    });
  archive[HEADER_LENGTH + ENTRY_FIXED_LENGTH] = '\0';

  const bool rejected =
      unpack_returns(archive, length, &wks, PAMBLE_INVALID_ARCHIVE);

  workspace_cleanup(&wks);

  cr_assert(rejected, "NUL byte in path was accepted");
}

Test(pamble_archive, unpack_validates_before_writing) {
  workspace wks;
  workspace_init(&wks);

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  size_t length = put_header(archive, PAMBLE_ARCHIVE_VERSION);
  length += put_entry(archive + length, &(crafted_entry){
                                            .type = ENTRY_DIRECTORY,
                                            .mode = MODE_DIR,
                                            .path = "good",
                                            .content = "",
                                        });
  length += put_entry(archive + length, &(crafted_entry){
                                            .type = ENTRY_FILE,
                                            .mode = MODE_FILE,
                                            .path = "../bad",
                                            .content = "x",
                                        });
  length += put_end(archive + length);

  const bool untouched =
      (unpack_returns(archive, length, &wks, PAMBLE_INVALID_ARCHIVE) &&
       output_is_missing(&wks, "good")) != 0;

  workspace_cleanup(&wks);

  cr_assert(untouched, "invalid archive was partially extracted");
}

Test(pamble_archive, unpack_refuses_to_overwrite) {
  workspace wks;
  workspace_init(&wks);

  static const uint8_t original[] = "original";
  char path[PATH_BUFFER_SIZE];
  join(path, wks.output, "f");
  must(write_bytes(path, original, sizeof(original) - 1), "write output file");

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  const size_t length = craft_single_entry(archive, &(crafted_entry){
                                                        .type = ENTRY_FILE,
                                                        .mode = MODE_FILE,
                                                        .path = "f",
                                                        .content = "replaced",
                                                    });

  const bool kept =
      (unpack_returns(archive, length, &wks, PAMBLE_IO_ERROR) &&
       output_has_content(&wks, "f", original, sizeof(original) - 1)) != 0;

  workspace_cleanup(&wks);

  cr_assert(kept, "existing file was overwritten");
}

Test(pamble_archive, unpack_into_existing_directory) {
  workspace wks;
  workspace_init(&wks);

  char path[PATH_BUFFER_SIZE];
  join(path, wks.output, "d");
  must(mkdir(path, MODE_DIR) == 0, "mkdir output dir");

  uint8_t archive[CRAFTED_ARCHIVE_SIZE];
  size_t length = put_header(archive, PAMBLE_ARCHIVE_VERSION);
  length += put_entry(archive + length, &(crafted_entry){
                                            .type = ENTRY_DIRECTORY,
                                            .mode = MODE_DIR,
                                            .path = "d",
                                            .content = "",
                                        });
  length += put_entry(archive + length, &(crafted_entry){
                                            .type = ENTRY_FILE,
                                            .mode = MODE_FILE,
                                            .path = "d/f",
                                            .content = "x",
                                        });
  length += put_end(archive + length);

  const bool extracted =
      (unpack_returns(archive, length, &wks, PAMBLE_OK) &&
       output_has_content(&wks, "d/f", (const uint8_t *)"x", 1)) != 0;

  workspace_cleanup(&wks);

  cr_assert(extracted, "could not extract into an existing directory");
}

Test(pamble_archive, free_null_is_noop) { pamble_free_archive(NULL); }
