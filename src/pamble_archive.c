#include "pamble/pamble_archive.h"

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define BITS_PER_BYTE 8

#define MAGIC_LENGTH 4
#define VERSION_LENGTH 1

#define TYPE_LENGTH 1
#define MODE_LENGTH (sizeof(uint32_t))
#define PATH_LENGTH_LENGTH (sizeof(uint16_t))
#define CONTENT_LENGTH_LENGTH (sizeof(uint64_t))
#define ENTRY_FIELDS_LENGTH                                                    \
  (MODE_LENGTH + PATH_LENGTH_LENGTH + CONTENT_LENGTH_LENGTH)

#define MODE_OFFSET 0
#define PATH_LENGTH_OFFSET (MODE_OFFSET + MODE_LENGTH)
#define CONTENT_LENGTH_OFFSET (PATH_LENGTH_OFFSET + PATH_LENGTH_LENGTH)

#define MAX_ARCHIVE_PATH_LENGTH UINT16_MAX

#define MODE_MASK 0777
#define DIRECTORY_CREATE_MODE 0700

#define INITIAL_CAPACITY 4096
#define GROWTH_FACTOR 2

#define PATH_SEPARATOR '/'
#define PATH_SEPARATOR_LENGTH 1
#define NUL_TERMINATOR_LENGTH 1

enum { ENTRY_END = 0, ENTRY_FILE, ENTRY_DIRECTORY };

static const uint8_t MAGIC[MAGIC_LENGTH] = {'P', 'M', 'B', 'A'};

typedef struct {
  uint8_t *data;
  size_t length;
  size_t capacity;
} byte_buffer;

typedef struct {
  const uint8_t *data;
  size_t length;
  size_t offset;
} byte_reader;

typedef struct {
  uint8_t type;
  uint32_t mode;
  const uint8_t *path;
  size_t path_length;
  const uint8_t *content;
  size_t content_length;
} archive_entry;

typedef struct {
  const char *fs_path;
  const char *archive_path;
} entry_location;

static pamble_status pack_entry(byte_buffer *buffer,
                                const entry_location *location);

/*
 * @brief Encodes an unsigned integer as a big-endian byte sequence.
 *
 * @param value Value to encode.
 * @param width Number of bytes to write.
 * @param output_buffer Output buffer for the encoded value.
 */
static void encode_be(uint64_t value, size_t width,
                      uint8_t output_buffer[static width]) {

  for (size_t i = 0; i < width; i++) {
    output_buffer[i] = (uint8_t)(value >> ((width - i - 1) * BITS_PER_BYTE));
  }
}

/*
 * @brief Decodes a big-endian byte sequence into an unsigned integer.
 *
 * @param input_buffer Bytes holding the big-endian value.
 * @param width Number of bytes to read.
 *
 * @return The decoded value.
 */
static uint64_t decode_be(const uint8_t input_buffer[static 1], size_t width) {

  uint64_t value = 0;

  for (size_t i = 0; i < width; i++) {
    value = (value << BITS_PER_BYTE) | input_buffer[i];
  }

  return value;
}

/*
 * @brief Ensures a byte buffer has room for additional bytes.
 *
 * Grows the buffer geometrically, starting at INITIAL_CAPACITY.
 *
 * @param buffer Byte buffer to grow.
 * @param additional Number of bytes that must fit after the current length.
 *
 * @return PAMBLE_OK if the buffer has enough room.
 * @return PAMBLE_SIZE_OVERFLOW if the required size overflows or allocation
 *         fails.
 */
static pamble_status buffer_reserve(byte_buffer *buffer, size_t additional) {

  if (additional > SIZE_MAX - buffer->length) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  const size_t required = buffer->length + additional;

  if (required <= buffer->capacity) {
    return PAMBLE_OK;
  }

  size_t capacity = buffer->capacity == 0 ? INITIAL_CAPACITY : buffer->capacity;

  while (capacity < required) {
    if (capacity > SIZE_MAX / GROWTH_FACTOR) {
      capacity = required;
      break;
    }
    capacity *= GROWTH_FACTOR;
  }

  uint8_t *data = realloc(buffer->data, capacity);

  if (data == NULL) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  buffer->data = data;
  buffer->capacity = capacity;

  return PAMBLE_OK;
}

/*
 * @brief Appends bytes to the end of a byte buffer.
 *
 * @param buffer Byte buffer to append to.
 * @param bytes Bytes to append. May be NULL when bytes_length is zero.
 * @param bytes_length Number of bytes to append.
 *
 * @return PAMBLE_OK on success, otherwise an error from buffer_reserve.
 */
static pamble_status buffer_append(byte_buffer *buffer, const uint8_t *bytes,
                                   size_t bytes_length) {

  pamble_status status = buffer_reserve(buffer, bytes_length);
  PAMBLE_RETURN_IF_ERROR(status);

  if (bytes_length != 0) {
    memcpy(buffer->data + buffer->length, bytes, bytes_length);
    buffer->length += bytes_length;
  }

  return PAMBLE_OK;
}

/*
 * @brief Appends an entry header and its path to the archive buffer.
 *
 * Writes type || mode || path_length || content_length || path. The entry's
 * content, if any, is appended separately by the caller.
 *
 * @param buffer Archive buffer to append to.
 * @param entry Entry whose type, mode, path, and content_length are written.
 *              The content field is ignored.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_SIZE_OVERFLOW if the path is longer than
 *         MAX_ARCHIVE_PATH_LENGTH, or an error from buffer_append.
 */
static pamble_status append_entry_header(byte_buffer *buffer,
                                         const archive_entry *entry) {

  if (entry->path_length > MAX_ARCHIVE_PATH_LENGTH) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  pamble_status status;

  uint8_t fields[ENTRY_FIELDS_LENGTH];

  encode_be(entry->mode, MODE_LENGTH, &fields[MODE_OFFSET]);
  encode_be(entry->path_length, PATH_LENGTH_LENGTH,
            &fields[PATH_LENGTH_OFFSET]);
  encode_be(entry->content_length, CONTENT_LENGTH_LENGTH,
            &fields[CONTENT_LENGTH_OFFSET]);

  status = buffer_append(buffer, &entry->type, TYPE_LENGTH);
  PAMBLE_RETURN_IF_ERROR(status);

  status = buffer_append(buffer, fields, ENTRY_FIELDS_LENGTH);
  PAMBLE_RETURN_IF_ERROR(status);

  status = buffer_append(buffer, entry->path, entry->path_length);
  PAMBLE_RETURN_IF_ERROR(status);

  return PAMBLE_OK;
}

/*
 * @brief Builds the header fields of an entry being packed.
 *
 * @param type Entry type (ENTRY_FILE or ENTRY_DIRECTORY).
 * @param location Location of the entry; only archive_path is used.
 * @param info lstat result for the entry, supplying its permission bits.
 * @param content_length Number of content bytes that will follow.
 *
 * @return The entry, with no content pointer set.
 */
static archive_entry make_entry(uint8_t type, const entry_location *location,
                                const struct stat *info,
                                size_t content_length) {

  const archive_entry entry = {
      .type = type,
      .mode = (uint32_t)(info->st_mode & MODE_MASK),
      .path = (const uint8_t *)location->archive_path,
      .path_length = strlen(location->archive_path),
      .content = NULL,
      .content_length = content_length,
  };

  return entry;
}

/*
 * @brief Joins a base path and a name with a path separator.
 *
 * @param base Base path.
 * @param name Name to append. Need not be NUL-terminated.
 * @param name_length Number of bytes in name.
 *
 * @return A newly allocated "base/name" string, or NULL if allocation fails.
 *         Caller must free it.
 */
static char *join_path(const char *base, const char *name, size_t name_length) {

  const size_t base_length = strlen(base);

  char *joined = malloc(base_length + PATH_SEPARATOR_LENGTH + name_length +
                        NUL_TERMINATOR_LENGTH);

  if (joined == NULL) {
    return NULL;
  }

  memcpy(joined, base, base_length);
  joined[base_length] = PATH_SEPARATOR;
  memcpy(joined + base_length + PATH_SEPARATOR_LENGTH, name, name_length);
  joined[base_length + PATH_SEPARATOR_LENGTH + name_length] = '\0';

  return joined;
}

/*
 * @brief Derives the root archive name from an input path.
 *
 * Strips trailing separators and takes the final path component, so both
 * "a/b" and "a/b/" yield "b".
 *
 * @param input_path Path supplied to pamble_archive_pack.
 * @param name Output parameter; on success, set to a newly allocated
 *             NUL-terminated name. Caller must free it.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_INVALID_ARGUMENT if the final component is empty, "." or
 *         "..".
 * @return PAMBLE_SIZE_OVERFLOW if allocation fails.
 */
static pamble_status root_name(const char *input_path, char **name) {

  size_t end = strlen(input_path);

  while (end > 0 && input_path[end - 1] == PATH_SEPARATOR) {
    end--;
  }

  size_t start = end;

  while (start > 0 && input_path[start - 1] != PATH_SEPARATOR) {
    start--;
  }

  const size_t name_length = end - start;
  const char *component = input_path + start;

  if (name_length == 0 || (name_length == 1 && component[0] == '.') ||
      (name_length == 2 && component[0] == '.' && component[1] == '.')) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  *name = malloc(name_length + NUL_TERMINATOR_LENGTH);

  if (*name == NULL) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  memcpy(*name, component, name_length);
  (*name)[name_length] = '\0';

  return PAMBLE_OK;
}

/*
 * @brief Reads exactly content_length bytes of a file into the buffer.
 *
 * @param buffer Archive buffer to append the file content to.
 * @param fs_path Filesystem path of the file.
 * @param content_length Number of bytes to read.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_IO_ERROR if the file cannot be opened or fewer than
 *         content_length bytes could be read.
 * @return PAMBLE_SIZE_OVERFLOW if the buffer cannot grow.
 */
static pamble_status append_file_content(byte_buffer *buffer,
                                         const char *fs_path,
                                         size_t content_length) {

  FILE *file = fopen(fs_path, "rb");

  if (file == NULL) {
    return PAMBLE_IO_ERROR;
  }

  pamble_status status = buffer_reserve(buffer, content_length);

  if (status == PAMBLE_OK && content_length != 0) {
    const size_t bytes_read =
        fread(buffer->data + buffer->length, 1, content_length, file);

    if (bytes_read == content_length) {
      buffer->length += content_length;
    } else {
      status = PAMBLE_IO_ERROR;
    }
  }

  fclose(file);

  return status;
}

/*
 * @brief Appends a regular file entry and its content to the archive.
 *
 * @param buffer Archive buffer to append to.
 * @param location Filesystem and archive paths of the file.
 * @param info lstat result for the file.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_SIZE_OVERFLOW if the file size does not fit in size_t, or
 *         an error from append_entry_header or append_file_content.
 */
static pamble_status pack_file(byte_buffer *buffer,
                               const entry_location *location,
                               const struct stat *info) {

  if (info->st_size < 0 || (uintmax_t)info->st_size > SIZE_MAX) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  const size_t content_length = (size_t)info->st_size;

  pamble_status status;

  const archive_entry entry =
      make_entry(ENTRY_FILE, location, info, content_length);

  status = append_entry_header(buffer, &entry);
  PAMBLE_RETURN_IF_ERROR(status);

  status = append_file_content(buffer, location->fs_path, content_length);
  PAMBLE_RETURN_IF_ERROR(status);

  return PAMBLE_OK;
}

/*
 * @brief scandir filter that drops the "." and ".." entries.
 *
 * @param entry Directory entry to test.
 *
 * @return Non-zero if the entry should be kept.
 */
static int skip_dot_entries(const struct dirent *entry) {
  return strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0;
}

/*
 * @brief Appends a directory entry, then every child entry, to the archive.
 *
 * Children are visited in alphasort order so the archive is deterministic.
 *
 * @param buffer Archive buffer to append to.
 * @param location Filesystem and archive paths of the directory.
 * @param info lstat result for the directory.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_IO_ERROR if the directory cannot be listed.
 * @return PAMBLE_SIZE_OVERFLOW if allocation fails, or any error propagated
 *         from packing a child entry.
 */
static pamble_status pack_directory(byte_buffer *buffer,
                                    const entry_location *location,
                                    const struct stat *info) {

  const archive_entry entry = make_entry(ENTRY_DIRECTORY, location, info, 0);

  pamble_status status = append_entry_header(buffer, &entry);
  PAMBLE_RETURN_IF_ERROR(status);

  struct dirent **children = NULL;

  const int child_count =
      scandir(location->fs_path, &children, skip_dot_entries, alphasort);

  if (child_count < 0) {
    return PAMBLE_IO_ERROR;
  }

  for (int i = 0; i < child_count; i++) {
    const char *child_name = children[i]->d_name;
    const size_t child_name_length = strlen(child_name);

    if (status == PAMBLE_OK) {
      char *child_fs_path =
          join_path(location->fs_path, child_name, child_name_length);
      char *child_archive_path =
          join_path(location->archive_path, child_name, child_name_length);

      if (child_fs_path == NULL || child_archive_path == NULL) {
        status = PAMBLE_SIZE_OVERFLOW;
      } else {
        const entry_location child = {
            .fs_path = child_fs_path,
            .archive_path = child_archive_path,
        };

        status = pack_entry(buffer, &child);
      }

      free(child_fs_path);
      free(child_archive_path);
    }

    free(children[i]);
  }

  free((void *)children);

  return status;
}

/*
 * @brief Appends a filesystem entry to the archive.
 *
 * Regular files and directories are archived; anything else (symbolic
 * links, devices, sockets, FIFOs) is skipped.
 *
 * @param buffer Archive buffer to append to.
 * @param location Filesystem and archive paths of the entry.
 *
 * @return PAMBLE_OK on success or if the entry was skipped.
 * @return PAMBLE_IO_ERROR if the entry cannot be inspected, or any error
 *         from pack_file or pack_directory.
 */
static pamble_status pack_entry(byte_buffer *buffer,
                                const entry_location *location) {

  struct stat info;

  if (lstat(location->fs_path, &info) != 0) {
    return PAMBLE_IO_ERROR;
  }

  if (S_ISDIR(info.st_mode)) {
    return pack_directory(buffer, location, &info);
  }

  if (S_ISREG(info.st_mode)) {
    return pack_file(buffer, location, &info);
  }

  return PAMBLE_OK;
}

/*
 * @brief Writes the complete archive for input_path into buffer.
 *
 * @param buffer Empty archive buffer to fill.
 * @param input_path Path of the file or directory to pack.
 * @param name Root name of the archive.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_IO_ERROR if input_path cannot be inspected.
 * @return PAMBLE_INVALID_ARGUMENT if input_path is neither a regular file
 *         nor a directory, or any error from pack_entry.
 */
static pamble_status build_archive(byte_buffer *buffer, const char *input_path,
                                   const char *name) {

  struct stat info;

  if (lstat(input_path, &info) != 0) {
    return PAMBLE_IO_ERROR;
  }

  if (!S_ISDIR(info.st_mode) && !S_ISREG(info.st_mode)) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  pamble_status status;

  const uint8_t version = PAMBLE_ARCHIVE_VERSION;
  const uint8_t end_marker = ENTRY_END;

  status = buffer_append(buffer, MAGIC, MAGIC_LENGTH);
  PAMBLE_RETURN_IF_ERROR(status);

  status = buffer_append(buffer, &version, VERSION_LENGTH);
  PAMBLE_RETURN_IF_ERROR(status);

  const entry_location root = {.fs_path = input_path, .archive_path = name};

  status = pack_entry(buffer, &root);
  PAMBLE_RETURN_IF_ERROR(status);

  status = buffer_append(buffer, &end_marker, TYPE_LENGTH);
  PAMBLE_RETURN_IF_ERROR(status);

  return PAMBLE_OK;
}

/*
 * @brief Frees an archive previously allocated by pamble_archive_pack.
 *
 * @param archive Archive buffer to free. NULL is a no-op.
 */
void pamble_free_archive(uint8_t *archive) { free(archive); }

/*
 * @brief Packs a file or directory tree into an in-memory archive.
 *
 * This is the one-shot packing interface. The basename of input_path becomes
 * the root entry of the archive. Directories are walked recursively and their
 * entries are stored in sorted order, so packing the same tree twice yields
 * identical bytes. Only regular files and directories are archived; symbolic
 * links and other special files below the root are skipped.
 *
 * @param input_path Path of the file or directory to pack.
 * @param archive Output parameter; on success, set to a newly allocated
 *                buffer holding the archive. Caller must free it with
 *                pamble_free_archive. Set to NULL on failure.
 * @param archive_length Output parameter; on success, set to the number of
 *                       bytes in archive.
 *
 * @return PAMBLE_OK if the archive was built successfully.
 * @return PAMBLE_INVALID_ARGUMENT if any argument is NULL, if input_path has
 *         no usable basename (e.g. "/", ".", ".."), or if input_path is
 *         neither a regular file nor a directory.
 * @return PAMBLE_IO_ERROR if a path cannot be inspected, opened, listed, or
 *         read completely.
 * @return PAMBLE_SIZE_OVERFLOW if an archive path exceeds UINT16_MAX bytes,
 *         a file is too large to buffer, or allocation fails.
 */
pamble_status pamble_archive_pack(const char *input_path, uint8_t **archive,
                                  size_t *archive_length) {

  if (input_path == NULL || archive == NULL || archive_length == NULL) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  *archive = NULL;

  char *name = NULL;

  pamble_status status = root_name(input_path, &name);
  PAMBLE_RETURN_IF_ERROR(status);

  byte_buffer buffer = {.data = NULL, .length = 0, .capacity = 0};

  status = build_archive(&buffer, input_path, name);

  free(name);

  if (status != PAMBLE_OK) {
    free(buffer.data);
    return status;
  }

  *archive = buffer.data;
  *archive_length = buffer.length;

  return PAMBLE_OK;
}

/*
 * @brief Consumes a fixed number of bytes from a reader.
 *
 * @param reader Reader to consume from.
 * @param count Number of bytes to consume.
 * @param bytes Output parameter; set to the start of the consumed bytes.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_INVALID_ARCHIVE if fewer than count bytes remain.
 */
static pamble_status reader_take(byte_reader *reader, size_t count,
                                 const uint8_t **bytes) {

  if (count > reader->length - reader->offset) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  *bytes = reader->data + reader->offset;
  reader->offset += count;

  return PAMBLE_OK;
}

/*
 * @brief Reads and checks the archive magic and version.
 *
 * @param reader Reader positioned at the start of the archive.
 *
 * @return PAMBLE_OK if the header is valid.
 * @return PAMBLE_INVALID_ARCHIVE if the header is truncated, the magic does
 *         not match, or the version is unsupported.
 */
static pamble_status read_header(byte_reader *reader) {

  pamble_status status;

  const uint8_t *magic = NULL;
  const uint8_t *version = NULL;

  status = reader_take(reader, MAGIC_LENGTH, &magic);
  PAMBLE_RETURN_IF_ERROR(status);

  if (memcmp(magic, MAGIC, MAGIC_LENGTH) != 0) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  status = reader_take(reader, VERSION_LENGTH, &version);
  PAMBLE_RETURN_IF_ERROR(status);

  if (*version != PAMBLE_ARCHIVE_VERSION) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  return PAMBLE_OK;
}

/*
 * @brief Checks whether an archive path is safe to extract.
 *
 * A safe path is non-empty, relative, contains no NUL bytes, and consists
 * only of non-empty components other than "." and "..".
 *
 * @param path Path bytes from the archive. Not NUL-terminated.
 * @param path_length Number of bytes in path.
 *
 * @return true if the path is safe.
 */
static bool is_safe_path(const uint8_t *path, size_t path_length) {

  if (path_length == 0 || memchr(path, '\0', path_length) != NULL) {
    return false;
  }

  size_t start = 0;

  while (start <= path_length) {
    const uint8_t *separator =
        memchr(path + start, PATH_SEPARATOR, path_length - start);

    const size_t end =
        separator == NULL ? path_length : (size_t)(separator - path);

    const size_t component_length = end - start;
    const uint8_t *component = path + start;

    if (component_length == 0 ||
        (component_length == 1 && component[0] == '.') ||
        (component_length == 2 && component[0] == '.' && component[1] == '.')) {
      return false;
    }

    start = end + PATH_SEPARATOR_LENGTH;
  }

  return true;
}

/*
 * @brief Reads and validates the next entry from the archive.
 *
 * On ENTRY_END only entry->type is set.
 *
 * @param reader Reader positioned at the start of an entry.
 * @param entry Output parameter for the decoded entry.
 *
 * @return PAMBLE_OK if the entry is well-formed.
 * @return PAMBLE_INVALID_ARCHIVE if the entry is truncated, has an unknown
 *         type, mode bits outside MODE_MASK, an unsafe path, or is a
 *         directory with content.
 */
static pamble_status read_entry(byte_reader *reader, archive_entry *entry) {

  pamble_status status;

  const uint8_t *type = NULL;
  const uint8_t *fields = NULL;

  status = reader_take(reader, TYPE_LENGTH, &type);
  PAMBLE_RETURN_IF_ERROR(status);

  entry->type = *type;

  if (entry->type == ENTRY_END) {
    return PAMBLE_OK;
  }

  if (entry->type != ENTRY_FILE && entry->type != ENTRY_DIRECTORY) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  status = reader_take(reader, ENTRY_FIELDS_LENGTH, &fields);
  PAMBLE_RETURN_IF_ERROR(status);

  const uint64_t mode = decode_be(&fields[MODE_OFFSET], MODE_LENGTH);
  const uint64_t path_length =
      decode_be(&fields[PATH_LENGTH_OFFSET], PATH_LENGTH_LENGTH);
  const uint64_t content_length =
      decode_be(&fields[CONTENT_LENGTH_OFFSET], CONTENT_LENGTH_LENGTH);

  if ((mode & ~(uint64_t)MODE_MASK) != 0) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  if (entry->type == ENTRY_DIRECTORY && content_length != 0) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  if (content_length > reader->length - reader->offset) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  entry->mode = (uint32_t)mode;
  entry->path_length = (size_t)path_length;
  entry->content_length = (size_t)content_length;

  status = reader_take(reader, entry->path_length, &entry->path);
  PAMBLE_RETURN_IF_ERROR(status);

  if (!is_safe_path(entry->path, entry->path_length)) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  status = reader_take(reader, entry->content_length, &entry->content);
  PAMBLE_RETURN_IF_ERROR(status);

  return PAMBLE_OK;
}

/*
 * @brief Creates a directory entry on disk.
 *
 * The directory is created owner-only, then given its stored mode with the
 * owner rwx bits forced on so later entries can be extracted into it. An
 * existing real directory is accepted; anything else at that path is not.
 *
 * @param full_path Filesystem path to create.
 * @param mode Stored permission bits.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_IO_ERROR if the directory cannot be created or chmod'ed, or
 *         a non-directory already exists at full_path.
 */
static pamble_status extract_directory(const char *full_path, uint32_t mode) {

  if (mkdir(full_path, DIRECTORY_CREATE_MODE) != 0) {
    struct stat info;

    if (errno != EEXIST || lstat(full_path, &info) != 0 ||
        !S_ISDIR(info.st_mode)) {
      return PAMBLE_IO_ERROR;
    }
  }

  if (chmod(full_path, (mode_t)(mode | S_IRWXU)) != 0) {
    return PAMBLE_IO_ERROR;
  }

  return PAMBLE_OK;
}

/*
 * @brief Creates a regular file entry on disk.
 *
 * The file is opened in exclusive mode, so an existing file (or symbolic
 * link) at full_path is never overwritten or followed.
 *
 * @param full_path Filesystem path to create.
 * @param entry Entry holding the content and stored mode.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_IO_ERROR if the file exists or cannot be created, written,
 *         closed, or chmod'ed.
 */
static pamble_status extract_file(const char *full_path,
                                  const archive_entry *entry) {

  FILE *file = fopen(full_path, "wbx");

  if (file == NULL) {
    return PAMBLE_IO_ERROR;
  }

  pamble_status status = PAMBLE_OK;

  if (entry->content_length != 0 &&
      fwrite(entry->content, 1, entry->content_length, file) !=
          entry->content_length) {
    status = PAMBLE_IO_ERROR;
  }

  if (fclose(file) != 0) {
    status = PAMBLE_IO_ERROR;
  }

  PAMBLE_RETURN_IF_ERROR(status);

  if (chmod(full_path, (mode_t)entry->mode) != 0) {
    return PAMBLE_IO_ERROR;
  }

  return PAMBLE_OK;
}

/*
 * @brief Extracts a single validated entry under output_path.
 *
 * @param output_path Directory to extract into.
 * @param entry Validated entry to extract.
 *
 * @return PAMBLE_OK on success.
 * @return PAMBLE_SIZE_OVERFLOW if allocation fails, or any error from
 *         extract_directory or extract_file.
 */
static pamble_status extract_entry(const char *output_path,
                                   const archive_entry *entry) {

  char *full_path =
      join_path(output_path, (const char *)entry->path, entry->path_length);

  if (full_path == NULL) {
    return PAMBLE_SIZE_OVERFLOW;
  }

  pamble_status status = entry->type == ENTRY_DIRECTORY
                             ? extract_directory(full_path, entry->mode)
                             : extract_file(full_path, entry);

  free(full_path);

  return status;
}

/*
 * @brief Walks every entry of an archive, optionally extracting each one.
 *
 * @param archive Archive data.
 * @param archive_length Number of bytes in archive.
 * @param output_path Directory to extract into, or NULL to only validate.
 *
 * @return PAMBLE_OK if the archive is valid (and, when extracting, every
 *         entry was written).
 * @return PAMBLE_INVALID_ARCHIVE if any part of the archive is malformed or
 *         bytes follow the end marker, or any error from extract_entry.
 */
static pamble_status walk_archive(const uint8_t *archive, size_t archive_length,
                                  const char *output_path) {

  pamble_status status;

  byte_reader reader = {.data = archive, .length = archive_length, .offset = 0};

  status = read_header(&reader);
  PAMBLE_RETURN_IF_ERROR(status);

  archive_entry entry = {.type = ENTRY_END};

  do {
    status = read_entry(&reader, &entry);
    PAMBLE_RETURN_IF_ERROR(status);

    if (entry.type != ENTRY_END && output_path != NULL) {
      status = extract_entry(output_path, &entry);
      PAMBLE_RETURN_IF_ERROR(status);
    }
  } while (entry.type != ENTRY_END);

  if (reader.offset != reader.length) {
    return PAMBLE_INVALID_ARCHIVE;
  }

  return PAMBLE_OK;
}

/*
 * @brief Unpacks an in-memory archive into an existing directory.
 *
 * This is the one-shot unpacking interface. The whole archive is validated
 * before anything is written, so a malformed archive or one containing an
 * unsafe path (absolute, empty component, "." or "..") leaves output_path
 * untouched. Existing files are never overwritten.
 *
 * @param archive Archive data to unpack.
 * @param archive_length Number of bytes in archive.
 * @param output_path Existing directory to extract into.
 *
 * @return PAMBLE_OK if every entry was extracted successfully.
 * @return PAMBLE_INVALID_ARGUMENT if archive is NULL while archive_length is
 *         non-zero, if output_path is NULL, or if output_path is not an
 *         existing directory.
 * @return PAMBLE_INVALID_ARCHIVE if the archive is truncated, has a bad magic
 *         or version, contains an unknown entry type, invalid mode bits, an
 *         unsafe path, a directory with content, or trailing bytes.
 * @return PAMBLE_IO_ERROR if a directory or file cannot be created, written,
 *         or given its stored mode, or if a file already exists.
 * @return PAMBLE_SIZE_OVERFLOW if allocation fails.
 */
pamble_status pamble_archive_unpack(const uint8_t *archive,
                                    size_t archive_length,
                                    const char *output_path) {

  if (archive == NULL && archive_length != 0) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  if (output_path == NULL) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  struct stat info;

  if (stat(output_path, &info) != 0 || !S_ISDIR(info.st_mode)) {
    return PAMBLE_INVALID_ARGUMENT;
  }

  pamble_status status;

  status = walk_archive(archive, archive_length, NULL);
  PAMBLE_RETURN_IF_ERROR(status);

  status = walk_archive(archive, archive_length, output_path);
  PAMBLE_RETURN_IF_ERROR(status);

  return PAMBLE_OK;
}
