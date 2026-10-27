#pragma once

#include "pamble/pamble_status.h"

#include <stddef.h>
#include <stdint.h>

#define PAMBLE_ARCHIVE_VERSION 1

/*
 * @brief Frees an archive previously allocated by pamble_archive_pack.
 *
 * @param archive Archive buffer to free. NULL is a no-op.
 */
void pamble_free_archive(uint8_t *archive);

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
                                  size_t *archive_length);

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
                                    const char *output_path);
