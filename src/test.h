//
// Created by alex on 4/03/24.
//

#ifndef TEST_H
#define TEST_H

#include "tar_utils.h"

void test_filename(struct tar_t *headers);

void test_mode(struct tar_t *headers);

void test_uid(struct tar_t *headers);

void test_gid(struct tar_t *headers);

void test_size(struct tar_t *headers);

void test_mtime(struct tar_t *headers);

void test_typeflag(struct tar_t *headers);

void test_linkname(struct tar_t *headers);

void test_magic(struct tar_t *headers);

void test_version(struct tar_t *headers);

void test_uname(struct tar_t *headers);

void test_gname(struct tar_t *headers);

void test_devmajor(struct tar_t *headers);

void test_devminor(struct tar_t *headers);

void test_prefix(struct tar_t *headers);

void test_padding(struct tar_t *headers);

void test_checksum(struct tar_t *headers);

void test_all(struct tar_t *headers);
#endif //TEST_H
