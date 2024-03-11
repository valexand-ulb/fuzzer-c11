//
// Created by alex on 4/03/24.
//

#include "test.h"

void test_filename(struct tar_t *headers){
    printf("\tTesting filename...\n");
    tweak_header_field(headers, NAME_PADDING, "file1.txt");
}

void test_mode(struct tar_t *headers){
    printf("\tTesting mode...\n");
    tweak_header_field(headers, MODE_PADDING, "0644");
}

void test_uid(struct tar_t *headers){
    printf("\tTesting uid...\n");
    tweak_header_field(headers, UID_PADDING, "0000000");
}

void test_gid(struct tar_t *headers){
    printf("\tTesting gid...\n");
    tweak_header_field(headers, GID_PADDING, "0000000");
}

void test_size(struct tar_t *headers){
    printf("\tTesting size...\n");
    tweak_header_field(headers, SIZE_PADDING, "00000000000");
}

void test_mtime(struct tar_t *headers){
    printf("\tTesting mtime...\n");
    tweak_header_field(headers, MTIME_PADDING, "00000000000");
}

void test_typeflag(struct tar_t *headers){
    printf("\tTesting typeflag...\n");
    tweak_header_field(headers, TYPEFLAG_PADDING, "0");
}

void test_linkname(struct tar_t *headers){
    printf("\tTesting linkname...\n");
    tweak_header_field(headers, LINKNAME_PADDING, "");
}

void test_magic(struct tar_t *headers){
    printf("\tTesting magic...\n");
    tweak_header_field(headers, MAGIC_PADDING, "ustar");
}

void test_version(struct tar_t *headers){
    printf("\tTesting version...\n");
    tweak_header_field(headers, VERSION_PADDING, "00");
}

void test_uname(struct tar_t *headers){
    printf("\tTesting uname...\n");
    tweak_header_field(headers, UNAME_PADDING, "alex");
}

void test_gname(struct tar_t *headers){
    printf("\tTesting gname...\n");
    tweak_header_field(headers, GNAME_PADDING, "alex");
}

void test_devmajor(struct tar_t *headers){
    printf("\tTesting devmajor...\n");
    tweak_header_field(headers, DEVMAJOR_PADDING, "");
}

void test_devminor(struct tar_t *headers){
    printf("\tTesting devminor...\n");
    tweak_header_field(headers, DEVMINOR_PADDING, "");
}

void test_prefix(struct tar_t *headers){
    printf("\tTesting prefix...\n");
    tweak_header_field(headers, PREFIX_PADDING, "");
}

void test_padding(struct tar_t *headers){
    printf("\tTesting padding...\n");
    tweak_header_field(headers, PADDING_PADDING, "");
}

void test_checksum(struct tar_t *headers){
    printf("\tTesting checksum...\n");
    calculate_checksum(headers);
    tweak_header_field(headers, CHKSUM_PADDING, headers->chksum);
}

void test_all(struct tar_t *headers){
    printf("Testing all...\n");
    test_filename(headers);
    test_mode(headers);
    test_uid(headers);
    test_gid(headers);
    test_size(headers);
    test_mtime(headers);
    test_typeflag(headers);
    test_linkname(headers);
    test_magic(headers);
    test_version(headers);
    test_uname(headers);
    test_gname(headers);
    test_devmajor(headers);
    test_devminor(headers);
    test_prefix(headers);
    test_padding(headers);
    test_checksum(headers);
}