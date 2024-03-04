//
// Created by alex on 2/03/24.
//
#ifndef FUZZER_GENERATE_TAR_H
#define FUZZER_GENERATE_TAR_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "tar_header.h"

void initialize_tar_headers(struct tar_t *headers, const char * filename);

void initialize_fuzzed_tar_headers(struct tar_t *headers,unsigned padding, const char *value);

unsigned int calculate_checksum(struct tar_t* entry);

void write_file_contents(FILE* tar_file, FILE* file);

void generate_tar(const char *output_filename, int num_files, char *files[]);

#endif //FUZZER_GENERATE_TAR_H
