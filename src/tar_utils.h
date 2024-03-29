#ifndef FUZZER_GENERATE_TAR_H
#define FUZZER_GENERATE_TAR_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>

#include "tar_header.h"


// HEADERS MANIPULATION

void initialize_tar_headers_from_file(struct tar_t *header, const char* filename);

void initialize_tar_headers(struct tar_t *header, const char* filename, int size, int mtime);

void tweak_header_field(struct tar_t *header,unsigned padding, const char *value);

void fill_header_field(struct tar_t *header,unsigned padding);

void tweak_header_field_intval(struct tar_t * header, unsigned padding, int * value, const char *format);

unsigned int calculate_checksum(struct tar_t* entry);


// FILE CONTENT MANIPULATION
void write_file_contents(FILE* tar_file, FILE* file);

// TAR MANIPULATION
FILE * create_tar_file(const char* filename);

void write_tar_header(FILE* tar_file_ptr, struct tar_t *header);

void write_tar_content_from_file(FILE *tar_file_ptr, const char *filename);

void write_tar_content(FILE *tar_file_ptr, const char *content, bool add_padding);

void write_end_of_tar(FILE* tar_file);

void close_tar_file(FILE* tar_file_ptr);

void remove_tar(const char* filename);

void remove_extracted_files(const char** filenames);

void remove_directory(const char *path);

#endif //FUZZER_GENERATE_TAR_H
