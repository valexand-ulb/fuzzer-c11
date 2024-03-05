//
// Created by alex on 2/03/24.
//

#include "tar_utils.h"

#include "test.h"

/**
 * Initializes the tar headers with default metadata of the file
 * @param headers : pointer to the tar header
 * @param filename: file name associated with the header
 */
void initialize_tar_headers(struct tar_t *header, const char * filename) {
    struct stat file_stat;

    if (stat(filename, &file_stat) == -1){
        perror("Error getting file stats\n");
        return;
    }

    strncpy(header->name, filename, sizeof(header->name)-1);
    snprintf(header->mode, sizeof(header->mode), "%07o", 0644);
    snprintf(header->uid, sizeof(header->uid), "%07o", getuid()); // getuid instead of file_stat.st_uid
    snprintf(header->gid, sizeof(header->gid), "%07o", getgid()); // getgid instead of file_stat.st_gid
    snprintf(header->size, sizeof(header->size), "%011o", (int) file_stat.st_size);
    snprintf(header->mtime, sizeof(header->mtime), "%011o", (int) file_stat.st_mtime);
    header->typeflag = '0';
    strncpy(header->linkname, "", 100);
    strncpy(header->magic, "ustar", sizeof(header->magic)-1);
    strncpy(header->version, "00", sizeof(header->version));
    strncpy(header->uname, "alex", sizeof(header->uname)-1);
    strncpy(header->gname, "alex", sizeof(header->gname)-1);
    strncpy(header->devmajor, "", sizeof(header->devmajor)-1);
    strncpy(header->devminor, "", sizeof(header->devminor)-1);
    strncpy(header->prefix, "", sizeof(header->prefix)-1);
    strncpy(header->padding, "", sizeof(header->padding)-1);

    calculate_checksum(header);
}

/**
 * Initializes the tar headers with fuzzed a secific metadata of the file. The specific metadata is determined by the padding
 * @param headers : pointer to the tar header
 * @param padding: padding to be used for fuzzing
 * @param value: value to be used for fuzzing
 */
void initialize_fuzzed_tar_headers(struct tar_t *header,unsigned padding, const char *value) {
    char* ptr = (char*) header+padding;
    strncpy(ptr, value, strlen(value));
}

/**
 * Calculates the checksum of the tar header
 * @param entry : pointer to the tar header
 * @return : checksum value
 */
unsigned int calculate_checksum(struct tar_t* entry){
    // use spaces for the checksum bytes while calculating the checksum
    memset(entry->chksum, ' ', 8);

    // sum of entire metadata
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < 512; i++){
        check += raw[i];
    }

    snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);

    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}

/**
 * Writes the contents of the file to the tar file
 * @param tar_file : pointer to the tar file
 * @param file : pointer to the file
 */
void write_file_contents(FILE* tar_file, FILE* file){
    char buffer[512];
    size_t bytes_read;
    while((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0){
        fwrite(buffer, 1, bytes_read, tar_file);
        if (bytes_read < sizeof(buffer)){
            memset(buffer + bytes_read, 0, sizeof(buffer) - bytes_read);
            fwrite(buffer + bytes_read, 1, sizeof(buffer) - bytes_read, tar_file);
        }
    }
}

/**
 * Creates a tar file with the given name
 * @param filename : name of the tar file
 * @return : pointer to the tar file
 */
FILE * create_tar_file(const char* filename){
    FILE* tar_file = fopen(filename, "w+");

    if(tar_file == NULL){
        perror("Error creating tar file\n");
        return NULL;
    }
    return tar_file;
}

void write_tar_header(FILE* tar_file_ptr, struct tar_t *header){
    fwrite(header, 1, sizeof(struct tar_t), tar_file_ptr);
}

void write_tar_content_from_file(FILE *tar_file_ptr, const char *filename){
    FILE* content_file = fopen(filename, "r");

    if(content_file == NULL){
        perror("Error opening file\n");
        return;
    }
    // write the file contents
    write_file_contents(tar_file_ptr, content_file);

    // close the file added to the tar
    fclose(content_file);

    printf("Archive appenend\n");
}

void write_tar_content(FILE *tar_file_ptr, const char *content, bool add_padding) {
    fprintf(tar_file_ptr, "%s", content);

    if (add_padding) {
        char zeroes[512] = {7};
        int size_content = strlen(content);
        int amount_to_add = 512 - (size_content % 512);
        fwrite(zeroes, sizeof(char), amount_to_add, tar_file_ptr);
    }

    printf("Archive appenend\n");
}

/**
 * Writes the end of the archive to the tar file with two empty blocks of 512 bytes
 * @param tar_file : pointer to the tar file
 */
void write_end_of_tar(FILE* tar_file){
    char end[1024] = {0}; // end of archive with two empty blocks of 512 bytes
    fwrite(end, 1, sizeof(end), tar_file);
}

/**
 * Closes the tar file
 * @param tar_file_ptr : pointer to the tar file
 */
void close_tar_file(FILE* tar_file_ptr){
    write_end_of_tar(tar_file_ptr);
    fclose(tar_file_ptr);
}

/**
 * Renames the tar file when the archive has crashed the program
 * @param tar_file : pointer to the tar file
 * @param new_name : new name of the tar file
 */
void rename_tar_file(FILE* tar_file_ptr, const char* new_name){
    //fclose(tar_file_ptr); // close the file before renaming, otherwise it will not be renamed
    rename("archive.tar", new_name);
}

/**
 * Removes specified file
 *
 * @param filename : name (path) of the file to be removed
 */
void remove_tar(const char* filename) {
    remove(filename);
}

