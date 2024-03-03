//
// Created by alex on 2/03/24.
//

#include "generate_tar.h"


void initialize_tar_header(struct tar_t *headers,
                            const char *name,
                            const char *mode,
                            const char *uid,
                            const char *gid,
                            const char *size,
                            const char *mtime,
                            const char *typeflag,
                            const char *linkname,
                            const char *magic,
                            const char *version,
                            const char *uname,
                            const char *gname)
{
    memset(headers, 0, sizeof(struct tar_t));
    strncpy(headers->name, name, 100);
    snprintf(headers->mode, sizeof(headers->mode), "%07o", 0644);
    snprintf(headers->uid, sizeof(headers->uid), "%07o", getuid());
    snprintf(headers->gid, sizeof(headers->gid), "%07o", getgid());
    snprintf(headers->size, sizeof(headers->size), "%011o", 0);
    snprintf(headers->mtime, sizeof(headers->mtime), "%011o", 0);
    headers->typeflag = '0';
    strncpy(headers->linkname, linkname, 100);
    strncpy(headers->magic, magic, 6);
    strncpy(headers->version, version, 2);
    strncpy(headers->uname, uname, 32);
    strncpy(headers->gname, gname, 32);
}

void initialize_tar_headers(struct tar_t *headers, const char * filename) {
    struct stat file_stat;

    if (stat(filename, &file_stat) == -1){
        perror("Error getting file stats\n");
        return;
    }

    strncpy(headers->name, filename, sizeof(headers->name)-1);
    snprintf(headers->mode, sizeof(headers->mode), "%07o", 0644);
    snprintf(headers->uid, sizeof(headers->uid), "%07o", getuid()); // getuid instead of file_stat.st_uid
    snprintf(headers->gid, sizeof(headers->gid), "%07o", getgid()); // getgid instead of file_stat.st_gid
    snprintf(headers->size, sizeof(headers->size), "%011o", (int) file_stat.st_size);
    snprintf(headers->mtime, sizeof(headers->mtime), "%011o", (int) file_stat.st_mtime);
    headers->typeflag = '0';
    strncpy(headers->linkname, "", 100);
    strncpy(headers->magic, "ustar", sizeof(headers->magic)-1);
    strncpy(headers->version, "00", sizeof(headers->version));
    strncpy(headers->uname, "alex", sizeof(headers->uname)-1);
    strncpy(headers->gname, "alex", sizeof(headers->gname)-1);
    strncpy(headers->devmajor, "", sizeof(headers->devmajor)-1);
    strncpy(headers->devminor, "", sizeof(headers->devminor)-1);
    strncpy(headers->prefix, "", sizeof(headers->prefix)-1);
    strncpy(headers->padding, "", sizeof(headers->padding)-1);

    calculate_checksum(headers);
}


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

void generate_tar(const char *output_filename, int num_files, char *files[]){
    FILE* tar_file = fopen(output_filename, "w");
    if(tar_file == NULL){
        perror("Error opening file\n");
        return;
    }
    for (int i = 0; i < num_files; i++){
        FILE* file = fopen(files[i], "r");
        if(file == NULL){
            perror("Error opening file\n");
            return;
        }
        struct tar_t header = {0};
        initialize_tar_headers(&header, files[i]);
        //calculate_checksum(&header);
        fwrite(&header, 1, sizeof(struct tar_t), tar_file);
        write_file_contents(tar_file, file);
        fclose(file);
    }
    char end[1024] = {0}; // end of archive with two empty blocks of 512 bytes
    fwrite(end, 1, sizeof(end), tar_file);
    fclose(tar_file);
    printf("Archive created\n");
}
