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
                            const char *gname){
    memset(headers, 0, sizeof(struct tar_t));
    strncpy(headers->name, name, sizeof(headers->name));
    strncpy(headers->mode, mode, sizeof(headers->mode));
    strncpy(headers->uid, uid, sizeof(headers->uid));
    strncpy(headers->gid, gid, sizeof(headers->gid));
    strncpy(headers->size, size, sizeof(headers->size));
    strncpy(headers->mtime, mtime, sizeof(headers->mtime));
    headers->typeflag = *typeflag;
    strncpy(headers->linkname, linkname, sizeof(headers->linkname));
    strncpy(headers->magic, magic, sizeof(headers->magic));
    strncpy(headers->version, version, sizeof(headers->version));
    strncpy(headers->uname, uname, sizeof(headers->uname));
    strncpy(headers->gname, gname, sizeof(headers->gname));
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

void generate_tar(const char *output_filename, int num_files, char *files[]){
    FILE *output_tar_file = fopen(output_filename, "wb");
    if (!output_tar_file){
        perror("Error opening file\n");
        return;
    }

    for (unsigned i=0; i < num_files; i++) {
        const char *filename = files[i];

        struct tar_t header;
        initialize_tar_header(&header, filename, "0644", "1000", "1000", "0", "1635345324", "0", "", "ustar", "00", "username", "groupname");
        calculate_checksum(&header);

        fwrite(&header, sizeof(struct tar_t), 1, output_tar_file);

        FILE *input_file = fopen(filename, "rb");
        if (!input_file){
            perror("Error opening file\n");
            return;
        }

        char buffer[1024]; // double the size of the block size to mark end of file
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), input_file)) > 0){
            fwrite(buffer, 1, bytes_read, output_tar_file);
        }
        fclose(input_file);
    }
    fclose(output_tar_file);

    printf("Archive created\n");

}
