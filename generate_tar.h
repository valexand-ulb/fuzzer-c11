//
// Created by alex on 2/03/24.
//
#ifndef FUZZER_GENERATE_TAR_H
#define FUZZER_GENERATE_TAR_H

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>


#include "tar_header.h"

void initialize_tar_header(struct tar_t *header,
                            const char *name,       // name of the archive
                            const char *mode,       // file mode, 3 octal digits representing RWX for user, group, and other
                            const char *uid,        // id of the user who owns the file
                            const char *gid,        // id of the group who owns the file
                            const char *size,       // size of the file in bytes
                            const char *mtime,      // last modification time of the file
                            const char *typeflag,   // type of file, file, directory, link, etc
                            const char *linkname,   // if symlink, the name of the file it points to
                            const char *magic,      // magic value, "ustar" for tar
                            const char *version,    // version of the tar format
                            const char *uname,      // name of the user who owns the file
                            const char *gname);     // name of the group who owns the file

unsigned int calculate_checksum(struct tar_t* entry);

void generate_tar(const char *output_filename, int num_files, char *files[]);

#endif //FUZZER_GENERATE_TAR_H
