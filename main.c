#include <stdio.h>
#include <string.h>

#include "tar_utils.h"
#include "test.h"

int main(int argc, char* argv[]) {
    /*
     * HOW TO USE tar_utlils
     */
    char * files[] = {"test_files/file1.txt", "test_files/file2.txt"}; // <- list of files to be added to the tar

    FILE * tar_ptr = create_tar_file("archive.tar"); // <- create the tar file, use of the ptr to each function

    struct tar_t header1 = {0}; // <- create the headers for the files
    struct tar_t header2 = {0}; // <- create the headers for the files

    // WARNING: YOU CAN USE intialize_fuzzed_tar_headers to fuzz a specific metadata of the tar header

    // first file added to the tar
    initialize_tar_headers(&header1, files[0]); // <- initialize the headers with the file1.txt info
    write_tar_header(tar_ptr, &header1); // <- write the headers to the tar file
    write_tar_content(tar_ptr, files[0]); // <- write the file1.txt content to the tar file

    // second file added to the tar
    initialize_tar_headers(&header2, files[1]); // <- initialize the headers with the file2.txt info
    write_tar_header(tar_ptr, &header2); // <- write the headers to the tar file
    write_tar_content(tar_ptr, files[1]); // <- write the file2.txt content to the tar file

    close_tar_file(tar_ptr); // <- mandatory to close the tar file since it add the end of the archive


    if (argc < 2){
        printf("Not enough arguments given");
        return -1;
    }
    int rv = 0;
    char cmd[51];
    strncpy(cmd, argv[1], 25);
    cmd[26] = '\0';
    strncat(cmd, " archive.tar", 25);
    char buf[33];
    FILE *fp;

    if ((fp = popen(cmd, "r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }

    if(fgets(buf, 33, fp) == NULL) {
        printf("No output\n");
        goto finally;
    }
    if(strncmp(buf, "*** The program has crashed ***\n", 33)) {
        printf("Not the crash message\n");
        goto finally;
    } else {
        printf("Crash message\n");
        rv = 1;
        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }
    return rv;
}
