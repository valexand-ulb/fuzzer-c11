#include "fuzz.h"

void start_fuzzing(char* cmd) {
    // Declare an array of function pointers
    void (*functionList[])() = {attempt1,
                                attempt2,
                                attempt3};

    int numFunctions = sizeof(functionList) / sizeof(functionList[0]);

    // Iterate over the array and call each function
    for (int i = 0; i < numFunctions; i++) {
        (*functionList[i])(cmd);
    }
}


void attempt1(char* cmd) {
    char* filenames[] = {"myfile"};
    struct tar_t header1 = {0};

    FILE * tar_ptr = create_tar_file("archive.tar");

    initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);

    close_tar_file(tar_ptr);

    // ======== TEST ========
    printf("\nAttempt 1 output : ");
    execute_on_tar(cmd);
    remove_tar("archive.tar");      // cleanup tar
    remove_extracted_files(filenames);      // cleanup files
}

void attempt2(char* cmd) {
    printf("This is attempt 2\n");
}

void attempt3(char* cmd) {
    printf("This is attempt 3\n");
}

