#include "fuzz.h"

void start_fuzzing(char* cmd) {
    // Declare an array of function pointers
    void (*functionList[])() = {attempt1,
                                attempt2,
                                attempt3,
                                attempt4};

    int numFunctions = sizeof(functionList) / sizeof(functionList[0]);

    // Iterate over the array and call each function
    for (int i = 0; i < numFunctions; i++) {
        (*functionList[i])(cmd);
    }
}

/**
 * Attempt 1
 *
 * Example attempt on a regular tar file with no tweak
 */
void attempt1(char* cmd) {
    const char* filenames[] = {"myfile"};
    struct tar_t header1 = {0};

    FILE * tar_ptr = create_tar_file("archive.tar");

    initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 1 output : ");
    execute_on_tar(cmd);
    remove_tar("archive.tar");      // cleanup tar
    remove_extracted_files(filenames);      // cleanup files
}

/**
 * Attempt 2
 *
 * Non-ascii name
 */
void attempt2(char* cmd) {
    const char* filenames[] = {"myfile"};
    struct tar_t header1 = {0};

    FILE * tar_ptr = create_tar_file("archive.tar");

    initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
    // -------- header tweak --------
    strncpy(header1.name, "\xff", sizeof(header1.name)-1);
    filenames[0] = "\xff";
    // ------------------------------
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 2: Non-ascii name \noutput : ");
    execute_on_tar(cmd);
    remove_tar("archive.tar");      // cleanup tar
    remove_extracted_files(filenames);      // cleanup files
}

/**
 * Attempt 3
 *
 * Huge size in header
 */
void attempt3(char* cmd) {
    const char* filenames[] = {"myfile"};
    struct tar_t header1 = {0};

    FILE * tar_ptr = create_tar_file("archive.tar");

    initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
    // -------- header tweak --------
    snprintf(header1.size, sizeof(header1.size), "%011lo", 4294967295); // this gives 37777777777 (len: 11) in octal
    // ------------------------------
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 3: Huge size in header \noutput : ");
    execute_on_tar(cmd);
    remove_tar("archive.tar");      // cleanup tar
    remove_extracted_files(filenames);        // cleanup files
}

/**
 * Attempt 4
 *
 * Non-octal size in header
 */
void attempt4(char* cmd) {
    const char* filenames[] = {"myfile"};
    struct tar_t header1 = {0};

    FILE * tar_ptr = create_tar_file("archive.tar");

    initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
    // -------- header tweak --------
    strcpy(header1.size, "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");     // len : 1 + 11 nullbyte
    // ------------------------------
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 4: Non-octal size in header \noutput : ");
    execute_on_tar(cmd);
    remove_tar("archive.tar");      // cleanup tar
    remove_extracted_files(filenames);        // cleanup files
}

