#include "fuzz.h"

#include <bits/types/siginfo_t.h>

// padding values
const unsigned int PADDINGS[11] = {SIZE_PADDING,
        MODE_PADDING,
        UID_PADDING,
        GID_PADDING,
        MTIME_PADDING,
        TYPEFLAG_PADDING,
        LINKNAME_PADDING,
        MAGIC_PADDING,
        VERSION_PADDING,
        UNAME_PADDING,
        GNAME_PADDING,};

void start_fuzzing(char* cmd) {
    // Declare an array of function pointers
    void (*functionList[])() =
    {
        attempt1,
        attempt2,
        attempt3,
        attempt4,
        attempt5,
        attempt6,
        attempt7,
        attempt8,
        attempt9,
        attempt10,
        attempt11,
        attempt12,
        attempt13,
    };

    int numFunctions = sizeof(functionList) / sizeof(functionList[0]);

    // Iterate over the array and call each function
    for (int i = 0; i < numFunctions; i++) {
        (*functionList[i])(cmd);
    }
}

char* make_arch_name(int nbr1, int nbr2) {
    char attempt_num_str[10];
    sprintf(attempt_num_str, "%d", nbr1);

    char iter_num_str[10];
    sprintf(iter_num_str, "%d", nbr2);

    char arch_name[40] = "archive";
    strcat(arch_name, attempt_num_str);
    strcat(arch_name, "-");
    strcat(arch_name, iter_num_str);
    strcat(arch_name, ".tar");

    // allocating memory
    char* result = (char*)malloc(40 * sizeof(char));

    strcpy(result, arch_name);

    return result;
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

    initialize_tar_headers(&header1, filenames[0], 5, time(NULL)); // default tar header
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 1 \n\toutput : ");
    execute_on_tar(cmd, 1);
    remove_tar("archive.tar");      // cleanup tar
    rename_tar_file(tar_ptr, "archive1.tar");
    remove_extracted_files(filenames);      // cleanup files
}

/**
 * Attempt 2
 *
 * Non-ascii name
 */

void attempt2(char * cmd) {
    const char *filenames[] = {"test_files/file1.txt"};

    printf("Attempt 2: Non-ascii name \n");

    for (unsigned i = 0; i < sizeof(PADDINGS)/sizeof(unsigned); i++) {
        struct tar_t header1 = {0};

        FILE *tar_ptr = create_tar_file("archive.tar");

        initialize_tar_headers_from_file(&header1, filenames[0]);
        // -------- header tweak --------
        initialize_fuzzed_tar_headers(&header1, PADDINGS[i], "😃\0", "%s");
        // ------------------------------
        calculate_checksum(&header1);
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr, filenames[0]);
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        printf("\t- attempt 2.%d: Non-ascii name\n\toutput : ", i+1);
        execute_on_tar(cmd, 2);
        remove_tar("archive.tar");
    }

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
    //initialize_fuzzed_tar_headers(&header1, SIZE_PADDING,"4294967295", "%011lo");
    // ------------------------------
    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 3: Huge size in header \n\toutput : ");
    execute_on_tar(cmd, 3);
    remove_tar("archive.tar");      // cleanup tar
    rename_tar_file(tar_ptr, "archive3.tar");
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
    //initialize_fuzzed_tar_headers(&header1, SIZE_PADDING, "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "%s");
    memcpy(header1.size, "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof(header1.size));     // len : 1 + 11 nullbyte
    // ------------------------------
    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 4: Non-octal size in header \n\toutput : ");
    execute_on_tar(cmd, 4);
    remove_tar("archive.tar");      // cleanup tar
    rename_tar_file(tar_ptr, "archive4.tar");
    remove_extracted_files(filenames);        // cleanup files
}


/**
 * Attempt 5
 *
 * non null terminated field
 */
void attempt5(char *cmd) {
    const char *filenames[] = {"test_files/file1.txt"};
    printf("\nAttempt 5: non null terminated field \n");

    for (unsigned int i = 0; i < sizeof(PADDINGS)/sizeof(unsigned); i++)
    {

        struct tar_t header1 = {0};

        //char* arch_name = make_arch_name(5, i+1);

        FILE *tar_ptr = create_tar_file("archive.tar");

        initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
        // -------- header tweak --------
        //strncpy(header1.name, "AAAAAA", sizeof(header1.name)); // non null terminated
        initialize_fuzzed_tar_headers(&header1, PADDINGS[i], "A", "%s");
        // ------------------------------
        calculate_checksum(&header1);
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr,filenames[0]);
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 5.%d: non null terminated field\n\toutput : ", i+1);
        execute_on_tar(cmd, 5);
        remove_tar("archive.tar");        // cleanup tar
    }
}


/**
 * Attempt 6
 *
 * Empty field
 */

void attempt6(char *cmd) {
    const char *filenames[] = {"test_files/file1.txt"};
    printf("\nAttempt 6: Empty field \n");

    for (unsigned int i = 0; i < sizeof(PADDINGS)/sizeof(unsigned); i++)
    {
        struct tar_t header1 = {0};

        FILE *tar_ptr = create_tar_file("archive.tar");
        initialize_tar_headers_from_file(&header1, filenames[0]);
        //initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
        // -------- header tweak --------
        //strncpy(header1.name, "AAAAAA", sizeof(header1.name)); // non null terminated
        initialize_fuzzed_tar_headers(&header1, PADDINGS[i], "", "");
        // ------------------------------
        calculate_checksum(&header1);
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr, "test_files/file1.txt");
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 6.%d: Empty field\n\toutput : ", i+1);
        execute_on_tar(cmd, 6);
        remove_tar("archive.tar");      // cleanup tar
    }
}

/**
 * Attempt 7
 *
 * Int format instead of char * or octal
 */

void attempt7(char *cmd) {
    const char *filenames[] = {"test_files/file1.txt"};
    printf("\nAttempt 7: Int format instead of char * or octal \n");

    for (unsigned int i = 0; i < sizeof(PADDINGS)/sizeof(unsigned); i++)
    {
        struct tar_t header1 = {0};

        FILE *tar_ptr = create_tar_file("archive.tar");
        initialize_tar_headers_from_file(&header1, filenames[0]);
        //initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
        // -------- header tweak --------
        //strncpy(header1.name, "AAAAAA", sizeof(header1.name)); // non null terminated
        initialize_fuzzed_tar_headers(&header1, PADDINGS[i], "1234567890", "%d");
        // ------------------------------
        calculate_checksum(&header1);
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr, "test_files/file1.txt");
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 7.%d: Int format instead of char * or octal\n\toutput : ", i+1);
        execute_on_tar(cmd, 7);
        remove_tar("archive.tar");      // cleanup tar
    }
}

/**
 * Attempt 8
 *
 * Specific value for time padding
 */
void attempt8(char *cmd) {
    const char *filenames[] = {"test_files/file1.txt"};
    printf("\nAttempt 8: Specific value for time padding \n");

    // 2147483649 is the value for the bug of year 2038, thanks to Alan for the tips time(NULL) * time(NULL)
    time_t time_list[] = {-1, 0, 1, time(NULL), time(NULL) + 2147483649, time(NULL) - 2147483649, time(NULL) * time(NULL)};

    for (unsigned i = 0; i < sizeof(time_list)/sizeof(time_t); i++) {
        struct tar_t header1 = {0};

        FILE *tar_ptr = create_tar_file("archive.tar");
        initialize_tar_headers_from_file(&header1, filenames[0]);

        // -------- header tweak --------
        initialize_fuzzed_tar_headers_intval(&header1, MTIME_PADDING,  (int *) time_list[i], "%o");
        // ------------------------------
        calculate_checksum(&header1);
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr, "test_files/file1.txt");
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 8.%d: Specific value for time padding\n\toutput : ", i+1);
        execute_on_tar(cmd, 8);
        remove_tar("archive.tar");      // cleanup tar
    }
}

/**
* Attempt 9
*
* Empty tar with no header
*/
void attempt9(char *cmd) {
    printf("Attempt 9: Empty tar with no header\n");
    struct tar_t header1 = {0};

    FILE *tar_ptr = create_tar_file("archive.tar");

    write_tar_header(tar_ptr, &header1);
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    execute_on_tar(cmd, 9);
    remove_tar("archive.tar");      // cleanup tar
}

/**
 * Attempt 10
 *
 * Different value for typeflag header
 */
void attempt10(char *cmd) {
    printf("Attempt 10: Different value for typeflag header\n");
    const char *filenames[] = {"test_files/file1.txt"};

    for (int i=0; i < 2; i++) {
        struct tar_t header1 = {0};

        FILE *tar_ptr = create_tar_file("archive.tar");
        initialize_tar_headers_from_file(&header1,filenames[0]);

        // -------- header tweak --------
        initialize_fuzzed_tar_headers_intval(&header1, TYPEFLAG_PADDING, i, "%u");
        // ------------------------------

        calculate_checksum(&header1);
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr, filenames[0]);
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 10.%d: Different value for typeflag header\n\toutput : ", i+1);
        execute_on_tar(cmd, 10);
        remove_tar("archive.tar");      // cleanup tar
    }
}

/**
 * Attempt 11
 *
 * Tar archive on a folder and setting the typeflag to '5' (directory)
 */
void attempt11(char * cmd) {
    printf("Attempt 11: Tar archive on a folder and setting the typeflag to '5' (directory)\n");
    const char *filenames[] = {"test_files"};

    struct tar_t header1 = {0};

    FILE *tar_ptr = create_tar_file("archive.tar");
    initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
    //initialize_tar_headers_from_file(&header1, filenames[0]);

    // -------- header tweak --------
    initialize_fuzzed_tar_headers(&header1, TYPEFLAG_PADDING, "5", "%d");
    // ------------------------------

    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    //write_tar_content_from_file(tar_ptr, "test_files");
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("- attempt 11: Tar archive on a folder and setting the typeflag to '5' (directory)\n\toutput : ");
    execute_on_tar(cmd, 11);
    remove_tar("archive.tar");      // cleanup tar

}

/**
 * Attempt 12
 *
 * Tar archive on a folder but setting the typeflag to '0' (regular file)
 */
void attempt12(char * cmd) {
    printf("Attempt 12: Tar archive on a folder but setting the typeflag to '0' (regular file)\n");
    const char *filenames[] = {"test_files"};

    struct tar_t header1 = {0};

    FILE *tar_ptr = create_tar_file("archive.tar");
    initialize_tar_headers_from_file(&header1, filenames[0]);

    // -------- header tweak --------
    initialize_fuzzed_tar_headers(&header1, TYPEFLAG_PADDING, "0", "%d");
    // ------------------------------

    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    //write_tar_content_from_file(tar_ptr, "test_files");
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("- attempt 12: Tar archive on a folder but setting the typeflag to '0' (regular file)\n\toutput : ");
    execute_on_tar(cmd, 12);
    remove_tar("archive.tar");      // cleanup tar
}

/**
 * Attempt 13
 *
 * Tar archive on a file but setting the filename and the typeflag to directory
 */

void attempt13(char * cmd) {
    printf("Attempt 13: Tar archive on a file but setting the filename and the typeflag to directory\n");
    const char *filenames[] = {"test_files/file1.txt"};

    struct tar_t header1 = {0};

    FILE *tar_ptr = create_tar_file("archive.tar");
    initialize_tar_headers_from_file(&header1, filenames[0]);

    // -------- header tweak --------
    initialize_fuzzed_tar_headers(&header1, TYPEFLAG_PADDING, "5", "%d");
    initialize_fuzzed_tar_headers(&header1, NAME_PADDING, "test_files/file1.txt/", "%s");
    // ------------------------------

    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    write_tar_content_from_file(tar_ptr, filenames[0]);
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("- attempt 13: Tar archive on a file but setting the filename and the typeflag to directory\n\toutput : ");
    execute_on_tar(cmd, 13);
    remove_tar("archive.tar");      // cleanup tar
}