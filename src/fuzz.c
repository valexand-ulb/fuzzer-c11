#include "fuzz.h"

#include <bits/types/siginfo_t.h>

// crashes we have found
//      2.4
//      5.4
//      7.3
//      7.6
//      10.2
//      15.4
//      16.4.(1-11)

// padding values
const unsigned int PADDINGS[13] = {
        NAME_PADDING,
        MODE_PADDING,
        UID_PADDING,
        GID_PADDING,
        SIZE_PADDING,
        MTIME_PADDING,
        CHKSUM_PADDING,
        TYPEFLAG_PADDING,
        LINKNAME_PADDING,
        MAGIC_PADDING,
        VERSION_PADDING,
        UNAME_PADDING,
        GNAME_PADDING};

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
        attempt14,
        attempt15,
        attempt16
    };

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

    initialize_tar_headers(&header1, filenames[0], 5, time(NULL)); // default tar header
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 1.1 \n\toutput : ");
    execute_on_tar(cmd, 1, 1, 0);
    remove_tar("archive.tar");      // cleanup tar
    remove_extracted_files(filenames);      // cleanup files
}

/**
 * Attempt 2
 *
 * Non-ascii name
 */

void attempt2(char * cmd) {
    const char *filenames[] = {"test_files/file1.txt"};

    printf("Attempt 2: Non-ascii value \n");

    for (unsigned i = 0; i < sizeof(PADDINGS)/sizeof(unsigned); i++) {
        struct tar_t header1 = {0};

        FILE *tar_ptr = create_tar_file("archive.tar");
        initialize_tar_headers_from_file(&header1, filenames[0]);

        // -------- header tweak --------
        if (PADDINGS[i] == NAME_PADDING) {
            tweak_header_field(&header1, PADDINGS[i], "exec_files/😃\0");
        } else {
            tweak_header_field(&header1, PADDINGS[i], "😃\0");
        }
        // ------------------------------

        if (PADDINGS[i] != CHKSUM_PADDING) {calculate_checksum(&header1);} // dont calculate chksum if we fuzz chksum
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr, filenames[0]);
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        printf("\t- attempt 2.%d: Non-ascii value\n\toutput : ", i+1);
        execute_on_tar(cmd, 2, i+1, 0);
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
    //tweak_header_field(&header1, SIZE_PADDING,"4294967295", "%011lo");
    // ------------------------------
    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 3.1: Huge size in header \n\toutput : ");
    execute_on_tar(cmd, 3, 1, 0);
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

    for(int i=0; i<=2; i++) {
        struct tar_t header1 = {0};

        FILE * tar_ptr = create_tar_file("archive.tar");

        initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
        // -------- header tweak --------
        //tweak_header_field(&header1, SIZE_PADDING, "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "%s");
        if(i == 1) { memcpy(header1.size, "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof(header1.size)); }     // len : 1 + 11 nullbyte
        if(i == 2) { memcpy(header1.size, "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff", sizeof(header1.size)); }
        if(i == 3) { memcpy(header1.size, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", sizeof(header1.size)); }
        // ------------------------------
        calculate_checksum(&header1);
        write_tar_header(tar_ptr, &header1);
        write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("\nAttempt 4.%d: Non-octal size in header \n\toutput : ", i+1);
        execute_on_tar(cmd, 4, i+1, 0);
        remove_tar("archive.tar");      // cleanup tar
        remove_extracted_files(filenames);        // cleanup files
    }
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
        FILE *tar_ptr = create_tar_file("archive.tar");
        initialize_tar_headers(&header1, filenames[0], 5, time(NULL));

        // -------- header tweak --------
        fill_header_field(&header1, PADDINGS[i]);
        if(PADDINGS[i] == NAME_PADDING) {
            tweak_header_field(&header1, NAME_PADDING, "exec_files/");
        }
        // ------------------------------

        if (PADDINGS[i] != CHKSUM_PADDING) {calculate_checksum(&header1);} // dont calculate chksum if we fuzz chksum
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr,filenames[0]);
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 5.%d: non null terminated field\n\toutput : ", i+1);
        execute_on_tar(cmd, 5, i+1, 0);
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

        // -------- header tweak --------
        // this is probably making the file that has a number as name
        tweak_header_field(&header1, PADDINGS[i], "");
        // ------------------------------

        if (PADDINGS[i] != CHKSUM_PADDING) {calculate_checksum(&header1);} // dont calculate chksum if we fuzz chksum
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr, "test_files/file1.txt");
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 6.%d: Empty field\n\toutput : ", i+1);
        execute_on_tar(cmd, 6, i+1, 0);
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

        // -------- header tweak --------
        int value = 123456789;
        // no need to test the name since its the equivalent of other tests
        if (PADDINGS[i] != NAME_PADDING) {tweak_header_field_intval(&header1, PADDINGS[i], &value,"%d");}
        // ------------------------------

        if (PADDINGS[i] != CHKSUM_PADDING) {calculate_checksum(&header1);} // dont calculate chksum if we fuzz chksum
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr, "test_files/file1.txt");
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 7.%d: Int format instead of char * or octal\n\toutput : ", i+1);
        execute_on_tar(cmd, 7, i+1, 0);
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
    time_t time_list[] = {-1, 0, 1, time(NULL), time(NULL) + 2147483649, time(NULL) - 2147483649, time(NULL) * time(NULL), - time(NULL)};

    for (unsigned i = 0; i < sizeof(time_list)/sizeof(time_t); i++) {
        struct tar_t header1 = {0};

        FILE *tar_ptr = create_tar_file("archive.tar");
        initialize_tar_headers_from_file(&header1, filenames[0]);

        // -------- header tweak --------
        tweak_header_field_intval(&header1, MTIME_PADDING,  (int *) time_list[i], "%o");
        // ------------------------------
        calculate_checksum(&header1);
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr, "test_files/file1.txt");
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 8.%d: Specific value for time padding\n\toutput : ", i+1);
        execute_on_tar(cmd, 8, i+1, 0);
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

    // ============= TEST =============
    printf("Attempt 9.1: Empty tar with no header\n\toutput : ");
    execute_on_tar(cmd, 9, 1, 0);
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

    for (int i=-1; i < 5; i++) {
        struct tar_t header1 = {0};

        FILE *tar_ptr = create_tar_file("archive.tar");
        initialize_tar_headers_from_file(&header1,filenames[0]);

        // -------- header tweak --------

        char *buffer = (char *) malloc(2 * sizeof(char)); // int to char *
        snprintf(buffer, 2, "%u", i);

        tweak_header_field(&header1, TYPEFLAG_PADDING, buffer);
        // ------------------------------

        calculate_checksum(&header1);
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr, filenames[0]);
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 10.%d: Different value for typeflag header\n\toutput : ", i+1);
        execute_on_tar(cmd, 10, i+1, 0);
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
    tweak_header_field(&header1, TYPEFLAG_PADDING, "5");
    // ------------------------------

    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    //write_tar_content_from_file(tar_ptr, "test_files");
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("- attempt 11.1: Tar archive on a folder and setting the typeflag to '5' (directory)\n\toutput : ");
    execute_on_tar(cmd, 11, 1, 0);
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
    tweak_header_field(&header1, TYPEFLAG_PADDING, "0");
    // ------------------------------

    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    //write_tar_content_from_file(tar_ptr, "test_files");
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("- attempt 12.1: Tar archive on a folder but setting the typeflag to '0' (regular file)\n\toutput : ");
    execute_on_tar(cmd, 12, 1, 0);
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
    tweak_header_field(&header1, TYPEFLAG_PADDING, "5");
    tweak_header_field(&header1, NAME_PADDING, "exec_files/file1.txt/");
    // ------------------------------

    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    write_tar_content_from_file(tar_ptr, filenames[0]);
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("- attempt 13.1: Tar archive on a file but setting the filename and the typeflag to directory\n\toutput : ");
    execute_on_tar(cmd, 13, 1, 0);
    remove_tar("archive.tar");      // cleanup tar
}

/**
 * Attempt 14
 *
 * File specified in header is not the same as the file in the tar
 */
void attempt14(char * cmd) {
    printf("Attempt 14: File specified in header is not the same as the file in the tar\n");
    const char *filenames[] = {"test_files/file1.txt", "test_files/file2.txt"};

    struct tar_t header1 = {0};

    FILE *tar_ptr = create_tar_file("archive.tar");
    initialize_tar_headers_from_file(&header1, filenames[0]);

    // -------- header tweak --------
    tweak_header_field(&header1, NAME_PADDING, "exec_files/thisisrandom");
    // ------------------------------

    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    write_tar_content_from_file(tar_ptr, filenames[0]);
    write_end_of_tar(tar_ptr);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("- attempt 14.1: File specified in header is not the same as the file in the tar\n\toutput : ");
    execute_on_tar(cmd, 14, 1, 0);
    remove_tar("archive.tar"); // cleanup tar
}

/**
 * Attempt 15
 *
 * Char * value, generally a string null terminated
 */
void attempt15(char * cmd) {
    printf("Attempt 15: Char * value, generally a string null terminated\n");
    const char *filenames[] = {"test_files/file1.txt"};

    for (unsigned int i = 0; i < sizeof(PADDINGS)/sizeof(unsigned); i++)
    {
        struct tar_t header1 = {0};
        FILE *tar_ptr = create_tar_file("archive.tar");
        initialize_tar_headers_from_file(&header1, filenames[0]);

        // -------- header tweak --------
        if (PADDINGS[i] == NAME_PADDING) {
            tweak_header_field(&header1, PADDINGS[i], "exec_files/alex\0");
        } else {
            tweak_header_field(&header1, PADDINGS[i], "alex\0");
        }
        // ------------------------------

        if (PADDINGS[i] != CHKSUM_PADDING) {calculate_checksum(&header1);} // dont calculate chksum if we fuzz chksum
        write_tar_header(tar_ptr, &header1);
        write_tar_content_from_file(tar_ptr, filenames[0]);
        write_end_of_tar(tar_ptr);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 15.%d: Char * value, generally a string null terminated\n\toutput : ", i+1);
        execute_on_tar(cmd, 15, i+1, 0);
        remove_tar("archive.tar");      // cleanup tar
    }
}

/**
 * Attempt 16
 *
 * Escape sequence in fields
 */
void attempt16(char * cmd) {
    printf("Attempt 16: Escape sequence in fields\n");
    const char * escape_sequence[] = {"\n", "\t", "\r", "\b", "\a", "\f", "\v", "\\", "\'", "\"", "\?", "\0"};
    const char *filenames[] = {"test_files/file1.txt"};

    for (unsigned int i = 0; i < sizeof(PADDINGS)/sizeof(unsigned); i++)
    {
        for (unsigned int j = 0; j < sizeof(escape_sequence)/sizeof(char*); j++)
        {
            struct tar_t header1 = {0};
            FILE *tar_ptr = create_tar_file("archive.tar");
            initialize_tar_headers_from_file(&header1, filenames[0]);

            // -------- header tweak --------
            //if its the name, we put it in the dir (to remove weird files easily)
            char temp[20] = "exec_files/";
            strcat(temp, escape_sequence[j]);

            if (PADDINGS[i] == NAME_PADDING) {
                tweak_header_field(&header1, PADDINGS[i], temp);
            } else {
                tweak_header_field(&header1, PADDINGS[i], escape_sequence[j]);
            }
            // ------------------------------

            if (PADDINGS[i] != CHKSUM_PADDING) {calculate_checksum(&header1);} // dont calculate chksum if we fuzz chksum
            write_tar_header(tar_ptr, &header1);
            write_tar_content_from_file(tar_ptr, filenames[0]);
            write_end_of_tar(tar_ptr);

            close_tar_file(tar_ptr);

            // ============= TEST =============
            printf("- attempt 16.%d.%d: Escape sequence %s in fields\n\toutput : ", i+1, j+1, escape_sequence[j]);
            execute_on_tar(cmd, 16, i+1, j+1);
            remove_tar("archive.tar");      // cleanup tar
        }
    }
}

