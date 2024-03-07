#include "fuzz.h"

void start_fuzzing(char* cmd) {
    // Declare an array of function pointers
    void (*functionList[])() = {attempt1, attempt2, attempt3, attempt4, attempt5, attempt6};

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

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 1 \n\toutput : ");
    execute_on_tar(cmd);
    //remove_tar("archive.tar");      // cleanup tar
    rename_tar_file(tar_ptr, "archive1.tar");
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

    FILE * tar_ptr = create_tar_file("archive2.tar");

    initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
    // -------- header tweak --------
    strncpy(header1.name, "\xff", sizeof(header1.name)-1);
    //initialize_fuzzed_tar_headers(&header1, NAME_PADDING, "😃\0", "%c");
    filenames[0] = "\xff";
    // ------------------------------
    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 2: Non-ascii name \n\toutput : ");
    execute_on_tar(cmd);
    //remove_tar("archive2.tar");      // cleanup tar
    rename_tar_file(tar_ptr, "archive2.tar");
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
    //initialize_fuzzed_tar_headers(&header1, SIZE_PADDING,"4294967295", "%011lo");
    // ------------------------------
    calculate_checksum(&header1);
    write_tar_header(tar_ptr, &header1);
    write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 3: Huge size in header \n\toutput : ");
    execute_on_tar(cmd);
    //remove_tar("archive.tar");      // cleanup tar
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

    close_tar_file(tar_ptr);

    // ============= TEST =============
    printf("\nAttempt 4: Non-octal size in header \n\toutput : ");
    execute_on_tar(cmd);
    //remove_tar("archive.tar");      // cleanup tar
    rename_tar_file(tar_ptr, "archive4.tar");
    remove_extracted_files(filenames);        // cleanup files
}


/**
 * Attempt 5
 *
 * non null terminated field
 */
void attempt5(char *cmd) {
    unsigned int paddings[11] = {SIZE_PADDING,
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

    printf("\nAttempt 5: non null terminated field \n");

    for (unsigned int i = 0; i < sizeof(paddings)/sizeof(unsigned); i++)
    {
        const char *filenames[] = {"myfile"};
        struct tar_t header1 = {0};

        //char* arch_name = make_arch_name(5, i+1);

        FILE *tar_ptr = create_tar_file("archive.tar");

        initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
        // -------- header tweak --------
        //strncpy(header1.name, "AAAAAA", sizeof(header1.name)); // non null terminated
        initialize_fuzzed_tar_headers(&header1, paddings[i], "A", "%s");
        // ------------------------------
        calculate_checksum(&header1);
        write_tar_header(tar_ptr, &header1);
        write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 5.%d: non null terminated field\n\toutput : ", i+1);
        execute_on_tar(cmd);
        //remove_tar("archive.tar");        // cleanup tar
        char* arch_name = make_arch_name(5, i+1);
        rename_tar_file(tar_ptr, arch_name);
        free(arch_name);
        remove_extracted_files(filenames);        // cleanup files
        //free(arch_name);
    }
}


/**
 * Attempt 6
 *
 * Empty field
 */

void attempt6(char *cmd) {
    unsigned int paddings[11] = {SIZE_PADDING,
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

    printf("\nAttempt 6: Empty field \n");

    for (unsigned int i = 0; i < sizeof(paddings)/sizeof(unsigned); i++)
    {
        const char *filenames[] = {"myfile"};
        struct tar_t header1 = {0};

        FILE *tar_ptr = create_tar_file("archive.tar");

        initialize_tar_headers(&header1, filenames[0], 5, time(NULL));
        // -------- header tweak --------
        //strncpy(header1.name, "AAAAAA", sizeof(header1.name)); // non null terminated
        initialize_fuzzed_tar_headers(&header1, paddings[i], "", "");
        // ------------------------------
        calculate_checksum(&header1);
        write_tar_header(tar_ptr, &header1);
        write_tar_content(tar_ptr, "\x41\x42\x43\x44\x0a", true);

        close_tar_file(tar_ptr);

        // ============= TEST =============
        printf("- attempt 6.%d: Empty field\n\toutput : ", i+1);
        execute_on_tar(cmd);
        //remove_tar("archive.tar");      // cleanup tar
        char* arch_name = make_arch_name(6, i+1);
        rename_tar_file(tar_ptr, arch_name);
        free(arch_name);
        remove_extracted_files(filenames);        // cleanup files
    }
}