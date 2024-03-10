#include "exec_tar.h"


/*void rename_crash_archive(int crash_number) {
    char oldname[] = "archive.tar";
    char newname[50];
    snprintf(newname, 50, "crashing_tar_files/crash%d.tar", crash_number);

    if(rename(oldname, newname) == 0) {
        printf("File renamed successfully\n");
    } else {
        printf("Error: unable to rename the file\n");
    }
}*/

int execute_on_tar(char cmd[51], int current_attempt, int current_attempt_step, int current_attempt_sub_step) {
    char buf[33];
    int rv = 0;
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

        // rename file if success (non-renamed files will be removed)
        char* new_name = make_arch_name(current_attempt, current_attempt_step, current_attempt_sub_step);
        rename("archive.tar", new_name);

        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }

    return rv;
}

char* make_arch_name(int nbr1, int nbr2, int nbr3) {
    char attempt_num_str[5];
    sprintf(attempt_num_str, "%d", nbr1);

    char iter_num_str[5];
    sprintf(iter_num_str, "%d", nbr2);

    char arch_name[40] = "archive";
    strcat(arch_name, attempt_num_str);
    strcat(arch_name, "-");
    strcat(arch_name, iter_num_str);

    // Add the third number only if there is one (i.e. it is 0)
    if (nbr3 > 0) {
        char sub_iter_num_str[5];
        sprintf(sub_iter_num_str, "%d", nbr3);
        strcat(arch_name, "-");
        strcat(arch_name, sub_iter_num_str);
    }

    strcat(arch_name, ".tar");

    // allocating memory
    char* result = (char*)malloc(40 * sizeof(char));

    strcpy(result, arch_name);

    return result;
}

void init_cmd(char* extractor, char* cmd) {
    strncpy(cmd, extractor, 25);
    cmd[26] = '\0';
    strncat(cmd, " archive.tar", 25);
}