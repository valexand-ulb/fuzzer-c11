#include <stdio.h>
#include <string.h>
#include "exec_tar.h"

void rename_crash_archive(int crash_number) {
    char oldname[] = "archive.tar";
    char newname[50];
    snprintf(newname, 50, "crashing_tar/crash%d.tar", crash_number);

    if(rename(oldname, newname) == 0) {
        printf("File renamed successfully\n");
    } else {
        printf("Error: unable to rename the file\n");
    }
}

int execute_on_tar(char cmd[51]) {
    int crash_number = 0; // Number of crashes due to a tar file
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

        // TODO : Move tar file into crashing_tar folder, maybe it will make the program crash since it will not find archive.tar
        rename_crash_archive(crash_number);

        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }
    return rv;
}

void init_cmd(char* extractor, char* cmd) {
    strncpy(cmd, extractor, 25);
    cmd[26] = '\0';
    strncat(cmd, " archive.tar", 25);
}