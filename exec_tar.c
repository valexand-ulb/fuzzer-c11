#include "exec_tar.h"

unsigned CRASH_NUMBER = 0;
unsigned LAST_ATTEMPT = 0;

void rename_crash_archive(int crash_number) {
    char oldname[] = "archive.tar";
    char newname[50];
    snprintf(newname, 50, "crashing_tar_files/crash%d.tar", crash_number);

    if(rename(oldname, newname) == 0) {
        printf("File renamed successfully\n");
    } else {
        printf("Error: unable to rename the file\n");
    }
}

int execute_on_tar(char cmd[51], unsigned current_attempt) {
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
        // The renaming work fine but need testing with the  whole program
        if (current_attempt != LAST_ATTEMPT) {
            rename_crash_archive(current_attempt);
            CRASH_NUMBER++;
            LAST_ATTEMPT = current_attempt;
        }

        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }

    //sleep(3); // TODO : REMOVE WHEN TESTING IS DONE. SLEEP IS SET TO LET TIME FOR THE PROGRAM TO CRASH
    return rv;
}

void init_cmd(char* extractor, char* cmd) {
    strncpy(cmd, extractor, 25);
    cmd[26] = '\0';
    strncat(cmd, " archive.tar", 25);
}