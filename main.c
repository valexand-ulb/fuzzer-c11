#include <stdio.h>
#include <string.h>

#include "fuzz.h"
#include "generate_tar.h"
#include "test.h"
#include "exec_tar.h"

int main(int argc, char* argv[]) {
    char * files[] = {"file1.txt", "file2.txt"};

    if (argc < 2){
        printf("Not enough arguments given");
        return -1;
    }

    char cmd[51];
    init_cmd(argv[1], cmd);       // initialize command

    //generate_tar("archive.tar", 1, files);
    start_fuzzing();


}
