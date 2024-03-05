#include <stdio.h>
#include "fuzz.h"
#include "exec_tar.h"

int main(int argc, char* argv[]) {
    if (argc < 2){
        printf("Not enough arguments given\n");
        return -1;
    }

    char cmd[51];
    init_cmd(argv[1], cmd);       // initialize command

    //generate_tar("archive.tar", 1, files);
    start_fuzzing(cmd);


}
