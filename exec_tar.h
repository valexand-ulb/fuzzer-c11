#ifndef FUZZER_C11_TEST_TAR_H
#define FUZZER_C11_TEST_TAR_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>

int execute_on_tar(char cmd[51]);

void init_cmd(char* extractor, char* cmd);

#endif //FUZZER_C11_TEST_TAR_H
