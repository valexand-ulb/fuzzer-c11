#ifndef FUZZER_C11_TEST_TAR_H
#define FUZZER_C11_TEST_TAR_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>

extern unsigned CRASH_NUMBER;
extern unsigned LAST_ATTEMPT;

int execute_on_tar(char cmd[51], unsigned current_attempt);

void init_cmd(char* extractor, char* cmd);

#endif //FUZZER_C11_TEST_TAR_H
