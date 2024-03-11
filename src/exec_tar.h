#ifndef FUZZER_C11_TEST_TAR_H
#define FUZZER_C11_TEST_TAR_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern unsigned CRASH_NUMBER;
extern unsigned LAST_ATTEMPT;

int execute_on_tar(char cmd[51], int current_attempt, int current_attempt_step, int current_attempt_sub_step, bool print_output);

char* make_arch_name(int nbr1, int nbr2, int nbr3);
void init_cmd(char* extractor, char* cmd);

#endif //FUZZER_C11_TEST_TAR_H
