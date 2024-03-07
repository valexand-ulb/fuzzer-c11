#ifndef FUZZER_C11_FUZZ_H
#define FUZZER_C11_FUZZ_H

#include <stdio.h>
#include "tar_utils.h"
#include <time.h>
#include "exec_tar.h"

void start_fuzzing(char* cmd);

// --------------------
void attempt1(char* cmd);
void attempt2(char* cmd);
void attempt3(char* cmd);
void attempt4(char* cmd);
void attempt5(char* cmd);
void attempt6(char* cmd);

// --------------------

#endif //FUZZER_C11_FUZZ_H
