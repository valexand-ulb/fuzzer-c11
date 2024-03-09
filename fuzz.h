#ifndef FUZZER_C11_FUZZ_H
#define FUZZER_C11_FUZZ_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "tar_utils.h"
#include "exec_tar.h"

void start_fuzzing(char* cmd);
char* make_arch_name(int nbr1, int nbr2);

// --------------------
void attempt1(char* cmd); // simple tar archive
void attempt2(char* cmd); // non ascii fields
void attempt3(char* cmd); // huge size in header
void attempt4(char* cmd); // non octal size
void attempt5(char* cmd); // non null terminated fields
void attempt6(char* cmd); // empty fields
void attempt7(char* cmd); // int format instead of const char*
void attempt8(char* cmd); // specific value for mtime
void attempt9(char* cmd); // empty tar with no header
void attempt10(char* cmd); // different typeflag value
void attempt11(char* cmd); // directory instead of file
void attempt12(char* cmd); // directory but typeflag is not 5
void attempt13(char* cmd); // file but the filename and the typeflag are set to directory
// --------------------

extern const unsigned int PADDINGS[11];

#endif //FUZZER_C11_FUZZ_H
