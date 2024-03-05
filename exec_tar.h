#ifndef FUZZER_C11_TEST_TAR_H
#define FUZZER_C11_TEST_TAR_H

int execute_on_tar(char cmd[51]);

char* init_cmd(char* extractor);

#endif //FUZZER_C11_TEST_TAR_H
