#ifndef FUZZER_C11_TEST_TAR_H
#define FUZZER_C11_TEST_TAR_H

void execute_on_tar(char cmd[51]);

char[51] init_cmd(char* extractor);

#endif //FUZZER_C11_TEST_TAR_H
