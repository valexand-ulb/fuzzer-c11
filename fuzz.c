#include "fuzz.h"

void start_fuzzing() {
    // Declare an array of function pointers
    void (*functionList[])() = {attempt1,
                                attempt2,
                                attempt3};

    int numFunctions = sizeof(functionList) / sizeof(functionList[0]);

    // Iterate over the array and call each function
    for (int i = 0; i < numFunctions; i++) {
        (*functionList[i])();
    }
}


void attempt1() {
    printf("This is function 1\n");
}

void attempt2() {
    printf("This is function 2\n");
}

void attempt3() {
    printf("This is function 3\n");
}

