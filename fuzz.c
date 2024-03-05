#include "fuzz.h"

void start_fuzzing() {
    // Declare an array of function pointers
    void (*functionList[])() = {function1,
                                function2,
                                function3};
    int numFunctions = sizeof(functionList) / sizeof(functionList[0]);

    // Iterate over the array and call each function
    for (int i = 0; i < numFunctions; i++) {
        (*functionList[i])();
    }
}


void function1() {
    printf("This is function 1\n");
}

void function2() {
    printf("This is function 2\n");
}

void function3() {
    printf("This is function 3\n");
}

