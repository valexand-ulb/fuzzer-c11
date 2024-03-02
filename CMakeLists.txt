cmake_minimum_required(VERSION 3.27)
project(fuzzer C)

set(CMAKE_C_STANDARD 11)

add_executable(fuzzer main.c
        generate_tar.c
        generate_tar.h
        tar_header.h)
