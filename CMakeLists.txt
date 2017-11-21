cmake_minimum_required(VERSION 3.9)
project(pamela)

file(GLOB_RECURSE SRCS
        src/*.c)
file(GLOB_RECURSE INCLUDES
        include/*.h)

add_library(pamela ${SRCS} ${INCLUDES})
