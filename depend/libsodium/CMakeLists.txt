cmake_minimum_required(VERSION 3.9.4)

project(libsodium)

file(GLOB_RECURSE SRCS src/*.c)
file(GLOB_RECURSE HDRS src/*.h)

include_directories(src)
include_directories(src/libsodium/include/sodium)

add_definitions(-DUNICODE -D_UNICODE)
add_library(libsodium STATIC  ${SRCS} ${HDRS})

target_compile_features(libsodium PRIVATE cxx_std_20)

set_target_properties(libsodium PROPERTIES FOLDER "Lib")


