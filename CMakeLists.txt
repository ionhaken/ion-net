cmake_minimum_required(VERSION 3.9.4)

project(ion)

add_subdirectory("3rdparty")

file(GLOB_RECURSE SRCS src/ion/*.cpp)
file(GLOB_RECURSE HDRS src/ion/*.h)

include_directories(src)
include_directories(3rdparty)

add_definitions(-DUNICODE -D_UNICODE)
add_library(ion STATIC  ${SRCS} ${HDRS})

target_compile_features(ion PRIVATE cxx_std_20)

set_target_properties(ion PROPERTIES FOLDER "Lib")



